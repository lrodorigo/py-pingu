import argparse
import json
import logging
import os
import random
import signal
import subprocess
import time
from queue import Queue, Empty
from threading import Thread, Lock, Event

from pyroute2 import IPRoute, IPDB
from scapy.arch import get_if_hwaddr, L2Socket, get_if_addr, get_if_list, get_if_raw_hwaddr
from scapy.arch.linux import L3PacketSocket
from scapy.data import ARPHDR_ETHER, ARPHDR_LOOPBACK
from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import sndrcv

from scapy.all import conf as scapyconf

PINGU_PROTO = 89

FORMAT = '[%(levelname)s] %(message)s'

DEFAULT_MAX_LOST = 2
DEFAULT_DELAY = 500
DEFAULT_MAX_DELAY = 1000
DEFAULT_COUNT = 5


class Pingu(object):

    def __init__(self, configuration=None):
        if configuration is None:
            configuration = {
                "host": "8.8.8.8",
                "interfaces": {
                    "enx0c5b8f279a64": {
                        "metric": 100,
                        "count": 10,
                        "max_lost": 5,
                        "max_delay": 100,
                        "reset_script": None,
                        "reset_script_grace_period": 0,
                    },
                    "wlo1": {
                        "metric": 50,
                    }
                },
                "period": 5
            }

        self.log = logging.getLogger("py-pingu")
        self.gateways = {}
        self.ipdb = IPDB()
        self.pyroute = None
        self.event_queue = Queue()
        self.DEFAULT_PROTO = configuration.get("proto", PINGU_PROTO)
        self.gw_lock = Lock()
        self.sockets = {}
        self.route_monitor = Thread(target=self.route_monitor_thread)
        self.next_check_timestamps = {}

        self.loop_event = Event()
        self.exited = Event()
        self.exited.clear()

        self.base_period = configuration.get("period", 5)
        self.configuration = configuration

        self.configure_scapy()

    def configure_scapy(self):
        scapyconf.sniff_promisc = 0

    def get_ip(self, idx, addrs):
        for a in addrs:
            if a["index"] == idx:
                return self.get_attribute(a, "IFA_ADDRESS")

    def route_monitor_thread(self):

        while not self.exited.is_set():

            with IPRoute() as self.pyroute:
                try:
                    message = self.event_queue.get(timeout=0.5)
                except Empty as ex:
                    continue

                try:
                    links = self.pyroute.get_links()

                    with self.gw_lock:
                        iface = self.get_iface_name(message.get_attr("RTA_OIF"), links)

                        if iface not in self.configuration["interfaces"]:
                            continue

                        if message["dst_len"] == 0 and message["src_len"] == 0 and \
                                message["table"] == 254 and message["proto"] != self.DEFAULT_PROTO:

                            gw = self.get_attribute(message, "RTA_GATEWAY")

                            with IPRoute() as ipr2:
                                kwargs = dict(dst_len=0,
                                              src_len=0,
                                              type=message['type'],
                                              scope=message['scope'],
                                              oif=message.get_attr("RTA_OIF"))

                                #
                                # route scope is == 253 if the destination network is on the local host,
                                # so the fetched gateway will be null
                                #
                                #   eg. ip route add default dev eth0
                                #

                                if gw is not None and message['scope'] != 253:
                                    kwargs["gateway"] = gw

                                ipr2.route("del", **kwargs)
                            self.log.info("Fetched new default gw for interface %s: %s " % (iface, gw))

                            self.gateways[iface] = gw
                            self.next_check_timestamps[iface] = -1
                            self.loop_event.set()

                except Exception as ex:
                    self.log.exception("Exception in route_monitor_thread")

                finally:
                    self.event_queue.task_done()

    def get_attribute(self, message, name):
        for x in message["attrs"]:
            if x[0] == name:
                return x[1]

    def get_iface_name(self, index, links):
        for l in links:
            if l["index"] == index:
                return self.get_attribute(l, "IFLA_IFNAME")

    def load_route_table(self):
        self.log.info("Loading routing table")
        with IPDB() as ipdb:
            routes = ipdb.routes.filter({"dst": "default", "table": 254})
            with self.gw_lock:
                for r in routes:
                    name = ipdb.interfaces[r["route"].oif].ifname

                    if name not in self.configuration["interfaces"]:
                        continue
                    gw = r["route"].gateway
                    self.log.info("Fetched gateway for %s: %s" % (name, gw))
                    self.gateways[name] = gw

                    with r["route"] as to_del:
                        to_del.remove()
        self.log.info("Loaded %s gateways from routing table" % len(self.gateways))

    def get_gw_mac_address(self, iface):

        for i in range(5):
            arp_req_ip_dst = self.gateways[iface]

            source_hw_addr = get_if_hwaddr(iface)

            arp_req = Ether(dst="ff:ff:ff:ff:ff:ff", src=source_hw_addr) / \
                      ARP(pdst=arp_req_ip_dst, psrc=get_if_addr(iface), hwsrc=source_hw_addr)

            ans, unans = sndrcv(self.sockets[iface], arp_req, timeout=1, verbose=0)

            if len(ans) < 1:
                continue

            return ans[0][1].src

        raise ConnectionError("ARP Resolution Failed for %s (%s)" % (self.gateways[iface], iface))

    def use_l2_packet(self, interface):
        addrfamily, mac = get_if_raw_hwaddr(interface)
        return addrfamily in [ARPHDR_ETHER, ARPHDR_LOOPBACK]

    def check_interface(self, interface):
        try:
            if interface not in self.gateways:
                self.log.debug("No gateway fetched for %s" % interface)
                return False

            if hasattr(self.ipdb.interfaces[interface], "carrier") and self.ipdb.interfaces[interface].carrier == 0:
                return False

            count = self.configuration["interfaces"][interface].get("count", DEFAULT_COUNT)
            max_lost = self.configuration["interfaces"][interface].get("max_lost", DEFAULT_MAX_LOST)
            max_delay = self.configuration["interfaces"][interface].get("max_delay", DEFAULT_MAX_DELAY)

            delays = []
            id = random.randint(1, 65535)

            if_addr = get_if_addr(interface)

            if self.use_l2_packet(interface):

                try:
                    mac_address_gw = self.get_gw_mac_address(interface)
                except ConnectionError as ex:
                    self.log.error(ex.args[0])
                    return False

                if_hw_addr = get_if_hwaddr(interface)
                header = Ether(dst=mac_address_gw, src=if_hw_addr)

            else:
                # if using an L3 socket for this interface ->
                # add scapy route to route L3 traffic on the probed interface
                # the route will not be added to the kernel routing table
                scapyconf.route.add(net='%s/32' % self.configuration["host"], dev=interface)
                header = None

            for i in range(count):

                if self.exited.is_set():
                    return

                if header:
                    packet = header / \
                             IP(src=if_addr, dst=self.configuration["host"]) / \
                             ICMP(id=id, seq=i + 1)
                else:
                    packet = IP(src=if_addr, dst=self.configuration["host"]) / \
                             ICMP(id=id, seq=i + 1)

                ans, unans = sndrcv(self.sockets[interface], packet, timeout=1, verbose=0)

                # self.log.debug("Ping sent")
                if len(ans) > 0:
                    if ans[0][1][ICMP].type == 0 and ans[0][1][ICMP].id == id:
                        rx = ans[0][1]
                        tx = ans[0][0]
                        delta = rx.time - tx.sent_time
                        delays.append(delta)
                    else:
                        self.log.debug(
                            "[%s] Missed ping seq=%s - ICMP Recv Type: %s (must be 0) - Id: %s (must be %s) " %
                            (interface, i + 1, ans[0][1][ICMP].type, ans[0][1][ICMP].id, id))
                else:
                    self.log.debug("[%s] Missed ping id=%s seq=%s  - Timeout" % (interface, id, i + 1))

                self.exited.wait(timeout=DEFAULT_DELAY / 1000)

            # if using an L3 socket for this interface -> remove scapy route
            if header is None:
                scapyconf.route.delt(net='%s/32' % self.configuration["host"], dev=interface)

            if len(delays) == 0:
                return False

            ok_count = len(delays)
            delay_avg = sum(delays) / ok_count
            is_ok = (count - ok_count) <= max_lost and (delay_avg * 1000) < max_delay
            self.log.debug(
                "[%s %s] Ping %s via %s result - lost: %s/%s, delay: %0.0f ms" % (interface, "OK" if is_ok else "FAIL",
                                                                                  self.configuration["host"],
                                                                                  self.gateways[interface],
                                                                                  (count - ok_count), count,
                                                                                  delay_avg * 1000))
            return is_ok

        except PermissionError as pe:
            raise pe

        except Exception as ex:
            self.log.exception("check_interface error: ")
            return False

    def metric(self, interface):
        return self.configuration["interfaces"][interface]

    def activate_interface(self, name):
        if name not in self.gateways:
            self.log.warning("Missing default gw for ", name)

        with IPDB() as ipdb:
            existing_route = None
            try:
                existing_route = ipdb.routes[{'oif': ipdb.interfaces[name].index,
                                              'proto': self.DEFAULT_PROTO,
                                              'dst': 'default'}]
            except KeyError as ex:
                pass

            if existing_route is not None:
                if existing_route["priority"] == self.configuration["interfaces"][name]["metric"] and \
                        existing_route["gateway"] == self.gateways[name]:
                    return  # esco se gia' esiste

                # altrimenti cancello
                if len(existing_route) > 0:
                    ipdb.routes.remove({'oif': ipdb.interfaces[name].index,
                                        'proto': self.DEFAULT_PROTO,
                                        'dst': 'default'}).commit()
            metric = self.configuration["interfaces"][name]["metric"]
            ipdb.routes.add({'oif': ipdb.interfaces[name].index,
                             'dst': 'default',
                             'proto': self.DEFAULT_PROTO,
                             'gateway': self.gateways[name],
                             "priority": metric}).commit()
            self.log.info("[INSTALLED] %s via %s (metric %s)" % (name, self.gateways[name], metric))

    def deactivate_interface(self, name):

        with IPDB() as ipdb:
            try:
                ipdb.routes.remove({'oif': ipdb.interfaces[name].index,
                                    'proto': self.DEFAULT_PROTO,
                                    'dst': 'default'})

                ipdb.commit()

                self.log.info("[REMOVED] %s via %s" % (name, self.gateways.get(name, "---")))
            except KeyError as ex:
                pass

    def callback(self, ipdb, message, action):
        if "ROUTE" in message["event"]:
            self.log.debug("Event detected: %s " % message["event"])

            if message["event"] == "RTM_NEWROUTE":
                self.event_queue.put(message)

    def print_fetched_gws(self, a, b):
        with self.gw_lock:
            self.log.info("Fetched gateways:\n %s\n " % json.dumps(self.gateways))

    def get_interface_next_check(self, interface):
        return time.time() + self.configuration["interfaces"][interface].get("period", self.base_period)

    def load_next_checks(self):
        for i in self.configuration["interfaces"].keys():
            self.next_check_timestamps[i] = -1

    def run_on_interface(self, interface):
        try:

            if self.use_l2_packet(interface):
                self.sockets[interface] = L2Socket(iface=interface,
                                                   filter="arp or (icmp and src host %s)" % self.configuration[
                                                       "host"])
            else:
                self.sockets[interface] = L3PacketSocket(iface=interface)

        except Exception as ex:
            if "permission" in str(ex):
                self.log.exception("Error while opening filter: ")
            # if "tcpdump" in str(ex).lower():
            #     self.log.error("py-pingu requires tcpdump executable, please install tcpdump.")
            #     exit(1)

            return

        with self.gw_lock:
            if self.check_interface(interface):
                self.activate_interface(interface)
            else:
                self.run_reset_script(interface)
                self.deactivate_interface(interface)

    def run_reset_script(self, interface):
        script = self.configuration["interfaces"][interface].get("reset_script", None)
        if script is None:
            return
        grace_period = self.configuration["interfaces"][interface].get("reset_script_grace_period", 600)
        last = self.configuration["interfaces"][interface].get("last_reset_script_run", 0)
        now = time.time()

        if now - last < grace_period:
            return

        if not os.path.isfile(script):
            self.log.warning("Unable to find reset script %s for %s" % (script, interface))
            return

        self.log.info("Executing reset script for %s" % interface)
        p = subprocess.Popen(script, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, close_fds=True)
        # allow external program to work
        p.wait()

        self.configuration["interfaces"][interface]["last_reset_script_run"] = now


    def fetch_next_interface(self):
        v = min(self.next_check_timestamps, key=self.next_check_timestamps.get)
        now = time.time()
        expiration = self.next_check_timestamps[v]
        delta = expiration - now
        return v, delta if delta > 0 else 0

    def on_sigint(self, a, b):
        self.exited.set()
        self.loop_event.set()

    def run(self):
        self.ipdb.register_callback(self.callback, )

        self.log.info("Welcome to py-pingu! ")
        self.log.info(json.dumps(self.configuration, indent=2))
        self.route_monitor.start()

        signal.signal(signal.SIGINT, self.on_sigint)
        signal.signal(signal.SIGUSR1, self.print_fetched_gws)

        self.load_route_table()
        self.load_next_checks()

        while not self.exited.is_set():

            name, period = self.fetch_next_interface()

            if period > 0:
                if self.loop_event.wait(timeout=period):
                    self.loop_event.clear()
                    continue

            try:
                self.log.debug("Probing %s" % name)
                ifaces = get_if_list()

                if name not in ifaces:
                    self.log.debug("Interface %s does not exists." % name)
                    continue

                self.run_on_interface(name)

            except Exception as ex:
                self.log.exception("Error in main loop:")
            finally:
                self.next_check_timestamps[name] = self.get_interface_next_check(name)

        self.log.info("Exit signal received")


# ----------------------------------------------------------------------------------------------------------------------

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='PyPingu Routing Daemon')
    parser.add_argument("--config", default=None, metavar='config-file.json', dest="config_file",
                        type=str, help='Configuration file')
    parser.add_argument('-v', dest="verbose", action='store_true', help='Debug Log mode')
    args = parser.parse_args()

    config = None
    if args.config_file is not None:
        with open(args.config_file, "r") as f:
            config = json.load(f)
    if args.verbose:
        logging.basicConfig(format=FORMAT, level=logging.DEBUG)
    else:
        logging.basicConfig(format=FORMAT, level=logging.INFO)

    Pingu(config).run()
