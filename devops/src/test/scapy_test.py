import random
import time

from scapy.arch import  get_if_addr
from scapy.arch.linux import L3PacketSocket
from scapy.config import conf
from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sendp, sr, sndrcv
from scapy.supersocket import L3RawSocket

conf.use_pcap = True

while True:
    iface = "ppp0"

    s = L3PacketSocket(iface=iface)

    id = random.randint(1, 1 << 15)

    ppp0_ip = get_if_addr(iface)
    conf.route.add(net='8.8.8.8/32', dev=iface)

    for i in range(5):
        packet = IP(src=ppp0_ip, dst="8.8.8.8") / ICMP(id=id, seq=random.randint(1, 1 << 15))
        ans, _ = sndrcv(s, packet, timeout=10, verbose=0)

        # self.log.debug("Ping sent")
        rx = False
        if len(ans) > 0:
            if ans[0][1][ICMP].type == 0 and ans[0][1][ICMP].id == id:
                # rx = ans[0][1]
                # tx = ans[0][0]
                # delta = rx.time - tx.sent_time
                # rx = True
                print("ok")
            else:
                print("ICMP")
        else:
            print("Timeout")


    conf.route.delt(net='8.8.8.8/32', dev='ppp0')


    time.sleep(.5)