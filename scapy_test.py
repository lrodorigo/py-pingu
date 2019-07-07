import random
import time

from scapy.arch import get_if_hwaddr, get_if_addr, L2Socket
from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sndrcv, srp1, srp

while True:
    s = L2Socket(iface="eth0", filter="arp or (icmp and src host 8.8.8.8)")

    id = random.randint(1, 1 << 15)
    for i in range(5):
        packet = Ether(dst="0c:9d:92:43:d3:59"
                           "", src=get_if_hwaddr("eth0")) / \
                 IP(src=get_if_addr("eth0"), dst="8.8.8.8") / \
                 ICMP(id=id, seq=random.randint(1, 1 << 15))

        ans, _ = sndrcv(s, packet, timeout=10, verbose=0)

        # self.log.debug("Ping sent")
        rx = False
        if len(ans) > 0:
            if ans[0][1][ICMP].type == 0 and ans[0][1][ICMP].id == id :
                # rx = ans[0][1]
                # tx = ans[0][0]
                # delta = rx.time - tx.sent_time
                # rx = True
                print("ok")
            else:
                print("ICMP")
        else:
            print("Timeout")
    time.sleep(1)
