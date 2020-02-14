#!/usr/bin/python3
from scapy.all import *

E = Ether(dst='ff:ff:ff:ff:ff:ff', src='08:00:27:b7:ba:af')
A = ARP(hwsrc='08:00:27:b7:ba:af',psrc='10.0.2.9', 
	hwdst='ff:ff:ff:ff:ff:ff', pdst='10.0.2.9')

pkt = E/A
pkt.show()
sendp(pkt)
