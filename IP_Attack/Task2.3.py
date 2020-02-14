#!/usr/bin/python3
from scapy.all import *
import time

# Scapy Spoofing

ID = 1001
payload1 = "A" * 16
payload2 = "B" * 40
payload3 = "C" * 16

## First Fragment

udp = UDP(sport=7070, dport=9090)
udp.len = 8 + 40 + 16
ip = IP(src="1.2.3.4", dst="10.0.2.8") 
ip.id = ID
ip.frag = 0
ip.flags = 1
pkt = ip/udp/payload1
pkt[UDP].chksum = 0
send(pkt,verbose=0)

## Second Fragment

ip = IP(src="1.2.3.4", dst="10.0.2.8") 
ip.id = ID
ip.frag = 1
ip.flags = 1
ip.proto = 17
pkt = ip/payload2
send(pkt,verbose=0)

## Third Fragment

ip = IP(src="1.2.3.4", dst="10.0.2.8") 
ip.id = ID
ip.frag = 6
ip.flags = 0
ip.proto = 17
pkt = ip/payload3
send(pkt,verbose=0)

print("Finish Sending Packets!")

