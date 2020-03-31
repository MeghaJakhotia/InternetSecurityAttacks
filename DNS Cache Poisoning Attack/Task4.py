#!/usr/bin/python
from scapy.all import *


IP_packet = IP(dst="10.0.2.8", src="10.0.2.5")
UDP_packet = UDP(dport=53, sport=33333, chksum=0)
Qdsec = DNSQR(qname='aaaaa.example.com')
DNSpkt = DNS(id=0xAAAA, qr=0,qdcount=1,ancount=0, nscount=0, arcount=0, qd=Qdsec)

request = IP_packet/UDP_packet/DNSpkt

with open('ip_req.bin','wb') as f:
	f.write(bytes(request))

