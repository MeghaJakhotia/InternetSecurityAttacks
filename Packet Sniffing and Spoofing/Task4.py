#!usr/bin/python3
from scapy.all import *
# Sniffing and then Spoofing

def spoof_pkt(pkt):
	if ICMP in pkt and pkt[ICMP].type == 8:
		a = IP(src=pkt[IP].dst, dst=pkt[IP].src, ihl=pkt[IP].ihl)
		a[IP].dst = pkt[IP].src
		b = ICMP(type=0,id=pkt[ICMP].id, seq=pkt[ICMP].seq)
		data = pkt[Raw].load
		newpacket = a/b/data
		send(newpacket)


pkt = sniff(filter='icmp',prn=spoof_pkt)


