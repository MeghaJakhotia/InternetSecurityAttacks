#!/usr/bin/python

# Scapy Sniffing
from scapy.all import *

def print_pkt(pkt):
	pkt.show()

pkt = sniff(filter='icmp',prn=print_pkt)
# pkt = sniff(filter='tcp and src host 10.0.2.5 and dst host 23',prn=print_pkt)
# pkt = sniff(filter='net 126.18.0.0/16',prn=print_pkt)
