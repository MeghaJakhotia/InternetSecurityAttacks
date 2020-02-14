from scapy.all import *

# Traceroute 
TTL = 0
while(True):
	TTL += 1
	a = IP(dst="8.8.8.8", ttl=TTL)
	b = ICMP()
	p = a/b
	reply = sr1(p)
	print"Source IP: ", reply[IP].src
	if (reply[IP].src == "8.8.8.8"):
		break

print "Distance: ", TTL


