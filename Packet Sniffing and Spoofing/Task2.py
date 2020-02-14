from scapy.all import *

# Scapy Spoofing
a = IP(src="8.8.8.8", dst="10.0.2.5")
b = ICMP()
p = a/b
p.show()
send(p)


