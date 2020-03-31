# [SEED Attack Labs](https://seedsecuritylabs.org/) 

These labs cover some of the most common network attack techniques and vulnerabilities. These labs also cover different defense mechanisms, including intrusion detection, firewalls, tracing the source of attacks, anonymous communication, IPsec, virtual private network, and PKI. 

## Table of Contents 

- [Getting Started](#getting-started)
- [Motivation](#motivation)
- [List of Attacks](#list-of-attacks)
- [Key Learnings](#key-learnings)
- [References](#references)


## Getting Started

These instructions will get you to set up the environment on your local machine to perform these attacks.

Step 1: Create a new VM in Virtual Box.\
Step 2: Download the image [SEEDUbuntu-16.04-32bit.zip](https://seedsecuritylabs.org/lab_env.html) from here.\
Step 3: Use the Virtual Machine Hard Disk file to setup your VM.\
Step 4: Configure the VM.

The [link](https://seedsecuritylabs.org/lab_env.html) contains a document that can be used to set up the VM without any issues.

## Motivation
The labs were completed as a part of the Internet Security (CSE644) course at Syracuse University. The course is well structured to understand the concepts of Internet Security.

## List of Attacks

1. **Sniffing and Spoofing**
>*Description:* Packet sniffing and spoofing are the two important concepts in network security; they are two major threats in network communication. I not only learned to use various sniffing tools such as Wireshark but also learned the way they work. In this lab, I write a sniffing and spoofing program in C as well as Python (Scapy).

2. **ARP Cache Poisoning Attack**
>*Description:* The Address Resolution Protocol (ARP) is a communication protocol used for discovering the link-layer address, such as a MAC address, given an IP address. The ARP protocol is very simple, and it does not implement any security measure. The ARP cache poisoning attack is a common attack against the ARP protocol. Under such an attack, attackers can fool the victim into accepting forged IP-to-MAC mappings. In this lab, we exploit this vulnerability and cause the victim's packets to be redirected to the computer with the forged MAC address.

3. **IP Attacks**
>*Description:* In this lab, we understand the way fragmentation works and perform attacks such as DOS Attack, Ping-of-death attack, Teardrop attack, ICMP redirect attack by exploiting the vulnerabilities at Layer 3.

4. **TCP Attacks**
>*Description:* The vulnerabilities in the TCP/IP protocols represent a special genre of vulnerabilities in protocol designs and implementations; they provide an invaluable lesson as to why security should be designed in from the beginning, rather than being added as an afterthought. Moreover, studying these vulnerabilities helped me understand the challenges of network security and why many network security measures are needed.

5. **Mitnick Attack**
>*Description:* In this lab, we perform TCP Session Hijacking attack on a machine. As done by Mitnick, we exploit the relationship between a trusted server and a sensitive server and plant a backdoor on the sensitive machine to gain unrestricted access.

6. **DNS Cache Poisoning Attack**
>*Description:* Here, we perform local and remote DNS Cache Poisoning attack. DNS (Domain Name System) is the Internet’s phone book; it translates hostnames to IP addresses and vice versa. This translation is through DNS resolution, which happens behind the scene. DNS attacks manipulate this resolution process in various ways, with an intent to misdirect users to alternative destinations, which are often malicious

7. **DNS Rebinding Attack**
>*Description:* In this lab, we demonstrate the functioning of DNS Rebinding Attack - linking the original domain name to different IP address, in order to gain access to restricted home network. We also see how it can be used to exploit the IoT devices in the home network. 

## Key Learnings

- These attack labs give us the idea of fundamental principles of internet security, including network attacks and protocols, cryptography, VPN, and many more.

- Identifying the vulnerabilities and exploiting them. Further work on countermeasures as a security solution to the problem.


## References

1. https://www.handsonsecurity.net/courses/intsec/labs.html
2. Internet Security: A Hands-on Approach by Wenliang Du 

