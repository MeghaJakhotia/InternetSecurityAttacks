#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <stdlib.h>

struct udpheader {
	u_int16_t udp_sport;
	u_int16_t udp_dport;
	u_int16_t udp_ulen;
	u_int16_t udp_sum;
};
struct ipheader {
	unsigned char iph_ihl:4, iph_ver:4;
	unsigned char iph_tos;
	unsigned short int iph_len;
	unsigned short int iph_ident;
	unsigned short int iph_flag:3, iph_offset:13;
	unsigned char iph_ttl;
	unsigned char iph_protocol;
	unsigned short int iph_chksum;
	struct in_addr iph_sourceip;
	struct in_addr iph_destip;
};

void send_raw_ip_packet (struct ipheader *ip) {
	int sd;
	int enable = 1;
	struct sockaddr_in sin;
	/* Create a raw socket with IP protocol. The IPPROTO_RAW parameter tells the sytem that the IP header is already included;
	* this prevents the OS from adding another IP header. */
	sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if(sd < 0) {
		perror("socket() error"); exit(-1);
	}
	setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));
	/* This data structure is needed when sending the packets using sockets. Normally, we need to fill out several
	* fields, but for raw sockets, we only need to fill out this one field */
	sin.sin_family = AF_INET;
	sin.sin_addr = ip->iph_destip;
	/* Send out the IP packet. ip_len is the actual size of the packet. */
	if(sendto(sd, ip, ntohs(ip->iph_len), 0, (struct sockaddr *)&sin,sizeof(sin)) < 0) {
		perror("sendto() error"); exit(-1);
	}
}

int main() {
	char buffer[1500];
	memset(buffer, 0, 1500);
	struct ipheader *ip = (struct ipheader *) buffer;
	struct udpheader *udp = (struct udpheader *) (buffer + sizeof(struct ipheader));
	// Filling in UDP Data field
	char *data = buffer + sizeof(struct ipheader) + sizeof(struct udpheader);
	const char *msg="Hello Server!\n";
	int data_len = strlen(msg);
	strncpy(data, msg, data_len);
	// Fill in the UDP header
	udp->udp_sport = htons(12345);
	udp->udp_dport = htons(9090);
	udp->udp_ulen = htons(sizeof(struct udpheader) + data_len);
	udp->udp_sum = 0;
	// Fill in the IP header
	ip->iph_ver = 4;
	ip->iph_ihl = 5;
	ip->iph_ttl = 20;
	ip->iph_sourceip.s_addr = inet_addr("1.2.3.4");
	ip->iph_destip.s_addr = inet_addr("10.0.2.5");
	ip->iph_protocol = IPPROTO_UDP;
	ip->iph_len=htons(sizeof(struct ipheader)+sizeof(struct udpheader) + data_len);
	// Send the spoofed packet
	send_raw_ip_packet(ip);
	return 0;
}