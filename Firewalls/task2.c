#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/inet.h>

#define NIPQUAD(addr) ((unsigned char *)&addr)[0], ((unsigned char *)&addr)[1], ((unsigned char *)&addr)[2], ((unsigned char *)&addr)[3]

static struct nf_hook_ops nfho;
static struct nf_hook_ops nfho1;
static struct nf_hook_ops nfho2;
static struct nf_hook_ops nfho3;
static struct nf_hook_ops nfho4;

unsigned int telnet_outgoing(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct tcphdr *tcph;

	iph = ip_hdr(skb);
	tcph = (void *)iph+iph->ihl*4;

	if (iph->protocol == IPPROTO_TCP && tcph->dest == htons(23) && iph->saddr == in_aton("10.0.2.7") && iph->daddr==in_aton("10.0.2.8")) {
		printk(KERN_INFO "Dropping Telnet Packet to destination address: %d.%d.%d.%d\n",NIPQUAD(iph->daddr));
		return NF_DROP;
	} else {
		return NF_ACCEPT;
	}
}

unsigned int ssh_outgoing(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct tcphdr *tcph;

	iph = ip_hdr(skb);
	tcph = (void *)iph+iph->ihl*4;


	if (iph->protocol == IPPROTO_TCP &&  tcph->dest == htons(22) && iph->saddr == in_aton("10.0.2.7") && iph->daddr==in_aton("10.0.2.8")) {
		printk(KERN_INFO "Dropping SSH Packet to destination address: %d.%d.%d.%d\n",NIPQUAD(iph->daddr));
		return NF_DROP;
	} else {
		return NF_ACCEPT;
	}
}

unsigned int telnet_incoming(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct tcphdr *tcph;

	iph = ip_hdr(skb);
	tcph = (void *)iph+iph->ihl*4;

	if (iph->protocol == IPPROTO_TCP && tcph->dest == htons(23) && iph->saddr == in_aton("10.0.2.8") && iph->daddr==in_aton("10.0.2.7")) {
		printk(KERN_INFO "Dropping Telnet Packet from source address: %d.%d.%d.%d\n",NIPQUAD(iph->saddr));
		return NF_DROP;
	} else {
		return NF_ACCEPT;
	}
}

unsigned int ssh_incoming(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct tcphdr *tcph;

	iph = ip_hdr(skb);
	tcph = (void *)iph+iph->ihl*4;

	if (iph->protocol == IPPROTO_TCP && tcph->dest == htons(22) && iph->saddr == in_aton("10.0.2.8") && iph->daddr==in_aton("10.0.2.7")) {
		printk(KERN_INFO "Dropping SSH Packet from source address: %d.%d.%d.%d\n",NIPQUAD(iph->saddr));
		return NF_DROP;
	} else {
		return NF_ACCEPT;
	}
}

unsigned int web_block(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct tcphdr *tcph;

	iph = ip_hdr(skb);
	tcph = (void *)iph+iph->ihl*4;

	if (iph->protocol == IPPROTO_TCP && iph->saddr == in_aton("10.0.2.7") && iph->daddr==in_aton("148.251.191.4") && (tcph->dest == htons(80) || tcph->dest == htons(443)) ) {
		printk(KERN_INFO "Dropping Web Packet to web page on address: %d.%d.%d.%d\n",NIPQUAD(iph->daddr));
		return NF_DROP;
	} else {
		return NF_ACCEPT;
	}
}

int init_module()
{ 
	nfho.hook = telnet_outgoing; /* Handler function */
	nfho.hooknum = NF_INET_LOCAL_OUT; 
	nfho.pf = PF_INET;
	nfho.priority = NF_IP_PRI_FIRST; /* Make our function first */
	nf_register_hook(&nfho);

	nfho1.hook = telnet_incoming; /* Handler function */
	nfho1.hooknum = NF_INET_LOCAL_IN; /* First hook for IPv4 */
	nfho1.pf = PF_INET;
	nfho1.priority = NF_IP_PRI_FIRST; /* Make our function first */
	nf_register_hook(&nfho1);

	nfho2.hook = web_block; /* Handler function */
	nfho2.hooknum = NF_INET_LOCAL_OUT; /* First hook for IPv4 */
	nfho2.pf = PF_INET;
	nfho2.priority = NF_IP_PRI_FIRST; /* Make our function first */
	nf_register_hook(&nfho2);

	nfho3.hook = ssh_outgoing; /* Handler function */
	nfho3.hooknum = NF_INET_LOCAL_OUT; /* First hook for IPv4 */
	nfho3.pf = PF_INET;
	nfho3.priority = NF_IP_PRI_FIRST; /* Make our function first */
	nf_register_hook(&nfho3);

	nfho4.hook = ssh_incoming; /* Handler function */
	nfho4.hooknum = NF_INET_LOCAL_IN; /* First hook for IPv4 */
	nfho4.pf = PF_INET;
	nfho4.priority = NF_IP_PRI_FIRST; /* Make our function first */
	nf_register_hook(&nfho4);

	return 0;
}
/* Cleanup routine */
void cleanup_module()
{
	nf_unregister_hook(&nfho);
	nf_unregister_hook(&nfho1);
	nf_unregister_hook(&nfho2);
	nf_unregister_hook(&nfho3);
	nf_unregister_hook(&nfho4);
}
