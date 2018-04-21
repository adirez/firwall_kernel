#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/ip.h>

#define TCP_PROTO 6
#define TCP_WORD_SIZE 4
#define LOG_TAG "[NETFILTER]"

char* Strstr(char *str, char *target) {
  char *p1 = str;
  if (!*target) return str;
  
  while (*p1) {
    char *p1Begin = p1, *p2 = (char*)target;
    while (*p1 && *p2 && *p1 == *p2) {
      p1++;
      p2++;
    }
    if (!*p2)
      return p1Begin;
    p1 = p1Begin + 1;
  }
  return NULL;
}

int Strncmp(unsigned char * s1, unsigned char * s2, int n )
{
    while ( n && *s1 && ( *s1 == *s2 ) )
    {
        ++s1;
        ++s2;
        --n;
    }
    if ( n == 0 )
    {
        return 0;
    }
    else
    {
        return ( *(unsigned char *)s1 - *(unsigned char *)s2 );
    }
}

int Strlen(unsigned char *str)
{
        unsigned char *s;

        for (s = str; *s; ++s);
        return (s - str);
}

static struct nf_hook_ops hk;

//basically a copy of the variables fed into 'hk' below
unsigned int nf_hook_ex(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)) {
	struct tcphdr *tcp_header;	//tcp header struct (not used)
	struct iphdr *ip_header;	//ip header struct
	unsigned char *data;	//tCP data begin pointer
	unsigned char* data_cur;	
	
	//if packet is empty do nothing - accept 
	if(!skb) { 
		return NF_ACCEPT;
	}
	
	//check the IP protocol, if not tcp do nothing - accept
	ip_header = (struct iphdr *)skb_network_header(skb);    //grab network header using accessor
	if (ip_header->protocol != TCP_PROTO) {
		return NF_ACCEPT;
	}

	tcp_header = (struct tcphdr *)skb_transport_header(skb);  //grab transport header - always tcp header
	//calculate pointers for begin and end of TCP packet data
	data = (unsigned char *)((unsigned char *)tcp_header + (tcp_header->doff * TCP_WORD_SIZE));
	
	data_cur = Strstr((unsigned char*)data, "\r\n");
	if (data_cur == NULL)
	{
		return NF_ACCEPT;
	}
	while (data_cur > data && (*data_cur) != ' ') {
		--data_cur;
	}

	printk(KERN_INFO "[DATA CURSER:] %c %c", *data_cur, *(data_cur + 1));

	if ((*data_cur) == ' '){
		if(Strncmp(data_cur, " HTTP/", Strlen(" HTTP/")) == 0){
			printk(KERN_INFO "dropping valid HTTP packet");
			return NF_DROP;
		}
	}
	return NF_ACCEPT;
        
}
 
//called when module loaded using 'insmod'
int kmod_init(void) {
	//just some fancy C to copy an inline struct
	hk = (struct nf_hook_ops) {
		.hook = nf_hook_ex, //this is important, this variable is of type nf_hookfn - the signature of the function MUST match this type
		.hooknum = NF_INET_LOCAL_OUT, //triggered by any locally created outbound traffic as soon it hits the network stack
		.pf = PF_INET, //just hook for Internet Packets
		.priority = NF_IP_PRI_FIRST //run this hook before any other hook
	};
	nf_register_hook(&hk);
	 
	return 0;
}
 
//called when module unloaded using 'rmmod'
void kmod_exit(void){
	nf_unregister_hook(&hk);
}
 
//some standard macros to pass the kernel compile script some information
module_init(kmod_init);
module_exit(kmod_exit);
