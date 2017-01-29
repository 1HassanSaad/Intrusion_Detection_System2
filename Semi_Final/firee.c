#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/list.h>
#include <asm/uaccess.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>


struct mf_rule {
    int in_out;  // 0: neither in nor out, 1: in, 2: out
    int src_ip;
    int src_port;        //0~2^32
    int dest_ip;
    int dest_port;
    int proto;        //0: all, 1: tcp, 2: udp
    int action;        //0: for block, 1: for unblock
    struct list_head list;
};

static struct mf_rule policy_list;
struct nf_hook_ops nfho;
struct nf_hook_ops nfho_out;

bool check_ip(int ip, int ip_rule) {
    if(ip!=ip_rule){
        printk(KERN_INFO "ip compare: doesn't match\n");
        return false;
    }
    return true;
}

void IpConverter(int ip){
int bytes[4];
    bytes[0] = (ip >> 0) & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    printk("%d.%d.%d.%d \t", bytes[0], bytes[1], bytes[2], bytes[3]);
}

//the hook function itself: regsitered for filtering outgoing packets
unsigned int hook_func_out(unsigned int hooknum, struct sk_buff *skb,
        const struct net_device *in, const struct net_device *out,
        int (*okfn)(struct sk_buff *)) {
   //get src address, src port, dest ip, dest port, protocol//
   struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
   struct udphdr *udp_header;
   struct tcphdr *tcp_header;
   struct list_head *p;
   struct mf_rule *a_rule;
   int i = 0;
   //get src and dest ip addresses
   unsigned int src_ip = (unsigned int)ip_header->saddr;
   unsigned int dest_ip = (unsigned int)ip_header->daddr;
   unsigned int src_port = 0;
   unsigned int dest_port = 0;
   //get src and dest port number
   if (ip_header->protocol==17) {
       udp_header = (struct udphdr *)skb_transport_header(skb);
       src_port = (unsigned int)ntohs(udp_header->source);
       dest_port = (unsigned int)ntohs(udp_header->dest);
   } else if (ip_header->protocol == 6) {
       tcp_header = (struct tcphdr *)skb_transport_header(skb);
       src_port = (unsigned int)ntohs(tcp_header->source);
       dest_port = (unsigned int)ntohs(tcp_header->dest);
   }
   printk(KERN_INFO"OUT packet info: src ip: %u, src port: %u; dest ip: %u, dest port: %u; proto: %u\n", src_ip, src_port, dest_ip, dest_port, ip_header->protocol);
    printk("source ip : ");
    IpConverter(src_ip);
    printk("destination ip : ");
    IpConverter(dest_ip);
   //go through the firewall list and check if there is a match
   //in case there are multiple matches, take the first one
   list_for_each(p, &policy_list.list) {
       i++;
       a_rule = list_entry(p, struct mf_rule, list);
       printk(KERN_INFO "rule %d: a_rule->in_out = %u; a_rule->src_ip = %u; a_rule->src_port=%u; a_rule->dest_ip=%u; a_rule->dest_port=%u; a_rule->proto=%u; a_rule->action=%u\n", i, a_rule->in_out, a_rule->src_ip, a_rule->src_port, a_rule->dest_ip, a_rule->dest_port, a_rule->proto, a_rule->action);
       //if a rule doesn't specify as "out", skip it
       if (a_rule->in_out != 2) {
           printk(KERN_INFO "rule %d (a_rule->in_out: %u) not match: out packet, rule doesn't specify as out\n", i, a_rule->in_out);
           continue;
       } else {
           //check the protocol
           if ((a_rule->proto==1) && (ip_header->protocol != 6)) {
               printk(KERN_INFO "rule %d not match: rule-TCP, packet->not TCP\n", i);
               continue;
           } else if ((a_rule->proto==2) && (ip_header->protocol != 17)) {
               printk(KERN_INFO "rule %d not match: rule-UDP, packet->not UDP\n", i);
               continue;
           }
           //check the ip address
           if (a_rule->src_ip==0) {
              //rule doesn't specify ip: match
           } else {
              if (!check_ip(src_ip, a_rule->src_ip)) {
                  printk(KERN_INFO "rule %d not match: src ip mismatch\n", i);
                  continue;
              }
           }
           if (a_rule->dest_ip == 0) {
               //rule doesn't specify ip: match
           } else {
               if (!check_ip(dest_ip, a_rule->dest_ip)) {
                   printk(KERN_INFO "rule %d not match: dest ip mismatch\n", i);
                   continue;
               }
           }
           //check the port number
           if (a_rule->src_port==0) {
               //rule doesn't specify src port: match
           } else if (src_port!=a_rule->src_port) {
               printk(KERN_INFO "rule %d not match: src port dismatch\n", i);
               continue;
           }
           if (a_rule->dest_port == 0) {
               //rule doens't specify dest port: match
           }
           else if (dest_port!=a_rule->dest_port) {
               printk(KERN_INFO "rule %d not match: dest port mismatch\n", i);
               continue;
           }
           //a match is found: take action
           if (a_rule->action==0) {
               printk(KERN_INFO "a match is found: %d, drop the packet\n", i);
              printk(KERN_INFO "---------------------------------------\n");
               return NF_DROP;
           } else {
               printk(KERN_INFO "a match is found: %d, accept the packet\n", i);
              printk(KERN_INFO "---------------------------------------\n");
               return NF_ACCEPT;
           }
       }
   }
   printk(KERN_INFO "no matching is found, accept the packet\n");
   printk(KERN_INFO "---------------------------------------\n");
   return NF_ACCEPT;
}

//the hook function itself: registered for filtering incoming packets
unsigned int hook_func_in(unsigned int hooknum, struct sk_buff *skb,
        const struct net_device *in, const struct net_device *out,
        int (*okfn)(struct sk_buff *)) {
   //get src address, src port, dest ip dest port, protocol
   struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
   struct udphdr *udp_header;
   struct tcphdr *tcp_header;
   struct list_head *p;
   struct mf_rule *a_rule;

   int i = 0;
   //get src and dest ip addresses

   unsigned int src_ip = (unsigned int)ip_header->saddr;
   unsigned int dest_ip = (unsigned int)ip_header->daddr;
   unsigned int src_port = 0;
   unsigned int dest_port = 0;
   //get src and dest port number
   if (ip_header->protocol==17) { //udp
       udp_header = (struct udphdr *)(skb_transport_header(skb)+20);
       src_port = (unsigned int)ntohs(udp_header->source);
       dest_port = (unsigned int)ntohs(udp_header->dest);
   } else if (ip_header->protocol == 6) { //tcp
       tcp_header = (struct tcphdr *)(skb_transport_header(skb)+20);
       src_port = (unsigned int)ntohs(tcp_header->source);
       dest_port = (unsigned int)ntohs(tcp_header->dest);
   }
   printk(KERN_INFO "IN packet info: src ip: %u, src port: %u; dest ip: %u, dest port: %u; proto: %u\n", src_ip, src_port, dest_ip, dest_port, ip_header->protocol);
    printk("source ip : ");
    IpConverter(src_ip);
    printk("destination ip : ");
    IpConverter(dest_ip);
   //go through the firewall list and check if there is a match
   //in case there are multiple matches, take the first one
   list_for_each(p, &policy_list.list) {
       i++;
       a_rule = list_entry(p, struct mf_rule, list);
printk(KERN_INFO "rule %d: a_rule->in_out = %u; a_rule->src_ip = %u; a_rule->src_port=%u; a_rule->dest_ip=%u; a_rule->dest_port=%u; a_rule->proto=%u; a_rule->action=%u\n", i, a_rule->in_out, a_rule->src_ip, a_rule->src_port, a_rule->dest_ip, a_rule->dest_port, a_rule->proto, a_rule->action);
    printk("source ip : ");
    IpConverter(a_rule->src_ip);
    printk("destination ip : ");
    IpConverter(a_rule->dest_ip);
       //if a rule doesn't specify as "in", skip it
       if (a_rule->in_out != 1) {
           printk(KERN_INFO "rule %d (a_rule->in_out:%u) not match: in packet, rule doesn't specify as in\n", i, a_rule->in_out);
           continue;
       } else {
           //check the protocol
           if ((a_rule->proto==1/*tcp*/) && (ip_header->protocol == 6)) { //not equal tcp
               printk(KERN_INFO "rule %d not match: rule-TCP, packet->not TCP\n", i);
               continue;
           } else if ((a_rule->proto==2 /*udp*/) && (ip_header->protocol != 17)) { //not equal udp
               printk(KERN_INFO "rule %d not match: rule-UDP, packet->not UDP\n", i);
               continue;
           }
           //check the ip address
           if (a_rule->src_ip==0) {
           } else {
              if (!check_ip(src_ip, a_rule->src_ip)) {
                  printk(KERN_INFO "rule %d not match: src ip mismatch\n", i);
                  continue;
              }
           }
           if (a_rule->dest_ip == 0) {
           } else {
               if (!check_ip(dest_ip, a_rule->dest_ip)) {
                  printk(KERN_INFO "rule %d not match: dest ip mismatch\n", i);
                  continue;
               }
           }
           //check the port number
           if (a_rule->src_port==0) {
               //rule doesn't specify src port: match
           } else if (src_port!=a_rule->src_port) {
               printk(KERN_INFO "rule %d not match: src port mismatch\n", i);
               continue;
           }
           if (a_rule->dest_port == 0) {
               //rule doens't specify dest port: match
           }
           else if (dest_port!=a_rule->dest_port) {
               printk(KERN_INFO "rule %d not match: dest port mismatch\n", i);
               continue;
           }
           //a match is found: take action
           if (a_rule->action==0) {
               printk(KERN_INFO "a match is found: %d, drop the packet\n", i);
               printk(KERN_INFO "---------------------------------------\n");
               return NF_DROP;
           } else {
               printk(KERN_INFO "a match is found: %d, accept the packet\n", i);
               printk(KERN_INFO "---------------------------------------\n");
               return NF_ACCEPT;
           }
       }
   }
   printk(KERN_INFO "no matching is found, accept the packet\n");
   printk(KERN_INFO "---------------------------------------\n");
   return NF_ACCEPT;
}

int add_a_rule(void){
    struct mf_rule* a_rule;
    struct file *fp;
    mm_segment_t fs;
    loff_t pos;
    char buf1[100],s2[20],*p;
    int i,j=0,k=0; unsigned int A[10];
    a_rule = kmalloc(sizeof(*a_rule), GFP_KERNEL);
    if (a_rule == NULL) {
        printk(KERN_INFO "error: cannot allocate memory for a_new_rule\n");
	return 0;
    }
    fp = filp_open("firee.txt",O_RDWR|O_CREAT,0644);//(name,avel,permetion 0 0 0) open
    if (IS_ERR(fp)) {
        printk ("open file error \n");
	return 0;
    }//handling
    fs = get_fs();//get current segment
    set_fs(KERNEL_DS);//set kernal segment
    pos = 0;
    vfs_read(fp, buf1, sizeof(buf1), &pos);//read
    for(i=0;i<strlen(buf1);i++){
        if(buf1[i]==','||i==strlen(buf1)-1){
            A[k]= simple_strtol(s2,&p,0);//str to int 0 is the mode
            k++;j=0;
	    memset(s2,'\0',20);
            continue;
        }
        s2[j]=buf1[i];
        j++;
    }
    for(i=0;i<k-1;i++){printk("read : %u \n",A[i]);}
    filp_close(fp, NULL);//close
    set_fs (fs);//set stored segment
    a_rule->in_out        = A[0];
    a_rule->src_ip        = A[1];
    a_rule->src_port      = A[2];
    a_rule->dest_ip       = A[3];
    a_rule->dest_port     = A[4];
    a_rule->proto         = A[5];
    a_rule->action        = A[6];
    printk(KERN_INFO "add_a_rule: in_out=%u, src_ip=%u, src_port=%u, dest_ip=%u, dest_port=%u, proto=%u, action=%u \n", a_rule->in_out, a_rule->src_ip, a_rule->src_port, a_rule->dest_ip, a_rule->dest_port, a_rule->proto, a_rule->action);
    printk("source ip : ");
    IpConverter(a_rule->src_ip);
    printk("destination ip : ");
    IpConverter(a_rule->dest_ip);
    INIT_LIST_HEAD(&(a_rule->list));
    list_add_tail(&(a_rule->list), &(policy_list.list));
    return 0;
}

int init_module() {
    printk(KERN_INFO "initialize kernel module\n");
    INIT_LIST_HEAD(&(policy_list.list));
    //Fill in the hook structure for incoming packet hook
    nfho.hook = (nf_hookfn *)hook_func_in;
    nfho.hooknum = NF_INET_LOCAL_IN;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&nfho);         // Register the hook
    //Fill in the hook structure for outgoing packet hook
    nfho_out.hook = (nf_hookfn *)hook_func_out;
    nfho_out.hooknum = NF_INET_LOCAL_OUT;
    nfho_out.pf = PF_INET;
    nfho_out.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&nfho_out);    // Register the hook
    add_a_rule();
    return 0;
}

void cleanup_module() {
    struct list_head *p, *q;
    struct mf_rule *a_rule;
    nf_unregister_hook(&nfho);
    nf_unregister_hook(&nfho_out);
    printk(KERN_INFO "free policy list\n");
    list_for_each_safe(p, q, &policy_list.list) {
        printk(KERN_INFO "free one\n");
        a_rule = list_entry(p, struct mf_rule, list);
        list_del(p);
        kfree(a_rule);
    }
    printk(KERN_INFO "kernel module unloaded\n");
}
