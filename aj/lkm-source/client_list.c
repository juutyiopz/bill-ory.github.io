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

#include "client_list.h"
#include "monitor_proc.h"

void destroy_client_list(struct client_list *clist)
{
    struct client_node *curr = NULL;
    struct client_node *next = NULL;
	
	list_for_each_entry_safe(curr, next, &clist->list, list) {
        list_del(&(curr->list));
		kfree(curr);
	}
}

int init_client_list(struct client_list *clist, int max_num)
{
    int i = 0;
    int ret = 0;
    struct client_node *node = NULL;
    
	INIT_LIST_HEAD(&(clist->list));
	spin_lock_init(&(clist->lock));

    for (i = 0; i < max_num; i++) {
        node = kmalloc(sizeof( struct client_node), GFP_KERNEL);
        if (node == NULL) {
            ret = -1;
            goto DESTROY;
        }
        node->ip = 0;
        node->port = 0;
        list_add(&node->list, &clist->list);
    }
    ret = 0;
    clist->max_num = max_num;
    goto SUCCESS;
    
DESTROY:
    destroy_client_list(clist);
SUCCESS:
    return ret;
}

int client_check_and_update(struct client_list *clist, u32 ip, u16 port)
{
    int ret = 0;
    struct client_node *curr = NULL;
    struct client_node *next = NULL;
    
	spin_lock_bh(&(clist->lock));
	list_for_each_entry_safe(curr, next, &clist->list, list) {
        if (curr->ip == 0 && curr->port == 0) {
            ret = 0;
            break;
        }
        if (curr->ip == ip && curr->port == port) {
            list_del(&(curr->list));
            list_add(&(curr->list), &(clist->list));
            ret = 1;
            break;
        }
	}
	spin_unlock_bh(&(clist->lock));
    
    return ret;
}

void client_add_to_list(struct client_list *clist, u32 ip, u16 port)
{
    struct client_node *curr = NULL;
    struct client_node *next = NULL;
    
	spin_lock_bh(&(clist->lock));
	list_for_each_entry_safe(curr, next, &clist->list, list) {
        if (curr->ip == 0 && curr->port == 0) {
            curr->ip = ip;
            curr->port = port;
            goto RET;
        }
        if (curr->ip == ip && curr->port == port) {
            list_del(&(curr->list));
            list_add(&(curr->list), &(clist->list));
            goto RET;
        }
    }

    curr = list_entry(clist->list.prev, struct client_node, list);
    curr->ip = ip;
    curr->port = port;
    list_del(&(curr->list));
    list_add(&curr->list, &clist->list);
RET:
	spin_unlock_bh(&(clist->lock));
    return;
}

int skb_add_to_list(struct sk_buff *skb, struct client_list *flist, struct client_list *slist)
{
    struct iphdr *iph = ip_hdr(skb);
    struct tcphdr *tcph = NULL;
    int ihlen = iph->ihl * 4;
    
    skb_set_transport_header(skb, ihlen);
    tcph = tcp_hdr(skb);

    if (tcph->syn) {
        client_add_to_list(flist, iph->saddr, tcph->source);
        return 0;
    }

    if (client_check_and_update(flist, iph->saddr, tcph->source)) {
        return 0;
    } else if (client_check_and_update(slist, iph->saddr, tcph->source)) {
        return 1;
    } else {
        MY_PRINT("Error in add skb.\n");
        client_add_to_list(flist, iph->saddr, tcph->source);
    }

    return 0;
}


