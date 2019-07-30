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

#include "monitor_proc.h"

int udp_client_init(struct socket **s)
{
	struct timeval tv = {0,500000};
	int flag = 1;
	int err = sock_create_kern(AF_INET, SOCK_DGRAM, IPPROTO_UDP, s);
	if (err < 0) {
		MY_PRINT("Error %d while creating socket\n", err);
		*s = NULL;
		return err;
	}
	//MY_PRINT("Socket created\n");

	kernel_setsockopt(*s, SOL_SOCKET, SO_RCVTIMEO , (char * )&tv, sizeof(tv));
	kernel_setsockopt(*s, SOL_SOCKET, SO_REUSEADDR , (char * )&flag, sizeof(int));
	//kernel_setsockopt(*s, SOL_SOCKET, SO_REUSEPORT , (char * )&flag, sizeof(int));

	return 0;
}

int udp_send_data(struct socket *sock, char *addr, u16 port, void *data, size_t data_len)
{
	struct msghdr hdr;
	struct kvec vec;
	struct sockaddr_in address;
	memset(&hdr, 0, sizeof(hdr));
	memset(&address, 0, sizeof(address));

	address.sin_addr.s_addr = in_aton(addr);
	address.sin_port = htons(port);
	address.sin_family = AF_INET;

	hdr.msg_name = &address;
	hdr.msg_namelen = sizeof(struct sockaddr_in);
	vec.iov_len = data_len;
	vec.iov_base = data;

	return kernel_sendmsg(sock, &hdr, &vec, 1, data_len);
}

int udp_receive(struct socket *sock, void *buf, size_t buf_len)
{
	struct msghdr hdr;	
	struct kvec vec;
	
	memset(&hdr, 0, sizeof(hdr));
	memset(&vec, 0, sizeof(vec));
	vec.iov_base = buf;
	vec.iov_len = buf_len;

	return kernel_recvmsg(sock, &hdr, &vec, 1, buf_len, 0);
}

