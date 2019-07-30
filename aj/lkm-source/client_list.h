#ifndef _CLIENT_LIST_H_
#define _CLIENT_LIST_H_

#include <linux/spinlock.h>
#include <linux/list.h>

struct client_node {
    struct list_head list;
    u32 ip;
    u16 port;
};

struct client_list {
    int max_num;
    spinlock_t lock;
    struct list_head list;
};

void destroy_client_list(struct client_list *clist);
int init_client_list(struct client_list *clist, int max_num);
int client_check_and_update(struct client_list *clist, u32 ip, u16 port);
void client_add_to_list(struct client_list *clist, u32 ip, u16 port);
int skb_add_to_list(struct sk_buff *skb, struct client_list *flist, struct client_list *slist);

#endif

