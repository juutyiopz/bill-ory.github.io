#ifndef _HIDE_IP_PORT_MAP_H_
#define _HIDE_IP_PORT_MAP_H_

void init_hide_ip_port_map(int timeout);
void update_port_ip(u16 port, u32 ip);
int is_hide_ipaddr(u16 port, u32 ip);

#endif

