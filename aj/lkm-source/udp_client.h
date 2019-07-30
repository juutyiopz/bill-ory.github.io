#ifndef _LKM_PROXY_UDP_CLIENT_H_
#define _LKM_PROXY_UDP_CLIENT_H_

int udp_send_data(struct socket *sock, char *addr, u16 port, void *data, size_t data_len);
int udp_receive(struct socket *sock, void *buf, size_t buf_len);
int udp_client_init(struct socket **s);

#endif

