obj-m += proxy.o
proxy-objs := loopback_proxy.o monitor_proc.o hide_ip_port_map.o client_list.o udp_client.o hide_info.o caddy_array.o caddy_conf_array.o checkchange_array.o
all:
	        make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	        make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
