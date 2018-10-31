#ifndef SNIFFD_H__
# define SNIFFD_H__
# include <sys/types.h>
# include <net/if.h>
# include <unistd.h>
# include <stdlib.h>
# include <string.h>
# include <sys/mman.h>
# include <sys/un.h>
# include <stdio.h>
# include <signal.h>
# include <ifaddrs.h>
# include <fcntl.h>
# include <arpa/inet.h>
# include <sys/stat.h>
# include <netinet/ip.h>
# include <errno.h>
# include <net/ethernet.h>
# include <sys/ioctl.h>
# include <linux/if_packet.h>

# define CONF_PID_POD		0
# define CONF_IFACE_POS		4
# define CONF_SIZE			(CONF_IFACE_POS + IF_NAMESIZE)
# define DEFAULT_IFACE		"eth0"

# define STATS_IPREC_SIZE	8
# define STATS_MAX_IP		1000
# define STATS_SIZE			(STATS_IPREC_SIZE * STATS_MAX_IP + 4)

# define SNIFF_BUFF_SIZE	(sizeof(struct ethhdr) + sizeof(struct iphdr))

# define OP_START			1
# define OP_STOP			2
# define OP_SHOW_IFACE		3
# define OP_SELECT_IFACE	4
# define OP_STAT_ALL		5
# define OP_STAT_IFACE		6
# define OP_SHOW_IP_COUNT	7
# define OP_HELP			8

# define UN_BUFF_SIZE		(IF_NAMESIZE + 2)
# define UN_SOCKET_PATH		"unix_socket"

// op_func.c
void		op_start(int cl_sock, char *conf, pid_t *sniff);
void		op_stop(int cl_sock, pid_t *sniff);
void		op_ifaces(int cl_sock);
int			op_select_iface(int cl_sock, char *conf, char *iface);
void		print_stat(int cl_sock, char *iface);
void		op_stat(int cl_sock, char *iface);
void		op_show_ip_count(int cl_sock, char *conf, char *ip);

// sniffer.c
int			raw_socket(char *iface);
uint32_t	*ip_search(uint32_t ip, uint32_t *stats); // binary search
void		ip_shift(uint32_t *stats, uint32_t pos);
uint32_t	*ip_new(uint32_t ip, uint32_t *stats);
void		process_data(char *buffer, uint32_t *stats);
void		sniffer(int sock, uint32_t *stats);
void		recv_request(int cl, char *buf);
void		handle_request(int cl, char *buf, char *conf, pid_t *sniff);
void		sniffd(void);

// main.c
void		error(char *str);
pid_t		init_daemon(void);
void		*access_mmap(char *fname, size_t size);
void		print_help(void);
char		parse_request(int argc, char **argv);
int			create_unix_socket(struct sockaddr_un *addr);
int			connect_daemon(void);
int			send_request(int sock, char **argv, char op);
void		recv_res(int sock);

#endif
