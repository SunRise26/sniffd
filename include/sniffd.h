#ifndef SNIFFD_H__
# define SNIFFD_H__
# include <sys/types.h>
# include <net/if.h>
# include <unistd.h>
# include <stdlib.h>
# include <string.h>
# include <sys/mman.h>

# define CONF_PID_POD		0
# define CONF_IFACE_POS		4
# define CONF_SIZE			(CONF_IFACE_POS + IF_NAMESIZE)
# define DEFAULT_IFACE		"eth0"

# define STATS_IPREC_SIZE	8
# define STATS_MAX_IP		1000
# define STATS_SIZE			(STATS_IPREC_SIZE * STATS_MAX_IP + 4)

# define OP_START			1
# define OP_STOP			2
# define OP_SHOW_IFACE		3
# define OP_SELECT_IFACE	4
# define OP_STAT_ALL		5
# define OP_STAT_IFACE		6
# define OP_SHOW_IP_COUNT	7
# define OP_HELP			8

// sniffer.c
uint32_t	*ip_search(uint32_t ip, uint32_t *stats); // binary search
void		ip_shift(uint32_t *stats, uint32_t pos);
uint32_t	*ip_new(uint32_t ip, uint32_t *stats);
void		process_data(char *buffer, uint32_t *stats);
void		sniffer(int sock, uint32_t *stats);

// main.c
void	error(char *str);
pid_t	init_daemon(void);
void	*access_mmap(char *fname, size_t size);
void	op_start(char *conf);
void	op_stop(char *conf);
void	op_ifaces(void);
void	op_select_iface(char *conf, char *iface);
void	print_stat(char *iface);
void	op_stat(char *iface);
void	op_show_ip_count(char *conf, char *ip);
void	op_help(void);
int		parse_request(int argc, char **argv);
void	handle_request(char **argv, char *conf, int op);

#endif
