#include <stdio.h>
#include <signal.h>
#include <ifaddrs.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include "sniffd.h"

void	error(char *msg) {
	perror(msg);
	exit(EXIT_FAILURE);
}

pid_t	init_daemon(void) {
	pid_t	pid, sid;

	pid = fork();
	if (pid < 0)
		error("ERROR on fork");
	if (pid > 0)
		exit(EXIT_SUCCESS);
	umask(0);
	sid = setsid();
	if (sid < 0)
		error("ERROR on sid");
	chdir("/");
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
	return (sid);
}

void	*access_mmap(char *fname, size_t size) {
	int		fd, acc;
	void	*map;

	if ((acc = access(fname, F_OK)) == -1) { // check file exist
		if ((fd = open(fname, O_RDWR | O_CREAT, 0777)) < 0) // create new
			error("ERROR on open/create");
		if (lseek(fd, size - 1, SEEK_SET) < 0) {
			close(fd);
			error("ERROR on lseek");
		}
		if (write(fd, "", 1) < 0) {
			close(fd);
			error("ERROR on write");
		}
	} else if ((fd = open(fname, O_RDWR)) < 0) {
		error("ERROR in open");
	}
	map = mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		close(fd);
		error("ERROR on mmap");
	}
	if (acc == -1) {
		memset(map, 0, size); // clear new file ( to be sure :) )
		msync(map, size, MS_SYNC);
	}
	return (map);
}

void	op_start(char *conf) {
	pid_t			daemon;
	int				sock;
	char			device[IF_NAMESIZE];
	uint32_t		*stats;

	if (conf[CONF_IFACE_POS] == 0) // check selected iface
		op_select_iface(conf, DEFAULT_IFACE);
	strcpy(device, &conf[CONF_IFACE_POS]); // get iface name
	stats = (uint32_t *)access_mmap(device, STATS_SIZE); // connect stats
	if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0)
		error("ERROR on socket");
	if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE,
	device, strlen(device)) < 0) // bind socket to selected iface
		error("ERROR on setsockopt");
	memcpy(&daemon, conf, 4); // get daemon pid
	if (!daemon || kill(daemon, 0) == -1) {
		printf("Starting sniffing on %s\n", device);
		daemon = init_daemon(); // start daemon
		memcpy(conf, &daemon, 4); // set daemon pid in config
		while (1) {
			sniffer(sock, stats);
		}
	} else {
		fprintf(stderr, "Sniffing already started!\n");
		munmap(stats, STATS_SIZE);
	}
}

void	op_stop(char *conf) {
	pid_t	daemon;

	memcpy(&daemon, conf, 4); // get daemon pid from config file
	if (daemon != 0 && kill(daemon, SIGINT) != -1) {
		memset(conf, 0, 4); // clear daemon pid in config file
		printf("Sniffing stopped\n");
	} else {
		fprintf(stderr, "Nothing to stop!\n");
	}
}

void	op_ifaces(void) {
	struct ifaddrs	*ifa, *tmp;
	int				i;

	if (getifaddrs(&ifa) < 0)
		error("ERROR on getifaddrs");
	tmp = ifa;
	i = 0;
	printf("Available running ifaces :\n");
	while (tmp != NULL) {
		if ((tmp->ifa_flags & IFF_UP) == IFF_UP &&
		tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_PACKET &&
		tmp->ifa_name != NULL) {
			printf("%-5d: %s\n", ++i, tmp->ifa_name);
		}
		tmp = tmp->ifa_next;
	}
	printf("\n");
	freeifaddrs(ifa);
}

void	op_select_iface(char *conf, char *new_iface) {
	struct ifaddrs	*ifa, *tmp;
	size_t			len;

	if ((len = strlen(new_iface)) >= IF_NAMESIZE) {
		fprintf(stderr, "Too long iface name!\n");
		exit(EXIT_FAILURE);
	}
	if (!strcmp(&conf[CONF_IFACE_POS], new_iface)) {
		fprintf(stderr, "iface already selected \"%s\"\n", new_iface);
		exit(EXIT_FAILURE);
	}
	if (getifaddrs(&ifa) < 0)
		error("ERROR on getifaddrs");
	tmp = ifa;
	while (tmp != NULL) {
		if ((tmp->ifa_flags & IFF_UP) == IFF_UP &&
		tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_PACKET &&
		tmp->ifa_name != NULL && !strcmp(tmp->ifa_name, new_iface)) {
			freeifaddrs(ifa);
			memset(&conf[CONF_IFACE_POS], 0, IF_NAMESIZE); // clear
			memcpy(&conf[CONF_IFACE_POS], new_iface, len); // set iface
			return ;
		}
		tmp = tmp->ifa_next;
	}
	fprintf(stderr, "No available iface called \"%s\"\n\n", new_iface);
	freeifaddrs(ifa);
	op_ifaces();
	exit(EXIT_FAILURE);
}

void	print_stat(char *iface) {
	uint32_t		*stat;
	uint32_t		i, n, res;
	unsigned char	bytes[4];

	printf("STATISTICS FOR %s \n\n", iface);
	stat = (uint32_t *)access_mmap(iface, STATS_SIZE);
	if (*stat == 0) {
		printf("No collected statistic available\n\n");
	} else {
		res = 0;
		n = ((*stat - 1) * 2) + 1;
		i = 1;
		while (i <= n) {
			res += stat[i + 1];
			bytes[0] = stat[i] & 0xFF;
			bytes[1] = (stat[i] >> 8) & 0xFF;
			bytes[2] = (stat[i] >> 16) & 0xFF;
			bytes[3] = (stat[i] >> 24) & 0xFF;
			printf("IP        : %u.%u.%u.%u\n",
			bytes[0], bytes[1], bytes[2], bytes[3]);
			printf("received  : %u\n\n", stat[i + 1]);
			i += 2;
		}
	}
	printf("total ip was connected : %u\n", *stat);
	printf("total packets received : %u\n\n", res);
	printf("END STATISTICS FOR %s\n\n", iface);
}

void	op_stat(char *iface) {
	struct ifaddrs	*ifa, *tmp;

	if (getifaddrs(&ifa) < 0)
		error("ERROR on getifaddrs");
	tmp = ifa;
	while (tmp != NULL) {
		if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_PACKET &&
		tmp->ifa_name != NULL) {
			if (!iface || (iface && !strcmp(tmp->ifa_name, iface))) {
				print_stat(tmp->ifa_name);
			}
		}
		tmp = tmp->ifa_next;
	}
	freeifaddrs(ifa);
}

void	op_show_ip_count(char *conf, char *ip) {
	struct sockaddr_in	sa;
	uint32_t			*stats, *res;

	if (!inet_pton(AF_INET, ip, &(sa.sin_addr))) {
		fprintf(stderr, "wrong ipv4 address : \"%s\"\n", ip);
		exit(EXIT_FAILURE);
	}
	stats = access_mmap(&conf[CONF_IFACE_POS], STATS_SIZE);
	res = ip_search(sa.sin_addr.s_addr, stats);
	if (res != NULL)
		printf("%u\n", res[1]);
	else
		fprintf(stderr, "no records for \"%s\" in %s\n",
		ip, &conf[CONF_IFACE_POS]);
}

void	op_help(void) {
	printf("Usage: sniffd [COMMAND][[COMMAND_OPT]...]\n\n");
	printf("Commands:\n\n");
	printf("start                 start sniffing packets on \
selected iface\n\
                      (by default \"eth0\")\n\n");
	printf("stop                  stop sniffing packets\n\n");
	printf("show [ip] count       print number of packets \
received from [ip]\n\n");
	printf("select iface [iface]  select iface for sniffing\n\n");
	printf("stat [iface]          show all collected statistics \
for particular iface,\n\
                      if iface omitted - for all ifaces\n\n");
};

int		parse_request(int argc, char **argv) {
	if (argc == 2 && !strcmp(argv[1], "start")) {
		return (OP_START);
	} else if (argc == 2 && !strcmp(argv[1], "stop")) {
		return (OP_STOP);
	} else if (argc > 2 && !strcmp(argv[1], "select") &&
	!strcmp(argv[2], "iface")) {
		if (argc == 3)
			return (OP_SHOW_IFACE);
		else if (argc == 4)
			return (OP_SELECT_IFACE);
	} else if (argc > 1 && !strcmp(argv[1], "stat")) {
		if (argc == 2)
			return (OP_STAT_ALL);
		else if (argc == 3)
			return (OP_STAT_IFACE);
	} else if (argc == 4 && !strcmp(argv[1], "show") &&
	!strcmp(argv[3], "count")) {
		return (OP_SHOW_IP_COUNT);
	} else if (argc == 2 && !strcmp(argv[1], "--help")) {
		return (OP_HELP);
	}
	return (0);
}

void	handle_request(char **argv, char *conf, int op) {
	pid_t	daemon;

	if (op == OP_START) {
		op_start(conf);
	} else if (op == OP_STOP) {
		op_stop(conf);
	} else if (op == OP_SHOW_IFACE) {
		op_ifaces();
	} else if (op == OP_SELECT_IFACE) {
		op_select_iface(conf, argv[3]);
		memcpy(&daemon, conf, 4);
		if (daemon != 0) {
			op_stop(conf);
			op_start(conf);
		}
	} else if (op == OP_STAT_ALL) {
		op_stat(NULL);
	} else if (op == OP_STAT_IFACE) {
		op_stat(argv[2]);
	} else if (op == OP_SHOW_IP_COUNT) {
		op_show_ip_count(conf, argv[2]);
	} else if (op == OP_HELP) {
		op_help();
	} else {
		fprintf(stderr, "try \'%s --help\' for more information\n",
		argv[0]);
	}
}

int		main(int argc, char **argv) {
	char	*conf;
	int		op;

	if (argc < 2) {
		fprintf(stderr, "try \'%s --help\' for more information\n",
		argv[0]);
		return (EXIT_FAILURE);
	}
	if (getuid() != 0) {
		fprintf(stderr, "Please, use root access (sudo)!\n\
It is necessary because of using of raw sockets\n");
		return (EXIT_FAILURE);
	}
	conf = (char *)access_mmap("conf.bin", CONF_SIZE);	// access config
	op = parse_request(argc, argv);
	handle_request(argv, conf, op);
	munmap(conf, CONF_SIZE);
	return EXIT_SUCCESS;
}
