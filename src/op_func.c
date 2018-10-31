#include "sniffd.h"

int		raw_socket(char *iface) {
	int					sock;
	struct ifreq		ifr;
	struct sockaddr_ll	sll;

	if ((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0)
		return (-1);
	bzero(&ifr, sizeof(ifr));
	bzero(&sll, sizeof(sll));
	strcpy((char *)ifr.ifr_name, iface);
	if ((ioctl(sock, SIOCGIFINDEX, &ifr)) == -1)
		return (-1);
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifr.ifr_ifindex;
	sll.sll_protocol = htons(ETH_P_IP);
	if ((bind(sock, (struct sockaddr *)(&sll), sizeof(sll))) == -1)
		return (-1);
	return (sock);
}

void	op_start(int cl_sock, char *conf, pid_t *sniff) {
	pid_t			pid;
	int				sock;
	char			device[IF_NAMESIZE];
	uint32_t		*stats;

	if (*sniff != 0 && kill(*sniff, 0) != -1) {
		dprintf(cl_sock, "Sniffing already started\n");
		return ;
	}
	if (conf[CONF_IFACE_POS] == 0 &&
	op_select_iface(cl_sock, conf, DEFAULT_IFACE) == -1) {
		return;
	}
	strcpy(device, &conf[CONF_IFACE_POS]); // get iface name
	stats = (uint32_t *)access_mmap(device, STATS_SIZE); // connect stats
	if ((sock = raw_socket(device)) < 0) { // create raw socket
		dprintf(cl_sock, "ERROR on raw socket creation: %s\n",
		strerror(errno));
	}
	pid = fork();	// one more proc for sniffing :)
	if (pid == 0) {
		close(cl_sock);
		munmap(conf, CONF_SIZE);
		sniffer(sock, stats); // while true loop sniffing
		exit(EXIT_FAILURE); // for undefined cases
	} else if (pid < 0) {
		dprintf(cl_sock, "ERROR on fork: %s\n", strerror(errno));
		close(cl_sock);
		munmap(stats, STATS_SIZE);
	} else {
		*sniff = pid;
		dprintf(cl_sock, "Starting sniffing on %s\n",
		&conf[CONF_IFACE_POS]);
	}
	munmap(stats, STATS_SIZE);
}

void	op_stop(int cl_sock, pid_t *sniff) {
	if (*sniff != 0 && kill(*sniff, SIGINT) != -1) {
		*sniff = 0;
		dprintf(cl_sock, "Sniffing stopped\n");
	} else {
		dprintf(cl_sock, "Nothing to stop!\n");
	}
}

void	op_ifaces(int cl_sock) {
	struct ifaddrs	*ifa, *tmp;
	int				i;

	if (getifaddrs(&ifa) < 0) {
		dprintf(cl_sock, "ERROR on getifaddrs: %s\n", strerror(errno));
		return;
	}
	tmp = ifa;
	i = 0;
	dprintf(cl_sock, "Available running ifaces :\n");
	while (tmp != NULL) {
		if ((tmp->ifa_flags & IFF_UP) == IFF_UP &&
		tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_PACKET &&
		tmp->ifa_name != NULL) {
			dprintf(cl_sock, "%-5d: %s\n", ++i, tmp->ifa_name);
		}
		tmp = tmp->ifa_next;
	}
	dprintf(cl_sock, "\n");
	freeifaddrs(ifa);
}

int		op_select_iface(int cl_sock, char *conf, char *new_iface) {
	struct ifaddrs	*ifa, *tmp;
	size_t			len;

	if ((len = strlen(new_iface)) >= IF_NAMESIZE) {
		dprintf(cl_sock, "Too long iface name!\n");
		return (-1);
	}
	if (!strcmp(&conf[CONF_IFACE_POS], new_iface)) {
		dprintf(cl_sock, "iface already selected \"%s\"\n", new_iface);
		return (1);
	}
	if (getifaddrs(&ifa) < 0) {
		dprintf(cl_sock, "ERROR on getifaddrs: %s\n", strerror(errno));
		return (-1);
	}
	tmp = ifa;
	while (tmp != NULL) {
		if ((tmp->ifa_flags & IFF_UP) == IFF_UP &&
		tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_PACKET &&
		tmp->ifa_name != NULL && !strcmp(tmp->ifa_name, new_iface)) {
			freeifaddrs(ifa);
			memset(&conf[CONF_IFACE_POS], 0, IF_NAMESIZE); // clear
			memcpy(&conf[CONF_IFACE_POS], new_iface, len); // set iface
			dprintf(cl_sock, "Selected iface %s\n", new_iface);
			return (0);
		}
		tmp = tmp->ifa_next;
	}
	dprintf(cl_sock, "No available iface called \"%s\"\n\n", new_iface);
	freeifaddrs(ifa);
	op_ifaces(cl_sock);
	return (-1);
}

void	print_stat(int cl_sock, char *iface) {
	uint32_t		*stat;
	uint32_t		i, n, res;
	unsigned char	bytes[4];

	dprintf(cl_sock, "STATISTICS FOR %s \n\n", iface);
	stat = (uint32_t *)access_mmap(iface, STATS_SIZE);
	if (*stat == 0) {
		dprintf(cl_sock, "No collected statistic available\n\n");
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
			dprintf(cl_sock, "IP        : %u.%u.%u.%u\n",
			bytes[0], bytes[1], bytes[2], bytes[3]);
			dprintf(cl_sock, "received  : %u\n\n", stat[i + 1]);
			i += 2;
		}
	}
	dprintf(cl_sock, "total ip was connected : %u\n", *stat);
	dprintf(cl_sock, "total packets received : %u\n\n", res);
	dprintf(cl_sock, "END STATISTICS FOR %s\n\n", iface);
}

void	op_stat(int cl_sock, char *iface) {
	struct ifaddrs	*ifa, *tmp;

	if (getifaddrs(&ifa) < 0) {
		dprintf(cl_sock, "ERROR on getifaddrs: %s\n", strerror(errno));
		return;
	}
	tmp = ifa;
	while (tmp != NULL) {
		if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_PACKET &&
		tmp->ifa_name != NULL) {
			if (!iface || (iface && !strcmp(tmp->ifa_name, iface))) {
				print_stat(cl_sock, tmp->ifa_name);
			}
		}
		tmp = tmp->ifa_next;
	}
	freeifaddrs(ifa);
}

void	op_show_ip_count(int cl_sock, char *conf, char *ip) {
	struct sockaddr_in	sa;
	uint32_t			*stats, *res;

	if (!inet_pton(AF_INET, ip, &(sa.sin_addr))) {
		dprintf(cl_sock, "wrong ipv4 address : \"%s\"\n", ip);
		return;
	}
	stats = access_mmap(&conf[CONF_IFACE_POS], STATS_SIZE);
	res = ip_search(sa.sin_addr.s_addr, stats);
	if (res != NULL)
		dprintf(cl_sock, "%u\n", res[1]);
	else
		dprintf(cl_sock, "no records for \"%s\" in %s\n",
		ip, &conf[CONF_IFACE_POS]);
}

