#include "sniffd.h"

uint32_t	*ip_search(uint32_t ip, uint32_t *stats) { // binary search
	int32_t	first, last, middle;
	
	if (!(*stats))
		return (NULL);
	first = 1;
	last = (*stats * 2) - 1;
	middle = (first + last) / 2;
	
	if (middle % 2 == 0)
		--middle;
	while (first <= last) {	
		if (stats[middle] < ip)
			first = middle + 2;
		else if (stats[middle] == ip)
			return (&stats[middle]);
		else
			last = middle - 2;
		if ((middle = (first + last) / 2) % 2 == 0)
			--middle;
	}
	return (NULL);
}

void		ip_shift(uint32_t *stats, uint32_t pos) {
	uint32_t	i;

	i = *stats * 2 - 1;
	while (i > pos) {
		stats[i + 1] = stats[i - 1];
		stats[i] = stats[i - 2];
		i -= 2;
	}
}

uint32_t	*ip_new(uint32_t ip, uint32_t *stats) {
	uint32_t	i, n;

	if (*stats >= STATS_MAX_IP)
		return (NULL);
	n = ++stats[0];
	n = ((n - 1) * 2) + 1;
	i = 1;
	while (i < n) {
		if (stats[i] > ip) {
			ip_shift(stats, i);
			break;
		}
		i += 2;
	}
	stats[i] = ip;
	return (&stats[i]);
}

void	process_data(char *buffer, uint32_t *stats) {
	struct iphdr	*iph;
	uint32_t		*cur;
	uint32_t		ip;

	iph = (struct iphdr *)buffer;
	ip = iph->saddr;
	cur = ip_search(ip, stats);
	if (cur == NULL)
		cur = ip_new(ip, stats);
	if (cur == NULL)
		return ;
	++cur[1];
	msync(stats, STATS_SIZE, MS_SYNC);
}

void	sniffer(int sock, uint32_t *stats) {
	ssize_t				data_size;
	socklen_t			saddr_size;
	struct sockaddr		saddr;
	char				buffer[SNIFF_BUFF_SIZE];
	
	while (1) {
		saddr_size = sizeof(saddr);
		data_size = recvfrom(sock, buffer, SNIFF_BUFF_SIZE,
		0, &saddr, &saddr_size);
		if (data_size < 0) {
			close(sock);
			munmap(stats, STATS_SIZE);
			exit(EXIT_FAILURE);
		}
		process_data(buffer + sizeof(struct ethhdr), stats);
	}
}

void	handle_request(int cl, char *buf, char *conf, pid_t *sniff) {
	char	op;

	op = *buf;
	if (op == OP_START) {
		op_start(cl, conf, sniff);
	} else if (op == OP_STOP) {
		op_stop(cl, sniff);
	} else if (op == OP_SHOW_IFACE) {
		op_ifaces(cl);
	} else if (op == OP_SELECT_IFACE) {
		if (op_select_iface(cl, conf, &buf[1]) == 0 &&
		*sniff != 0 && kill(*sniff, 0) != -1) {
			op_stop(cl, sniff);
			op_start(cl, conf, sniff);
		}
	} else if (op == OP_STAT_ALL) {
		op_stat(cl, NULL);
	} else if (op == OP_STAT_IFACE) {
		op_stat(cl, &buf[1]);
	} else if (op == OP_SHOW_IP_COUNT) {
		op_show_ip_count(cl, conf, &buf[1]);
	}
	close(cl);
}

void	sniffd(void) {
	struct sockaddr_un	addr;
	char				buf[UN_BUFF_SIZE];
	char				*conf;
	int					sock, cl;
	pid_t				sniff;

	conf = access_mmap("conf.bin", CONF_SIZE);
	sock = create_unix_socket(&addr);
	unlink(UN_SOCKET_PATH);
	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1)
		exit(EXIT_FAILURE);
	if (listen(sock, 5) == -1)
		exit(EXIT_FAILURE);
	while (1) {
		bzero(buf, UN_BUFF_SIZE);
		if ((cl = accept(sock, NULL, NULL)) == -1)
			continue;
		if (read(cl, buf, UN_BUFF_SIZE) == -1)
			continue;
		handle_request(cl, buf, conf, &sniff);
	}
}

