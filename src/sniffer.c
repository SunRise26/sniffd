#include <netinet/ip.h>
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
	ssize_t			data_size;
	socklen_t		saddr_size;
	struct sockaddr	saddr;
	char			buffer[sizeof(struct iphdr)];

	saddr_size = sizeof(saddr);
	data_size = recvfrom(sock, buffer, sizeof(struct iphdr),
	0, &saddr, &saddr_size);
	if (data_size < 0) {
		close(sock);
		munmap(stats, STATS_SIZE);
		exit(EXIT_FAILURE);
	}
	process_data(buffer, stats);
}

