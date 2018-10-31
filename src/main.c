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
		return (pid);
	umask(0);
	sid = setsid();
	if (sid < 0)
		error("ERROR on sid");
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
	sniffd();
	exit(EXIT_SUCCESS);
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


void	print_help(void) {
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

char	parse_request(int argc, char **argv) {
	if (argc == 1) {
		return (0);
	} else if (argc == 2 && !strcmp(argv[1], "start")) {
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
	return (-1);
}

int		create_unix_socket(struct sockaddr_un *addr) {
	int		fd;

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		error("ERROR on AF_UNIX socket");
	memset(addr, 0, sizeof(*addr));
	addr->sun_family = AF_UNIX;
	strncpy(addr->sun_path, UN_SOCKET_PATH, strlen(UN_SOCKET_PATH));
	return (fd);
}

int		connect_daemon(void) {
	struct sockaddr_un	addr;
	int					sock;

	sock = create_unix_socket(&addr);
	if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1)
		error("ERROR on AF_UNIX connect");
	return (sock);
}

int		send_request(int sock, char **argv, char op) {
	char				buf[UN_BUFF_SIZE];

	if (op == -1) {
		fprintf(stderr, "try \'%s --help\' for more information\n", argv[0]);
		exit(EXIT_FAILURE);
	} else if (op == OP_HELP) {
		print_help();
		exit(EXIT_SUCCESS);
	}
	bzero(buf, UN_BUFF_SIZE);
	buf[0] = op;
	if (op == OP_SELECT_IFACE) {
		strncpy(&buf[1], argv[3], UN_BUFF_SIZE);
	} else if (op == OP_STAT_IFACE) {
		strncpy(&buf[1], argv[2], UN_BUFF_SIZE);
	} else if (op == OP_SHOW_IP_COUNT) {
		strncpy(&buf[1], argv[2], UN_BUFF_SIZE);
	}
	write(sock, buf, UN_BUFF_SIZE);
	return (sock);
}

void	recv_res(int sock) {
	char	buf[128];
	int		rd;

	while ((rd = read(sock, buf, 128)) > 0)
		write(STDOUT_FILENO, buf, rd);
	if (rd < 0)
		error("ERROR on recv");
	close(sock);
}

int		main(int argc, char **argv) {
	pid_t	daemon;
	char	*conf;
	int		op, sock;

	if (getuid() != 0) {
		fprintf(stderr, "Please, use root access (sudo)!\n\
It is necessary because of using of raw sockets\n");
		return (EXIT_FAILURE);
	}
	signal(SIGCHLD, SIG_IGN);
	conf = (char *)access_mmap("conf.bin", CONF_SIZE);	// access config
	memcpy(&daemon, conf, 4); // get daemon pid
	if (!daemon || kill(daemon, 0) == -1) {
		daemon = init_daemon();
		memcpy(conf, &daemon, 4); // set daemon pid
		sleep(1); // giving time to establish daemon
	}
	sock = connect_daemon();
	op = parse_request(argc, argv);
	send_request(sock, argv, op);
	recv_res(sock);
	munmap(conf, CONF_SIZE);
	return (EXIT_SUCCESS);
}

