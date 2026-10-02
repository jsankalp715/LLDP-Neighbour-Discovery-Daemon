/*
 * lldpnd_ctl.c - lldpnd-ctl: query a running lldpnd over its control socket
 *
 *   lldpnd-ctl [-S path] [show|json|stats|local|help]
 */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#include "ctl.h"

static void usage(const char *prog)
{
	fprintf(stderr, "usage: %s [-S socket] [show|json|stats|local|help]\n"
		"  default socket: %s\n", prog, CTL_DEFAULT_PATH);
}

int main(int argc, char **argv)
{
	const char *path = CTL_DEFAULT_PATH, *cmd = "show";
	struct sockaddr_un sa;
	struct timeval tv = { 5, 0 };
	char buf[8192], line[80];
	ssize_t n;
	int c, fd;

	while ((c = getopt(argc, argv, "S:h")) != -1) {
		switch (c) {
		case 'S': path = optarg; break;
		case 'h': usage(argv[0]); return 0;
		default:  usage(argv[0]); return 2;
		}
	}
	if (optind < argc)
		cmd = argv[optind++];
	if (optind != argc || strlen(cmd) > 60) {
		usage(argv[0]);
		return 2;
	}
	if (strlen(path) >= sizeof sa.sun_path) {
		fprintf(stderr, "socket path too long\n");
		return 2;
	}

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		perror("socket");
		return 1;
	}
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
	memset(&sa, 0, sizeof sa);
	sa.sun_family = AF_UNIX;
	memcpy(sa.sun_path, path, strlen(path) + 1);
	if (connect(fd, (struct sockaddr *)&sa, sizeof sa) < 0) {
		fprintf(stderr, "cannot connect to lldpnd at %s: %s\n", path, strerror(errno));
		close(fd);
		return 1;
	}
	snprintf(line, sizeof line, "%s\n", cmd);
	if (send(fd, line, strlen(line), MSG_NOSIGNAL) < 0) {
		perror("send");
		close(fd);
		return 1;
	}
	while ((n = read(fd, buf, sizeof buf)) > 0)
		if (fwrite(buf, 1, (size_t)n, stdout) != (size_t)n)
			break;
	close(fd);
	if (n < 0) {
		perror("read");
		return 1;
	}
	return 0;
}
