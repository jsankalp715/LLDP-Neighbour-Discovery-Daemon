/*
 * ctl.c - local control socket for querying the daemon
 */
#include "ctl.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#define CTL_MAX_CLIENTS 8
#define CTL_MAX_CMD     64

struct ctl_client {
	int       fd;                  /* -1 = free slot */
	struct ev ev;
	char      in[CTL_MAX_CMD + 1];
	size_t    inlen;
	char     *out;                 /* reply, malloc'd by open_memstream */
	size_t    outlen, outoff;
	uint64_t  seq;                 /* accept order, for eviction */
};

struct ctl {
	int               lfd;
	struct ev         ev;
	int               epfd;
	char              path[sizeof(((struct sockaddr_un *)0)->sun_path)];
	ctl_fn            fn;
	void             *ctx;
	uint64_t          seq;
	struct ctl_client cl[CTL_MAX_CLIENTS];
};

static void client_close(struct ctl *c, struct ctl_client *k)
{
	if (k->fd < 0)
		return;
	epoll_ctl(c->epfd, EPOLL_CTL_DEL, k->fd, NULL);
	close(k->fd);
	free(k->out);
	memset(k, 0, sizeof *k);
	k->fd = -1;
}

/* Is something already accepting connections on path? */
static int socket_in_use(const struct sockaddr_un *sa)
{
	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	int live;

	if (fd < 0)
		return 0;
	live = connect(fd, (const struct sockaddr *)sa, sizeof *sa) == 0;
	close(fd);
	return live;
}

struct ctl *ctl_open(const char *path, int epfd, ctl_fn fn, void *ctx)
{
	struct sockaddr_un sa;
	struct epoll_event e;
	struct ctl *c;
	struct stat st;
	mode_t old;
	int i;

	if (strlen(path) >= sizeof sa.sun_path) {
		fprintf(stderr, "control socket path too long: %s\n", path);
		return NULL;
	}
	c = calloc(1, sizeof *c);
	if (!c)
		return NULL;
	c->lfd = -1;
	c->epfd = epfd;
	c->fn = fn;
	c->ctx = ctx;
	snprintf(c->path, sizeof c->path, "%s", path);
	for (i = 0; i < CTL_MAX_CLIENTS; i++)
		c->cl[i].fd = -1;

	memset(&sa, 0, sizeof sa);
	sa.sun_family = AF_UNIX;
	memcpy(sa.sun_path, path, strlen(path) + 1);

	/* replace only a stale socket, never a file or a live daemon's socket */
	if (lstat(path, &st) == 0) {
		if (!S_ISSOCK(st.st_mode)) {
			fprintf(stderr, "%s exists and is not a socket\n", path);
			goto fail;
		}
		if (socket_in_use(&sa)) {
			fprintf(stderr, "%s: another lldpnd is already running\n", path);
			goto fail;
		}
		unlink(path);
	}

	c->lfd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (c->lfd < 0)
		goto fail_errno;
	old = umask(0177);              /* created 0600: no window with wider mode */
	i = bind(c->lfd, (struct sockaddr *)&sa, sizeof sa);
	umask(old);
	if (i < 0 || listen(c->lfd, CTL_MAX_CLIENTS) < 0)
		goto fail_errno;

	c->ev.kind = EV_CTL;
	c->ev.obj = NULL;               /* NULL obj = the listener */
	e.events = EPOLLIN;
	e.data.ptr = &c->ev;
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, c->lfd, &e) < 0)
		goto fail_errno;
	return c;

fail_errno:
	fprintf(stderr, "control socket %s: %s\n", path, strerror(errno));
fail:
	if (c->lfd >= 0)
		close(c->lfd);
	free(c);
	return NULL;
}

static void accept_clients(struct ctl *c)
{
	for (;;) {
		struct ctl_client *k = NULL, *oldest = NULL;
		struct epoll_event e;
		int fd, i;

		fd = accept4(c->lfd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
		if (fd < 0)
			return;                    /* EAGAIN or a transient error */
		for (i = 0; i < CTL_MAX_CLIENTS; i++) {
			if (c->cl[i].fd < 0) {
				k = &c->cl[i];
				break;
			}
			if (!oldest || c->cl[i].seq < oldest->seq)
				oldest = &c->cl[i];
		}
		if (!k) {                          /* all busy: evict the oldest */
			client_close(c, oldest);
			k = oldest;
		}
		memset(k, 0, sizeof *k);
		k->fd = fd;
		k->seq = ++c->seq;
		k->ev.kind = EV_CTL;
		k->ev.obj = k;
		e.events = EPOLLIN;
		e.data.ptr = &k->ev;
		if (epoll_ctl(c->epfd, EPOLL_CTL_ADD, fd, &e) < 0) {
			close(fd);
			k->fd = -1;
		}
	}
}

/* A complete command has arrived: render the reply and switch to writing. */
static void client_respond(struct ctl *c, struct ctl_client *k)
{
	struct epoll_event e;
	char *nl;
	FILE *f;

	k->in[k->inlen] = '\0';
	nl = strpbrk(k->in, "\r\n");
	if (nl)
		*nl = '\0';
	f = open_memstream(&k->out, &k->outlen);
	if (!f) {
		client_close(c, k);
		return;
	}
	c->fn(k->in, f, c->ctx);
	if (fclose(f) != 0) {
		client_close(c, k);
		return;
	}
	k->outoff = 0;
	shutdown(k->fd, SHUT_RD);
	e.events = EPOLLOUT;
	e.data.ptr = &k->ev;
	if (epoll_ctl(c->epfd, EPOLL_CTL_MOD, k->fd, &e) < 0)
		client_close(c, k);
}

static void client_read(struct ctl *c, struct ctl_client *k)
{
	for (;;) {
		ssize_t n = read(k->fd, k->in + k->inlen, CTL_MAX_CMD - k->inlen);

		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
				return;
			client_close(c, k);
			return;
		}
		if (n == 0) {                      /* EOF: whatever we have is the command */
			client_respond(c, k);
			return;
		}
		k->inlen += (size_t)n;
		if (memchr(k->in, '\n', k->inlen) || k->inlen == CTL_MAX_CMD) {
			client_respond(c, k);
			return;
		}
	}
}

static void client_write(struct ctl *c, struct ctl_client *k)
{
	while (k->outoff < k->outlen) {
		ssize_t n = send(k->fd, k->out + k->outoff, k->outlen - k->outoff,
				 MSG_NOSIGNAL);
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
				return;                /* wait for EPOLLOUT again */
			break;
		}
		k->outoff += (size_t)n;
	}
	client_close(c, k);                        /* done (or peer went away) */
}

void ctl_event(struct ctl *c, struct ev *e, uint32_t events)
{
	struct ctl_client *k = e->obj;

	if (!c)
		return;
	if (!k) {
		accept_clients(c);
		return;
	}
	if (k->fd < 0)
		return;
	if (k->out) {
		if (events & (EPOLLOUT | EPOLLERR | EPOLLHUP))
			client_write(c, k);
		return;
	}
	if (events & (EPOLLIN | EPOLLHUP | EPOLLERR))
		client_read(c, k);
}

void ctl_close(struct ctl *c)
{
	int i;

	if (!c)
		return;
	for (i = 0; i < CTL_MAX_CLIENTS; i++)
		client_close(c, &c->cl[i]);
	epoll_ctl(c->epfd, EPOLL_CTL_DEL, c->lfd, NULL);
	close(c->lfd);
	unlink(c->path);   /* may fail after dropping privileges; next start cleans up */
	free(c);
}
