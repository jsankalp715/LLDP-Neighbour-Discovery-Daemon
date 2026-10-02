/*
 * main.c - lldpnd: LLDP (IEEE Std 802.1AB-2016) neighbour discovery daemon
 *
 * Single-threaded event loop on epoll(7). Every source of work is a file
 * descriptor, so the process sleeps in epoll_wait() until something happens:
 *
 *   raw socket   readable when an LLDP frame arrives        (9.2.9 rx)
 *   tx timerfd   periodic, msgTxInterval                    (9.2.8 tx)
 *   age timerfd  one-shot, armed for the earliest rxInfoTTL expiry
 *   print timerfd periodic neighbour table dump (optional)
 *   signalfd     SIGINT/SIGTERM -> shutdown LLDPDU, clean exit
 */
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include "lldpdu.h"
#include "neigh.h"
#include "rawsock.h"

/* 9.2.5 defaults: msgTxInterval = 30 s, msgTxHold = 4 */
#define DEFAULT_TX_INTERVAL  30
#define DEFAULT_TX_HOLD      4
#define DEFAULT_PRINT_SECS   0      /* 0 = print only on change */

/* Counters named after the 802.1AB statistics variables (9.2.6) */
struct stats {
	unsigned long frames_out;          /* statsFramesOutTotal */
	unsigned long frames_in;           /* statsFramesInTotal */
	unsigned long frames_discarded;    /* statsFramesDiscardedTotal */
	unsigned long frames_in_errors;    /* statsFramesInErrorsTotal */
	unsigned long tlvs_unrecognized;   /* statsTLVsUnrecognizedTotal */
	unsigned long ageouts;             /* statsAgeoutsTotal */
	unsigned long too_many_neighbors;  /* tooManyNeighbors events */
};

struct opts {
	const char *ifname;
	unsigned    tx_interval;
	unsigned    tx_hold;
	unsigned    print_secs;
	const char *sys_name;
	const char *sys_desc;
	const char *port_desc;
};

struct ctx {
	struct opts       o;
	struct lldp_sock  sock;
	struct lldp_local_info li;
	struct neigh_table table;
	struct stats      st;
	int               epfd, tx_tfd, age_tfd, print_tfd, sig_fd;
	char              hostname[256];
	char              sysdesc[4 * 65 + 4];   /* utsname: 4 fields of <= 65 */
	int               table_dirty;
};

static struct ctx C;   /* static: the neighbour table is ~50 KiB */

static uint64_t now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

__attribute__((format(printf, 1, 2)))
static void logmsg(const char *fmt, ...)
{
	char ts[32];
	struct timespec now;
	struct tm tm;
	va_list ap;

	clock_gettime(CLOCK_REALTIME, &now);
	localtime_r(&now.tv_sec, &tm);
	strftime(ts, sizeof ts, "%H:%M:%S", &tm);
	printf("%s.%03ld [%s] ", ts, now.tv_nsec / 1000000L, C.o.ifname);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	putchar('\n');
	fflush(stdout);
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s -i <interface> [options]\n"
		"  -i IF     interface to run LLDP on (required)\n"
		"  -t SECS   transmit interval, msgTxInterval (1-3600, default %d)\n"
		"  -H N      hold multiplier, msgTxHold (1-100, default %d);\n"
		"            advertised TTL = min(65535, SECS * N + 1)\n"
		"  -p SECS   print neighbour table every SECS (default: on change only)\n"
		"  -n NAME   System Name TLV (default: hostname)\n"
		"  -d DESC   System Description TLV (default: uname)\n"
		"  -P DESC   Port Description TLV (default: \"LLDP port <IF>\")\n"
		"  -h        this help\n",
		prog, DEFAULT_TX_INTERVAL, DEFAULT_TX_HOLD);
}

static int parse_uint(const char *s, unsigned lo, unsigned hi, unsigned *out)
{
	char *end;
	unsigned long v;

	errno = 0;
	v = strtoul(s, &end, 10);
	if (errno || end == s || *end != '\0' || v < lo || v > hi || s[0] == '-')
		return -1;
	*out = (unsigned)v;
	return 0;
}

static int parse_args(int argc, char **argv, struct opts *o)
{
	int c;

	o->tx_interval = DEFAULT_TX_INTERVAL;
	o->tx_hold = DEFAULT_TX_HOLD;
	o->print_secs = DEFAULT_PRINT_SECS;
	while ((c = getopt(argc, argv, "i:t:H:p:n:d:P:h")) != -1) {
		switch (c) {
		case 'i': o->ifname = optarg; break;
		case 't':
			if (parse_uint(optarg, 1, 3600, &o->tx_interval) < 0) {
				fprintf(stderr, "invalid -t %s (1-3600)\n", optarg);
				return -1;
			}
			break;
		case 'H':
			if (parse_uint(optarg, 1, 100, &o->tx_hold) < 0) {
				fprintf(stderr, "invalid -H %s (1-100)\n", optarg);
				return -1;
			}
			break;
		case 'p':
			if (parse_uint(optarg, 0, 86400, &o->print_secs) < 0) {
				fprintf(stderr, "invalid -p %s (0-86400)\n", optarg);
				return -1;
			}
			break;
		case 'n': o->sys_name = optarg; break;
		case 'd': o->sys_desc = optarg; break;
		case 'P': o->port_desc = optarg; break;
		case 'h': usage(argv[0]); exit(0);
		default:  return -1;
		}
	}
	if (optind != argc) {
		fprintf(stderr, "unexpected argument: %s\n", argv[optind]);
		return -1;
	}
	if (!o->ifname) {
		fprintf(stderr, "-i <interface> is required\n");
		return -1;
	}
	if ((o->sys_name && strlen(o->sys_name) > LLDP_STR_MAX_LEN) ||
	    (o->sys_desc && strlen(o->sys_desc) > LLDP_STR_MAX_LEN) ||
	    (o->port_desc && strlen(o->port_desc) > LLDP_STR_MAX_LEN)) {
		fprintf(stderr, "-n/-d/-P strings are limited to 255 octets (8.5.5-8.5.7)\n");
		return -1;
	}
	return 0;
}

/* Arm a timerfd: first expiry after first_ms, then every interval_ms (0 = once). */
static int timer_set_rel(int fd, uint64_t first_ms, uint64_t interval_ms)
{
	struct itimerspec its = {
		.it_value    = { (time_t)(first_ms / 1000), (long)(first_ms % 1000) * 1000000L },
		.it_interval = { (time_t)(interval_ms / 1000), (long)(interval_ms % 1000) * 1000000L },
	};
	if (first_ms == 0)
		its.it_value.tv_nsec = 1;          /* 0 would disarm: fire ASAP */
	return timerfd_settime(fd, 0, &its, NULL);
}

/* Re-arm the ageing timer for the earliest neighbour expiry, or disarm it. */
static void age_timer_rearm(void)
{
	struct itimerspec its;
	uint64_t when;

	memset(&its, 0, sizeof its);
	if (neigh_next_expiry(&C.table, &when)) {
		its.it_value.tv_sec = (time_t)(when / 1000);
		its.it_value.tv_nsec = (long)(when % 1000) * 1000000L;
		if (its.it_value.tv_sec == 0 && its.it_value.tv_nsec == 0)
			its.it_value.tv_nsec = 1;
	}
	if (timerfd_settime(C.age_tfd, TFD_TIMER_ABSTIME, &its, NULL) < 0)
		logmsg("timerfd_settime(age): %s", strerror(errno));
}

static void drain_timer(int fd)
{
	uint64_t expirations;
	ssize_t n = read(fd, &expirations, sizeof expirations);
	(void)n;   /* EAGAIN after a re-arm race is harmless */
}

static void transmit(uint16_t ttl)
{
	uint8_t frame[LLDP_FRAME_MAX];
	ssize_t n;

	C.li.ttl = ttl;
	n = lldp_frame_build(&C.li, frame, sizeof frame);
	if (n < 0) {
		logmsg("tx: failed to build frame");
		return;
	}
	if (lldp_sock_send(&C.sock, frame, (size_t)n) < 0) {
		logmsg("tx: send failed: %s", strerror(errno));
		return;
	}
	C.st.frames_out++;
}

static void log_neigh(const char *what, const struct neigh *n, const char *extra)
{
	char cid[LLDP_IDFMT_MAX], pid[LLDP_IDFMT_MAX], name[LLDP_ESC_MAX];

	lldp_id_format(&n->chassis, 1, cid, sizeof cid);
	lldp_id_format(&n->port, 0, pid, sizeof pid);
	if (n->sys_name.present)
		lldp_escape(n->sys_name.s, n->sys_name.len, name, sizeof name);
	else
		snprintf(name, sizeof name, "-");
	logmsg("NEIGHBOUR %s chassis=%s port=%s name=%s ttl=%u%s",
	       what, cid, pid, name, n->ttl, extra);
}

static void handle_frame(const uint8_t *buf, size_t len, int truncated)
{
	static struct lldp_msg msg;     /* ~1.3 KiB, reused */
	struct eth_view v;
	const struct neigh *n;
	char src[18];
	int rc;

	C.st.frames_in++;
	if (truncated || eth_frame_parse(buf, len, &v) < 0) {
		C.st.frames_discarded++;
		C.st.frames_in_errors++;
		logmsg("rx: discard: %s", truncated ? "oversized frame" : "runt frame");
		return;
	}
	eth_ntoa(v.src, src);
	/* belt and braces: the socket is bound to 0x88CC, verify anyway (7.2) */
	if (v.ethertype != ETHERTYPE_LLDP ||
	    memcmp(v.dst, LLDP_MCAST_NEAREST_BRIDGE, ETH_ADDR_LEN) != 0) {
		C.st.frames_discarded++;
		logmsg("rx: discard from %s: not LLDP / wrong destination", src);
		return;
	}
	/* our own frame looped back, e.g. by a hairpinning bridge */
	if (memcmp(v.src, C.sock.mac, ETH_ADDR_LEN) == 0)
		return;

	rc = lldpdu_parse(v.payload, v.payload_len, &msg);
	if (rc != LLDP_OK) {
		/* 9.2.7 (rxProcessFrame): invalid LLDPDUs are discarded */
		C.st.frames_discarded++;
		C.st.frames_in_errors++;
		logmsg("rx: discard from %s: %s", src, lldp_strerror(rc));
		return;
	}
	C.st.tlvs_unrecognized += msg.n_unknown_tlvs;

	switch (neigh_update(&C.table, &msg, v.src, now_ms(), &n)) {
	case NEIGH_ADDED:
		log_neigh("ADD", n, "");
		C.table_dirty = 1;
		break;
	case NEIGH_UPDATED:
		log_neigh("UPDATE", n, "");
		C.table_dirty = 1;
		break;
	case NEIGH_REFRESHED:
		break;
	case NEIGH_DELETED:
		log_neigh("DELETE", n, " (shutdown LLDPDU)");
		C.table_dirty = 1;
		break;
	case NEIGH_IGNORED:
		break;
	case NEIGH_FULL:
		C.st.too_many_neighbors++;
		C.st.frames_discarded++;
		logmsg("rx: neighbour table full (%d), dropping new neighbour from %s",
		       NEIGH_MAX, src);
		break;
	}
	age_timer_rearm();
}

static void handle_rx(void)
{
	uint8_t buf[LLDP_FRAME_MAX];
	int truncated, outgoing, budget = 64;
	ssize_t n;

	/* drain the socket, but bound the work per wakeup to stay fair */
	while (budget-- > 0) {
		n = lldp_sock_recv(&C.sock, buf, sizeof buf, &truncated, &outgoing);
		if (n == 0)
			return;
		if (n < 0) {
			logmsg("rx: recv: %s", strerror(errno));
			return;
		}
		if (outgoing)
			continue;          /* our own transmissions */
		handle_frame(buf, (size_t)n, truncated);
	}
}

static void ageout_cb(const struct neigh *n, void *ctx)
{
	uint64_t now = *(const uint64_t *)ctx;
	char extra[64];

	C.st.ageouts++;
	/* monotonic, so immune to wall-clock steps; should be ~TTL * 1000 */
	snprintf(extra, sizeof extra, " (TTL expired, last rx %llu ms ago)",
		 (unsigned long long)(now - n->last_seen_ms));
	log_neigh("AGEOUT", n, extra);
}

static void print_table(void)
{
	neigh_print(&C.table, now_ms(), stdout);
	C.table_dirty = 0;
}

static void print_stats(void)
{
	logmsg("stats: out=%lu in=%lu discarded=%lu in_errors=%lu "
	       "tlvs_unrecognized=%lu ageouts=%lu too_many_neighbors=%lu",
	       C.st.frames_out, C.st.frames_in, C.st.frames_discarded,
	       C.st.frames_in_errors, C.st.tlvs_unrecognized, C.st.ageouts,
	       C.st.too_many_neighbors);
}

static int add_fd(int fd)
{
	struct epoll_event ev = { .events = EPOLLIN, .data.fd = fd };
	return epoll_ctl(C.epfd, EPOLL_CTL_ADD, fd, &ev);
}

static void close_all(void)
{
	int *fds[] = { &C.tx_tfd, &C.age_tfd, &C.print_tfd, &C.sig_fd, &C.epfd };
	size_t i;

	for (i = 0; i < sizeof fds / sizeof fds[0]; i++)
		if (*fds[i] >= 0) {
			close(*fds[i]);
			*fds[i] = -1;
		}
	lldp_sock_close(&C.sock);
}

static void init_local_info(void)
{
	struct utsname u;
	static char portdesc[64];
	unsigned long ttl;

	if (!C.o.sys_name) {
		if (gethostname(C.hostname, sizeof C.hostname - 1) < 0)
			snprintf(C.hostname, sizeof C.hostname, "unknown");
		C.hostname[sizeof C.hostname - 1] = '\0';
		C.o.sys_name = C.hostname;
	}
	if (!C.o.sys_desc) {
		if (uname(&u) == 0)
			snprintf(C.sysdesc, sizeof C.sysdesc, "%s %s %s %s",
				 u.sysname, u.release, u.version, u.machine);
		else
			snprintf(C.sysdesc, sizeof C.sysdesc, "Linux");
		C.sysdesc[LLDP_STR_MAX_LEN] = '\0';   /* 8.5.7: at most 255 octets */
		C.o.sys_desc = C.sysdesc;
	}
	if (!C.o.port_desc) {
		snprintf(portdesc, sizeof portdesc, "LLDP port %s", C.o.ifname);
		C.o.port_desc = portdesc;
	}

	memcpy(C.li.mac, C.sock.mac, ETH_ADDR_LEN);
	C.li.ifname = C.sock.ifname;
	C.li.sys_name = C.o.sys_name;
	C.li.sys_desc = C.o.sys_desc;
	C.li.port_desc = C.o.port_desc;
	/* 9.2.5: txTTL = min(65535, (msgTxInterval * msgTxHold) + 1) */
	ttl = (unsigned long)C.o.tx_interval * C.o.tx_hold + 1;
	C.li.ttl = (uint16_t)(ttl > 65535 ? 65535 : ttl);
}

int main(int argc, char **argv)
{
	struct epoll_event evs[8];
	sigset_t mask;
	char mac[18];
	int running = 1, i, n, rc = 1;

	setvbuf(stdout, NULL, _IOLBF, 0);
	C.epfd = C.tx_tfd = C.age_tfd = C.print_tfd = C.sig_fd = -1;
	C.sock.fd = -1;

	if (parse_args(argc, argv, &C.o) < 0) {
		usage(argv[0]);
		return 2;
	}
	neigh_init(&C.table);

	if (lldp_sock_open(&C.sock, C.o.ifname) < 0)
		goto out;
	init_local_info();

	/* signals become readable events; nothing runs in signal context */
	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
		perror("sigprocmask");
		goto out;
	}
	C.sig_fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
	C.epfd = epoll_create1(EPOLL_CLOEXEC);
	C.tx_tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	C.age_tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	C.print_tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	if (C.sig_fd < 0 || C.epfd < 0 || C.tx_tfd < 0 || C.age_tfd < 0 || C.print_tfd < 0) {
		perror("signalfd/epoll/timerfd");
		goto out;
	}
	if (add_fd(C.sock.fd) < 0 || add_fd(C.tx_tfd) < 0 || add_fd(C.age_tfd) < 0 ||
	    add_fd(C.print_tfd) < 0 || add_fd(C.sig_fd) < 0) {
		perror("epoll_ctl");
		goto out;
	}

	/* first LLDPDU immediately, then every msgTxInterval (9.2.8) */
	if (timer_set_rel(C.tx_tfd, 0, (uint64_t)C.o.tx_interval * 1000u) < 0 ||
	    (C.o.print_secs &&
	     timer_set_rel(C.print_tfd, (uint64_t)C.o.print_secs * 1000u,
			   (uint64_t)C.o.print_secs * 1000u) < 0)) {
		perror("timerfd_settime");
		goto out;
	}

	eth_ntoa(C.sock.mac, mac);
	logmsg("lldpnd started: ifindex=%d chassis=%s port=%s tx-interval=%us ttl=%us",
	       C.sock.ifindex, mac, C.sock.ifname, C.o.tx_interval, C.li.ttl);

	while (running) {
		n = epoll_wait(C.epfd, evs, (int)(sizeof evs / sizeof evs[0]), -1);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			perror("epoll_wait");
			goto out;
		}
		for (i = 0; i < n; i++) {
			int fd = evs[i].data.fd;

			if (fd == C.sock.fd) {
				handle_rx();
			} else if (fd == C.tx_tfd) {
				drain_timer(fd);
				transmit(C.li.ttl);
			} else if (fd == C.age_tfd) {
				uint64_t now = now_ms();
				drain_timer(fd);
				if (neigh_age(&C.table, now, ageout_cb, &now))
					C.table_dirty = 1;
				age_timer_rearm();
			} else if (fd == C.print_tfd) {
				drain_timer(fd);
				print_table();
			} else if (fd == C.sig_fd) {
				struct signalfd_siginfo si;
				if (read(fd, &si, sizeof si) == (ssize_t)sizeof si) {
					logmsg("caught signal %u, shutting down", si.ssi_signo);
					running = 0;
				}
			}
		}
		/* with no -p, print whenever the table changed */
		if (C.table_dirty && C.o.print_secs == 0)
			print_table();
	}

	/*
	 * 9.2.7 (mkShutdownLLDPDU): announce shutdown with TTL 0 so that
	 * neighbours delete our information at once instead of waiting
	 * for it to age out.
	 */
	transmit(0);
	logmsg("sent shutdown LLDPDU (TTL 0)");
	print_table();
	print_stats();
	rc = 0;
out:
	close_all();
	return rc;
}
