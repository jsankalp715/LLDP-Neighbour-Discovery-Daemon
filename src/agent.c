/*
 * agent.c - the LLDP agent: ports, local information, event loop
 *           (IEEE Std 802.1AB-2016, clause 9)
 *
 * Everything is a file descriptor in one epoll set, so the process sleeps
 * until there is work:
 *
 *   per port   raw socket   LLDPDU received                  (9.2.9 rx)
 *              tx timerfd   one-shot at txs_deadline()       (9.2.8, 9.2.10)
 *              age timerfd  one-shot at the earliest rxInfoTTL expiry
 *   global     signalfd     SIGINT/SIGTERM -> shutdown LLDPDUs, exit
 *              netlink      link/address changes  -> portEnabled,
 *                           somethingChangedLocal
 *              hostname     /proc/sys/kernel/hostname poll -> System Name
 *              print timer  optional periodic table dump
 *              control socket + clients (ctl.c)
 *
 * Local changes are detected by rebuilding a port's LLDPDU and comparing it
 * byte-for-byte with the one last built: any difference is
 * somethingChangedLocal and schedules an immediate (credit-limited) frame.
 */
#include "agent.h"

#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

#include "ctl.h"
#include "localinfo.h"
#include "netmon.h"
#include "privdrop.h"
#include "report.h"

const char *agent_admin_name(enum admin_status a)
{
	switch (a) {
	case ADMIN_TX_ONLY: return "tx";
	case ADMIN_RX_ONLY: return "rx";
	case ADMIN_RXTX:    break;
	}
	return "rxtx";
}

const uint8_t *agent_group(const struct agent *ag)
{
	return ag->cfg.group ? ag->cfg.group : LLDP_MCAST_NEAREST_BRIDGE;
}

/* adminStatus (9.2.5.1) gates each direction */
static int tx_enabled(const struct agent *ag) { return ag->cfg.admin != ADMIN_RX_ONLY; }
static int rx_enabled(const struct agent *ag) { return ag->cfg.admin != ADMIN_TX_ONLY; }

uint64_t agent_now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

__attribute__((format(printf, 2, 3)))
static void logmsg(const char *tag, const char *fmt, ...)
{
	char ts[32];
	struct timespec now;
	struct tm tm;
	va_list ap;

	clock_gettime(CLOCK_REALTIME, &now);
	localtime_r(&now.tv_sec, &tm);
	strftime(ts, sizeof ts, "%H:%M:%S", &tm);
	printf("%s.%03ld [%s] ", ts, now.tv_nsec / 1000000L, tag ? tag : "-");
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	putchar('\n');
	fflush(stdout);
}

/* ---------------------------------------------------------------- timers */

/* Arm fd for absolute monotonic time when_ms; 0 disarms. */
static void timer_at(int fd, uint64_t when_ms)
{
	struct itimerspec its;

	memset(&its, 0, sizeof its);
	if (when_ms) {
		its.it_value.tv_sec = (time_t)(when_ms / 1000u);
		its.it_value.tv_nsec = (long)(when_ms % 1000u) * 1000000L;
	}
	timerfd_settime(fd, TFD_TIMER_ABSTIME, &its, NULL);
}

static void drain(int fd)
{
	uint64_t v;
	ssize_t n = read(fd, &v, sizeof v);
	(void)n;   /* EAGAIN after a re-arm is harmless */
}

static void port_arm_tx(struct port *p, uint64_t now)
{
	if (p->sock.fd >= 0 && p->oper_up && tx_enabled(p->ag))
		timer_at(p->tx_tfd, txs_deadline(&p->txs, now));
	else
		timer_at(p->tx_tfd, 0);
}

static void port_arm_age(struct port *p)
{
	uint64_t when;

	if (neigh_next_expiry(&p->table, &when))
		timer_at(p->age_tfd, when ? when : 1);
	else
		timer_at(p->age_tfd, 0);
}

static int ep_add(struct agent *ag, int fd, uint32_t events, struct ev *ev)
{
	struct epoll_event e = { .events = events, .data.ptr = ev };
	return epoll_ctl(ag->epfd, EPOLL_CTL_ADD, fd, &e);
}

/* ------------------------------------------------------- local information */

void agent_local_info(const struct agent *ag, const struct port *p,
		      struct lldp_local_info *li, char *portdesc, size_t pdcap)
{
	memset(li, 0, sizeof *li);
	memcpy(li->chassis_mac, ag->chassis_mac, ETH_ADDR_LEN);
	memcpy(li->port_mac, p->mac, ETH_ADDR_LEN);
	li->ifname = p->name;
	li->ttl = ag->ttl;
	li->dst = agent_group(ag);
	/* 802.3 Maximum Frame Size: MTU + Ethernet header (14) + FCS (4) */
	if (p->mtu)
		li->mfs = (uint16_t)(p->mtu + 18 > 65535 ? 65535 : p->mtu + 18);

	/* 8.5.5: Port Description = ifAlias by default, like ifDescr/ifAlias in IF-MIB */
	if (ag->cfg.port_desc)
		li->port_desc = ag->cfg.port_desc;
	else if (p->alias[0] && pdcap) {
		snprintf(portdesc, pdcap, "%s", p->alias);
		li->port_desc = portdesc;
	} else
		li->port_desc = p->name;
	li->sys_name = ag->cfg.sys_name ? ag->cfg.sys_name : ag->hostname;
	li->sys_desc = ag->cfg.sys_desc ? ag->cfg.sys_desc : ag->sysdesc;
	li->has_sys_cap = 1;
	li->sys_cap = ag->caps;
	li->sys_cap_enabled = ag->caps_enabled;

	if (!ag->cfg.no_mgmt && p->ifindex > 0) {
		struct ifaddrs *ifa = NULL;
		if (getifaddrs(&ifa) == 0) {
			li->n_mgmt = localinfo_mgmt(ifa, p->name, (unsigned)p->ifindex,
						    p->mac, li->mgmt, LLDP_MAX_MGMT);
			freeifaddrs(ifa);
		}
	}
}

/* Refresh system-wide information; returns 1 if anything changed. */
static int refresh_system(struct agent *ag)
{
	char host[sizeof ag->hostname];
	uint16_t caps, en;
	int changed = 0;

	if (!ag->cfg.sys_name) {
		localinfo_hostname(host, sizeof host);
		if (strcmp(host, ag->hostname) != 0) {
			if (ag->hostname[0])
				logmsg(NULL, "system name changed: %s -> %s", ag->hostname, host);
			memcpy(ag->hostname, host, sizeof host);
			changed = 1;
		}
	}
	localinfo_caps(localinfo_forwarding(), &caps, &en);
	if (caps != ag->caps || en != ag->caps_enabled) {
		ag->caps = caps;
		ag->caps_enabled = en;
		changed = 1;
	}
	return changed;
}

/*
 * Rebuild the port's information LLDPDU. If it differs from the previous
 * one this is somethingChangedLocal (9.2.5): transmit as soon as allowed.
 */
static void port_rebuild(struct port *p, const char *why)
{
	struct agent *ag = p->ag;
	struct lldp_local_info li;
	uint8_t frame[LLDP_FRAME_MAX];
	char pd[sizeof p->alias];
	ssize_t n;
	int first;

	if (p->ifindex == 0)
		return;
	agent_local_info(ag, p, &li, pd, sizeof pd);
	n = lldp_frame_build(&li, frame, sizeof frame);
	if (n < 0) {
		logmsg(p->name, "cannot build LLDPDU (information too large?)");
		return;
	}
	if ((size_t)n == p->frame_len && memcmp(frame, p->frame, (size_t)n) == 0)
		return;
	first = p->frame_len == 0;
	memcpy(p->frame, frame, (size_t)n);
	p->frame_len = (size_t)n;
	/*
	 * Only a change to information already advertised counts; before the
	 * first frame since link up (e.g. IPv6 link-local appearing right
	 * after it) the pending frame simply goes out with the new content.
	 */
	if (!first && p->oper_up && p->txs.sent > 0) {
		p->st.local_changes++;
		logmsg(p->name, "local information changed (%s): transmitting", why);
		txs_trigger(&p->txs);
		port_arm_tx(p, agent_now_ms());
	}
}

static void rebuild_all(struct agent *ag, const char *why)
{
	unsigned i;

	for (i = 0; i < ag->nports; i++)
		port_rebuild(ag->ports[i], why);
}

/* ------------------------------------------------------------ logging */

static void log_neigh(const struct port *p, const char *what, const struct neigh *n,
		      const char *extra)
{
	char cid[LLDP_IDFMT_MAX], pid[LLDP_IDFMT_MAX], name[LLDP_ESC_MAX];

	lldp_id_format(&n->chassis, 1, cid, sizeof cid);
	lldp_id_format(&n->port, 0, pid, sizeof pid);
	if (n->sys_name.present)
		lldp_escape(n->sys_name.s, n->sys_name.len, name, sizeof name);
	else
		snprintf(name, sizeof name, "-");
	logmsg(p->name, "NEIGHBOUR %s chassis=%s port=%s name=%s ttl=%u%s",
	       what, cid, pid, name, n->ttl, extra);
}

static void ageout_cb(const struct neigh *n, void *ctx)
{
	struct port *p = ctx;
	char extra[64];

	p->st.ageouts++;
	/* monotonic, so immune to wall-clock steps; should be ~TTL * 1000 */
	snprintf(extra, sizeof extra, " (TTL expired, last rx %llu ms ago)",
		 (unsigned long long)(agent_now_ms() - n->last_seen_ms));
	log_neigh(p, "AGEOUT", n, extra);
}

static void flush_cb(const struct neigh *n, void *ctx)
{
	log_neigh(ctx, "FLUSH", n, " (port not operational)");
}

static void print_port(struct port *p)
{
	neigh_print(&p->table, p->name, agent_now_ms(), stdout);
	p->dirty = 0;
}

/* ------------------------------------------------------------ port state */

static struct port *port_by_index(struct agent *ag, int ifindex)
{
	unsigned i;

	for (i = 0; i < ag->nports; i++)
		if (ag->ports[i]->ifindex == ifindex && ifindex > 0)
			return ag->ports[i];
	return NULL;
}

static struct port *port_by_name(struct agent *ag, const char *name)
{
	unsigned i;

	for (i = 0; i < ag->nports; i++)
		if (strcmp(ag->ports[i]->name, name) == 0)
			return ag->ports[i];
	return NULL;
}

/*
 * portEnabled (9.2.5) follows the interface's operational state. Going down
 * re-initialises the receive side, which deletes the port's remote
 * information (rxInitializeLLDP, 9.2.7). Coming up re-initialises transmit
 * (txInitializeLLDP, 9.2.7.12): full credit and a fast start, but no sooner
 * than reinitDelay (9.2.5.10) after it went down.
 */
static void port_set_oper(struct port *p, int up)
{
	struct agent *ag = p->ag;
	uint64_t now = agent_now_ms();

	if (!!up == p->oper_up)
		return;
	p->oper_up = !!up;
	if (up) {
		txs_init(&p->txs, ag->cfg.tx_interval * 1000u, TXS_DEFAULT_FAST_MS,
			 ag->cfg.fast_init, ag->cfg.credit_max, now);
		if (p->down_ms && now < p->down_ms + AGENT_REINIT_DELAY_MS)
			p->txs.next_ms = p->down_ms + AGENT_REINIT_DELAY_MS;
		logmsg(p->name, "link up");
		port_rebuild(p, "link up");
		port_arm_tx(p, now);
	} else {
		unsigned n;

		p->down_ms = now;
		logmsg(p->name, "link down");
		n = neigh_flush(&p->table, flush_cb, p);
		if (n)
			p->dirty = 1;
		port_arm_tx(p, now);
		port_arm_age(p);
	}
}

static int port_attach(struct port *p)
{
	struct agent *ag = p->ag;
	char mac[18];

	if (lldp_sock_open(&p->sock, p->name, agent_group(ag)) < 0)
		return -1;
	p->ifindex = p->sock.ifindex;
	memcpy(p->mac, p->sock.mac, ETH_ADDR_LEN);
	p->ev_sock.kind = EV_SOCK;
	p->ev_sock.obj = p;
	if (ep_add(ag, p->sock.fd, EPOLLIN, &p->ev_sock) < 0) {
		lldp_sock_close(&p->sock);
		p->ifindex = 0;
		return -1;
	}
	p->frame_len = 0;
	p->loop_warned = 0;
	eth_ntoa(p->mac, mac);
	logmsg(p->name, "attached: ifindex=%d mac=%s", p->ifindex, mac);
	return 0;
}

static void port_detach(struct port *p, const char *why)
{
	if (p->ifindex == 0)
		return;
	port_set_oper(p, 0);
	logmsg(p->name, "detached: %s", why);
	if (p->sock.fd >= 0)
		epoll_ctl(p->ag->epfd, EPOLL_CTL_DEL, p->sock.fd, NULL);
	lldp_sock_close(&p->sock);
	p->ifindex = 0;
	p->frame_len = 0;
}

/* ----------------------------------------------------------------- receive */

static void port_handle_frame(struct port *p, const uint8_t *buf, size_t len, int truncated)
{
	static struct lldp_msg msg;     /* ~1.5 KiB, reused */
	struct agent *ag = p->ag;
	struct eth_view v;
	const struct neigh *n;
	char src[18];
	int rc;

	p->st.frames_in++;
	if (truncated || eth_frame_parse(buf, len, &v) < 0) {
		p->st.frames_discarded++;
		p->st.frames_in_errors++;
		logmsg(p->name, "rx: discard: %s", truncated ? "oversized frame" : "runt frame");
		return;
	}
	eth_ntoa(v.src, src);
	/* belt and braces: the socket is bound to 0x88CC, verify anyway (7.2) */
	if (v.ethertype != ETHERTYPE_LLDP ||
	    memcmp(v.dst, agent_group(ag), ETH_ADDR_LEN) != 0) {
		/* another group address belongs to another agent (7.1) */
		p->st.frames_discarded++;
		logmsg(p->name, "rx: discard from %s: not LLDP / wrong destination", src);
		return;
	}
	/* our own frame reflected straight back (e.g. a hairpinning bridge) */
	if (memcmp(v.src, p->mac, ETH_ADDR_LEN) == 0)
		return;

	rc = lldpdu_parse(v.payload, v.payload_len, &msg);
	if (rc != LLDP_OK) {
		/* 9.2.7 rxProcessFrame(): invalid LLDPDUs are discarded */
		p->st.frames_discarded++;
		p->st.frames_in_errors++;
		logmsg(p->name, "rx: discard from %s: %s", src, lldp_strerror(rc));
		return;
	}
	p->st.tlvs_unrecognized += msg.n_unknown_tlvs;

	/*
	 * Our own chassis ID on a port means another of our ports is
	 * bridged to this one (or a loop). Don't record ourselves as a
	 * neighbour; warn once per attachment.
	 */
	if (msg.chassis.subtype == LLDP_CHASSIS_MAC && msg.chassis.len == ETH_ADDR_LEN &&
	    memcmp(msg.chassis.id, ag->chassis_mac, ETH_ADDR_LEN) == 0) {
		p->st.own_frames++;
		if (!p->loop_warned) {
			char pid[LLDP_IDFMT_MAX];
			lldp_id_format(&msg.port, 0, pid, sizeof pid);
			logmsg(p->name, "LOOP: received our own LLDPDU (sent on port %s, src %s); "
			       "this port and that one share a segment", pid, src);
			p->loop_warned = 1;
		}
		return;
	}

	switch (neigh_update(&p->table, &msg, v.src, agent_now_ms(), &n)) {
	case NEIGH_ADDED:
		log_neigh(p, "ADD", n, "");
		p->dirty = 1;
		/* 9.2.10: newNeighbor -> fast transmission so it learns us quickly */
		txs_new_neighbour(&p->txs);
		port_arm_tx(p, agent_now_ms());
		break;
	case NEIGH_UPDATED:
		log_neigh(p, "UPDATE", n, "");
		p->dirty = 1;
		break;
	case NEIGH_REFRESHED:
	case NEIGH_IGNORED:
		break;
	case NEIGH_DELETED:
		log_neigh(p, "DELETE", n, " (shutdown LLDPDU)");
		p->dirty = 1;
		break;
	case NEIGH_FULL:
		p->st.too_many_neighbors++;
		p->st.frames_discarded++;
		logmsg(p->name, "rx: neighbour table full (%d), dropping new neighbour from %s",
		       NEIGH_MAX, src);
		break;
	}
	port_arm_age(p);
}

static void port_rx(struct port *p)
{
	uint8_t buf[LLDP_FRAME_MAX];
	int truncated, outgoing, budget = 64;
	ssize_t n;

	/* drain the socket, but bound the work per wakeup to stay fair */
	while (budget-- > 0 && p->sock.fd >= 0) {
		n = lldp_sock_recv(&p->sock, buf, sizeof buf, &truncated, &outgoing);
		if (n == 0)
			return;
		if (n < 0) {
			logmsg(p->name, "rx: recv: %s", strerror(errno));
			return;
		}
		if (outgoing)
			continue;          /* our own transmissions */
		/*
		 * 9.2.9: nothing is received until portEnabled, nor when
		 * adminStatus is enabledTxOnly (drain and drop)
		 */
		if (!p->oper_up || !rx_enabled(p->ag))
			continue;
		port_handle_frame(p, buf, (size_t)n, truncated);
	}
}

/* ---------------------------------------------------------------- transmit */

static void port_send(struct port *p, const uint8_t *frame, size_t len)
{
	if (lldp_sock_send(&p->sock, frame, len) < 0) {
		logmsg(p->name, "tx: send failed: %s", strerror(errno));
		return;
	}
	p->st.frames_out++;
}

static void port_tx_timer(struct port *p)
{
	struct agent *ag = p->ag;
	uint64_t now = agent_now_ms();

	if (p->sock.fd < 0 || !p->oper_up || !tx_enabled(ag))
		return;
	/* cheap re-check of local information (catches sysctl changes too) */
	if (refresh_system(ag))
		rebuild_all(ag, "system information");
	else
		port_rebuild(p, "periodic check");
	if (p->frame_len && txs_poll(&p->txs, now))
		port_send(p, p->frame, p->frame_len);
	port_arm_tx(p, now);
}

static void send_shutdown(struct port *p)
{
	struct lldp_local_info li;
	uint8_t frame[LLDP_FRAME_MAX];
	char pd[sizeof p->alias];
	ssize_t n;

	/* an rx-only agent never transmitted, so it has nothing to withdraw */
	if (p->sock.fd < 0 || !p->oper_up || !tx_enabled(p->ag))
		return;
	agent_local_info(p->ag, p, &li, pd, sizeof pd);
	li.ttl = 0;                     /* 9.2.7 mibConstrShutdownLLDPDU() */
	n = lldp_frame_build(&li, frame, sizeof frame);
	if (n > 0) {
		port_send(p, frame, (size_t)n);
		logmsg(p->name, "sent shutdown LLDPDU (TTL 0)");
	}
}

/* ------------------------------------------------------------------ netlink */

static int is_oper_up(unsigned flags)
{
	return (flags & IFF_UP) && (flags & IFF_RUNNING);
}

static void on_netmon(const struct nm_event *ev, void *ctx)
{
	struct agent *ag = ctx;
	struct port *p;

	switch (ev->type) {
	case NM_RESYNC:
		logmsg(NULL, "netlink overrun: resynchronising link state");
		netmon_dump_links(on_netmon, ag);
		return;
	case NM_DELLINK:
		p = port_by_index(ag, ev->ifindex);
		if (p)
			port_detach(p, "interface removed");
		return;
	case NM_ADDR:
		return;   /* addresses are re-read by the rebuild after the batch */
	case NM_LINK:
		break;
	}

	/* chassis ID follows the MAC of the chassis interface */
	if (ev->has_mac && ev->ifname[0] && strcmp(ev->ifname, ag->cfg.chassis_if) == 0 &&
	    memcmp(ev->mac, ag->chassis_mac, ETH_ADDR_LEN) != 0) {
		char mac[18];
		memcpy(ag->chassis_mac, ev->mac, ETH_ADDR_LEN);
		eth_ntoa(ev->mac, mac);
		logmsg(NULL, "chassis ID changed to %s", mac);
	}

	p = port_by_index(ag, ev->ifindex);
	if (p && ev->ifname[0] && strcmp(ev->ifname, p->name) != 0) {
		/* renamed away from the configured name: no longer this port */
		port_detach(p, "interface renamed");
		p = NULL;
	}
	if (!p && ev->ifname[0]) {
		p = port_by_name(ag, ev->ifname);
		if (!p)
			return;
		if (p->ifindex != 0 && p->ifindex != ev->ifindex)
			return;            /* stale event for an old instance */
		if (p->ifindex == 0 && port_attach(p) < 0)
			return;            /* e.g. raced with another removal */
	}
	if (!p)
		return;

	if (ev->has_mac && memcmp(ev->mac, p->mac, ETH_ADDR_LEN) != 0) {
		char mac[18];
		memcpy(p->mac, ev->mac, ETH_ADDR_LEN);
		eth_ntoa(p->mac, mac);
		logmsg(p->name, "MAC address changed to %s", mac);
	}
	if (ev->has_mtu)
		p->mtu = ev->mtu;
	snprintf(p->alias, sizeof p->alias, "%s", ev->has_alias ? ev->alias : "");
	port_set_oper(p, is_oper_up(ev->flags));
}

/* ------------------------------------------------------------------- setup */

static int open_timer(void)
{
	return timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
}

static void ctl_cmd(const char *cmd, FILE *out, void *ctx)
{
	report_command(ctx, cmd, out);
}

int agent_init(struct agent *ag, const struct agent_cfg *cfg)
{
	sigset_t mask;
	unsigned i, j;
	unsigned long ttl;

	memset(ag, 0, sizeof *ag);
	ag->cfg = *cfg;
	ag->epfd = ag->sig_fd = ag->nl_fd = ag->host_fd = ag->print_tfd = -1;
	ag->start_ms = agent_now_ms();

	if (cfg->n_ifnames == 0 || cfg->n_ifnames > AGENT_MAX_PORTS) {
		fprintf(stderr, "need 1..%d interfaces\n", AGENT_MAX_PORTS);
		return -1;
	}
	for (i = 0; i < cfg->n_ifnames; i++) {
		if (strlen(cfg->ifnames[i]) == 0 || strlen(cfg->ifnames[i]) >= IF_NAMESIZE) {
			fprintf(stderr, "invalid interface name '%s'\n", cfg->ifnames[i]);
			return -1;
		}
		for (j = 0; j < i; j++)
			if (strcmp(cfg->ifnames[i], cfg->ifnames[j]) == 0) {
				fprintf(stderr, "interface %s given twice\n", cfg->ifnames[i]);
				return -1;
			}
	}
	if (!ag->cfg.chassis_if)
		ag->cfg.chassis_if = cfg->ifnames[0];

	/* 9.2.5.22: txTTL = min(65535, (msgTxInterval * msgTxHold) + 1) */
	ttl = (unsigned long)cfg->tx_interval * cfg->tx_hold + 1;
	ag->ttl = (uint16_t)(ttl > 65535 ? 65535 : ttl);

	/* chassis ID: one per system, the same on every port (8.5.2) */
	if (eth_get_ifmac(ag->cfg.chassis_if, ag->chassis_mac) < 0) {
		fprintf(stderr, "chassis ID: cannot read MAC of %s: %s\n",
			ag->cfg.chassis_if, strerror(errno));
		return -1;
	}
	localinfo_sysdesc(ag->sysdesc, sizeof ag->sysdesc);
	refresh_system(ag);

	/* signals become readable events; nothing runs in signal context */
	signal(SIGPIPE, SIG_IGN);
	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0)
		goto fail_errno;
	ag->sig_fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
	ag->epfd = epoll_create1(EPOLL_CLOEXEC);
	ag->nl_fd = netmon_open();
	ag->print_tfd = open_timer();
	if (ag->sig_fd < 0 || ag->epfd < 0 || ag->nl_fd < 0 || ag->print_tfd < 0)
		goto fail_errno;
	ag->ev_sig = (struct ev){ EV_SIGNAL, ag };
	ag->ev_nl = (struct ev){ EV_NETLINK, ag };
	ag->ev_print = (struct ev){ EV_PRINT, ag };
	if (ep_add(ag, ag->sig_fd, EPOLLIN, &ag->ev_sig) < 0 ||
	    ep_add(ag, ag->nl_fd, EPOLLIN, &ag->ev_nl) < 0 ||
	    ep_add(ag, ag->print_tfd, EPOLLIN, &ag->ev_print) < 0)
		goto fail_errno;

	/*
	 * System Name follows the hostname. proc_sys_poll() reports a change
	 * to /proc/sys/kernel/hostname as POLLPRI|POLLERR (and only then), so
	 * this fd is registered for EPOLLPRI alone.
	 */
	if (!cfg->sys_name) {
		ag->host_fd = open("/proc/sys/kernel/hostname", O_RDONLY | O_CLOEXEC);
		ag->ev_host = (struct ev){ EV_HOSTNAME, ag };
		if (ag->host_fd >= 0 && ep_add(ag, ag->host_fd, EPOLLPRI, &ag->ev_host) < 0) {
			close(ag->host_fd);
			ag->host_fd = -1;
		}
	}

	for (i = 0; i < cfg->n_ifnames; i++) {
		struct port *p = calloc(1, sizeof *p);
		if (!p)
			goto fail_errno;
		ag->ports[ag->nports++] = p;
		p->ag = ag;
		p->tx_tfd = p->age_tfd = -1;
		snprintf(p->name, sizeof p->name, "%s", cfg->ifnames[i]);
		p->sock.fd = -1;
		neigh_init(&p->table);
		p->tx_tfd = open_timer();
		p->age_tfd = open_timer();
		p->ev_tx = (struct ev){ EV_TX, p };
		p->ev_age = (struct ev){ EV_AGE, p };
		if (p->tx_tfd < 0 || p->age_tfd < 0 ||
		    ep_add(ag, p->tx_tfd, EPOLLIN, &p->ev_tx) < 0 ||
		    ep_add(ag, p->age_tfd, EPOLLIN, &p->ev_age) < 0)
			goto fail_errno;
		/* an interface that does not exist at start-up is a typo, not a hotplug */
		if (port_attach(p) < 0)
			goto fail;
	}

	/* initial operational state and aliases */
	if (netmon_dump_links(on_netmon, ag) < 0) {
		fprintf(stderr, "netlink link dump failed: %s\n", strerror(errno));
		goto fail;
	}

	if (cfg->ctl_path) {
		ag->ctl = ctl_open(cfg->ctl_path, ag->epfd, ctl_cmd, ag);
		if (!ag->ctl)
			goto fail;
	}
	if (cfg->print_secs) {
		struct itimerspec its = {
			.it_value = { (time_t)cfg->print_secs, 0 },
			.it_interval = { (time_t)cfg->print_secs, 0 },
		};
		timerfd_settime(ag->print_tfd, 0, &its, NULL);
	}

	/* everything privileged is open: shed root, keep only CAP_NET_RAW */
	if (cfg->run_as && privdrop(cfg->run_as) < 0)
		goto fail;
	return 0;

fail_errno:
	fprintf(stderr, "agent setup: %s\n", strerror(errno));
fail:
	agent_free(ag);
	return -1;
}

static void print_stats(const struct port *p)
{
	logmsg(p->name, "stats: out=%lu in=%lu discarded=%lu in_errors=%lu "
	       "tlvs_unrecognized=%lu ageouts=%lu too_many_neighbors=%lu "
	       "own_frames=%lu local_changes=%lu",
	       p->st.frames_out, p->st.frames_in, p->st.frames_discarded,
	       p->st.frames_in_errors, p->st.tlvs_unrecognized, p->st.ageouts,
	       p->st.too_many_neighbors, p->st.own_frames, p->st.local_changes);
}

int agent_run(struct agent *ag)
{
	struct epoll_event evs[16];
	char mac[18];
	unsigned i;
	int n, k;

	eth_ntoa(ag->chassis_mac, mac);
	logmsg(NULL, "lldpnd started: chassis=%s ports=%u mode=%s dest=%s tx-interval=%us "
	       "ttl=%us fast-init=%u credit-max=%u", mac, ag->nports,
	       agent_admin_name(ag->cfg.admin), lldp_group_name(agent_group(ag)),
	       ag->cfg.tx_interval, ag->ttl, ag->cfg.fast_init, ag->cfg.credit_max);
	ag->running = 1;

	while (ag->running) {
		int netlink_seen = 0;

		n = epoll_wait(ag->epfd, evs, (int)(sizeof evs / sizeof evs[0]), -1);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			logmsg(NULL, "epoll_wait: %s", strerror(errno));
			return 1;
		}
		for (k = 0; k < n; k++) {
			struct ev *e = evs[k].data.ptr;
			struct port *p = e->obj;

			switch (e->kind) {
			case EV_SOCK:
				port_rx(p);
				break;
			case EV_TX:
				drain(p->tx_tfd);
				port_tx_timer(p);
				break;
			case EV_AGE:
				drain(p->age_tfd);
				if (neigh_age(&p->table, agent_now_ms(), ageout_cb, p))
					p->dirty = 1;
				port_arm_age(p);
				break;
			case EV_SIGNAL: {
				struct signalfd_siginfo si;
				if (read(ag->sig_fd, &si, sizeof si) == (ssize_t)sizeof si) {
					logmsg(NULL, "caught signal %u, shutting down", si.ssi_signo);
					ag->running = 0;
				}
				break;
			}
			case EV_NETLINK:
				netmon_read(ag->nl_fd, on_netmon, ag);
				netlink_seen = 1;
				break;
			case EV_HOSTNAME: {
				char b[8];
				ssize_t r = pread(ag->host_fd, b, sizeof b, 0);
				(void)r;
				netlink_seen = 1;   /* same handling: refresh + rebuild */
				break;
			}
			case EV_PRINT:
				drain(ag->print_tfd);
				for (i = 0; i < ag->nports; i++)
					print_port(ag->ports[i]);
				break;
			case EV_CTL:
				ctl_event(ag->ctl, e, evs[k].events);
				break;
			}
		}
		if (netlink_seen) {
			refresh_system(ag);
			rebuild_all(ag, "interface/address/hostname change");
		}
		/* with no -p, print a port's table whenever it changed */
		if (ag->cfg.print_secs == 0)
			for (i = 0; i < ag->nports; i++)
				if (ag->ports[i]->dirty)
					print_port(ag->ports[i]);
	}

	/*
	 * 9.2.7 mibConstrShutdownLLDPDU(): announce shutdown with TTL 0 so
	 * that neighbours delete our information at once instead of waiting
	 * for it to age out.
	 */
	for (i = 0; i < ag->nports; i++)
		send_shutdown(ag->ports[i]);
	for (i = 0; i < ag->nports; i++) {
		print_port(ag->ports[i]);
		print_stats(ag->ports[i]);
	}
	return 0;
}

void agent_free(struct agent *ag)
{
	unsigned i;

	if (ag->ctl)
		ctl_close(ag->ctl);
	ag->ctl = NULL;
	for (i = 0; i < ag->nports; i++) {
		struct port *p = ag->ports[i];
		lldp_sock_close(&p->sock);
		if (p->tx_tfd >= 0)
			close(p->tx_tfd);
		if (p->age_tfd >= 0)
			close(p->age_tfd);
		free(p);
		ag->ports[i] = NULL;
	}
	ag->nports = 0;
	if (ag->sig_fd >= 0) close(ag->sig_fd);
	if (ag->nl_fd >= 0) close(ag->nl_fd);
	if (ag->host_fd >= 0) close(ag->host_fd);
	if (ag->print_tfd >= 0) close(ag->print_tfd);
	if (ag->epfd >= 0) close(ag->epfd);
	ag->sig_fd = ag->nl_fd = ag->host_fd = ag->print_tfd = ag->epfd = -1;
}
