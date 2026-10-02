/*
 * netmon.h - rtnetlink monitoring of links and addresses
 *
 * Local information changes (MAC, interface alias, addresses, operational
 * state) must trigger a new LLDPDU (somethingChangedLocal, 9.2.5) and port
 * enable/disable handling (portEnabled, 9.2.5). The kernel reports all of
 * these on NETLINK_ROUTE multicast groups, so the daemon sleeps on one more
 * file descriptor instead of polling.
 */
#ifndef LLDP_NETMON_H
#define LLDP_NETMON_H

#include <net/if.h>
#include <stdint.h>

enum nm_type {
	NM_LINK,      /* RTM_NEWLINK: link added or changed */
	NM_DELLINK,   /* RTM_DELLINK: link removed */
	NM_ADDR,      /* RTM_NEWADDR / RTM_DELADDR on ifindex */
	NM_RESYNC,    /* events were lost (ENOBUFS): re-read everything */
};

struct nm_event {
	enum nm_type type;
	int          ifindex;
	unsigned     flags;               /* IFF_* (links only) */
	char         ifname[IF_NAMESIZE]; /* "" if absent */
	int          has_mac;
	uint8_t      mac[6];
	int          has_mtu;
	unsigned     mtu;                 /* IFLA_MTU */
	int          has_alias;
	char         alias[256];          /* IFLA_IFALIAS, NUL-terminated */
};

typedef void (*nm_cb)(const struct nm_event *ev, void *ctx);

/* Subscribe to link + IPv4/IPv6 address events. Non-blocking fd, or -1. */
int netmon_open(void);

/* Drain pending events, calling cb for each. Returns 0, or -1 on error. */
int netmon_read(int fd, nm_cb cb, void *ctx);

/* Synchronously dump all links (RTM_GETLINK) as NM_LINK events. */
int netmon_dump_links(nm_cb cb, void *ctx);

/*
 * Parse one buffer of netlink messages (exposed for tests/fuzzing).
 * Returns the number of events delivered, or -1 if the buffer is malformed.
 */
int netmon_parse(const void *buf, size_t len, nm_cb cb, void *ctx);

#endif
