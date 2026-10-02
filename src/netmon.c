/*
 * netmon.c - rtnetlink monitoring of links and addresses
 */
#include "netmon.h"

#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int netmon_open(void)
{
	struct sockaddr_nl sa;
	int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE);

	if (fd < 0)
		return -1;
	memset(&sa, 0, sizeof sa);
	sa.nl_family = AF_NETLINK;
	sa.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;
	if (bind(fd, (struct sockaddr *)&sa, sizeof sa) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}

static void parse_link(const struct nlmsghdr *nh, nm_cb cb, void *ctx)
{
	const struct ifinfomsg *ifi = NLMSG_DATA(nh);
	int len = (int)nh->nlmsg_len - (int)NLMSG_LENGTH(sizeof *ifi);
	const struct rtattr *rta;
	struct nm_event ev;

	if (len < 0)
		return;
	memset(&ev, 0, sizeof ev);
	ev.type = nh->nlmsg_type == RTM_DELLINK ? NM_DELLINK : NM_LINK;
	ev.ifindex = ifi->ifi_index;
	ev.flags = ifi->ifi_flags;

	for (rta = IFLA_RTA(ifi); RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
		size_t plen = RTA_PAYLOAD(rta);
		switch (rta->rta_type) {
		case IFLA_IFNAME:
			if (plen > 0 && plen <= sizeof ev.ifname) {
				memcpy(ev.ifname, RTA_DATA(rta), plen);
				ev.ifname[sizeof ev.ifname - 1] = '\0';
				ev.ifname[plen - 1] = '\0';
			}
			break;
		case IFLA_ADDRESS:
			if (plen == sizeof ev.mac) {
				memcpy(ev.mac, RTA_DATA(rta), sizeof ev.mac);
				ev.has_mac = 1;
			}
			break;
		case IFLA_IFALIAS:
			ev.has_alias = 1;
			if (plen >= sizeof ev.alias)
				plen = sizeof ev.alias - 1;
			memcpy(ev.alias, RTA_DATA(rta), plen);
			ev.alias[plen] = '\0';
			break;
		}
	}
	if (ev.ifindex > 0)
		cb(&ev, ctx);
}

int netmon_parse(const void *buf, size_t len, nm_cb cb, void *ctx)
{
	const struct nlmsghdr *nh;
	int n = 0;
	/*
	 * Signed on purpose: NLMSG_NEXT subtracts the *aligned* length, which can
	 * exceed what is left for a final unaligned message. An unsigned counter
	 * would wrap and NLMSG_OK would then walk past the buffer (found by
	 * fuzzing); a signed one goes negative and ends the loop.
	 */
	int rem = len > 0x7fffffff ? 0x7fffffff : (int)len;

	for (nh = buf; NLMSG_OK(nh, rem); nh = NLMSG_NEXT(nh, rem)) {
		switch (nh->nlmsg_type) {
		case NLMSG_DONE:
			return n;
		case NLMSG_ERROR:
			return -1;
		case RTM_NEWLINK:
		case RTM_DELLINK:
			if (nh->nlmsg_len >= NLMSG_LENGTH(sizeof(struct ifinfomsg))) {
				parse_link(nh, cb, ctx);
				n++;
			}
			break;
		case RTM_NEWADDR:
		case RTM_DELADDR:
			if (nh->nlmsg_len >= NLMSG_LENGTH(sizeof(struct ifaddrmsg))) {
				const struct ifaddrmsg *ifa = NLMSG_DATA(nh);
				struct nm_event ev;
				memset(&ev, 0, sizeof ev);
				ev.type = NM_ADDR;
				ev.ifindex = (int)ifa->ifa_index;
				cb(&ev, ctx);
				n++;
			}
			break;
		}
	}
	return n;
}

static void resync(nm_cb cb, void *ctx)
{
	struct nm_event ev;

	memset(&ev, 0, sizeof ev);
	ev.type = NM_RESYNC;
	cb(&ev, ctx);
}

int netmon_read(int fd, nm_cb cb, void *ctx)
{
	/* 8 KiB aligned buffer, as recommended by netlink(7) */
	static unsigned char buf[8192] __attribute__((aligned(NLMSG_ALIGNTO)));
	struct sockaddr_nl from;
	socklen_t fl;
	ssize_t n;

	for (;;) {
		fl = sizeof from;
		n = recvfrom(fd, buf, sizeof buf, MSG_DONTWAIT, (struct sockaddr *)&from, &fl);
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
				return 0;
			if (errno == ENOBUFS) {          /* overrun: state is unknown */
				resync(cb, ctx);
				continue;
			}
			return -1;
		}
		/* only the kernel (port id 0) is trusted to describe links */
		if (fl < sizeof from || from.nl_pid != 0)
			continue;
		netmon_parse(buf, (size_t)n, cb, ctx);
	}
}

int netmon_dump_links(nm_cb cb, void *ctx)
{
	static unsigned char buf[16384] __attribute__((aligned(NLMSG_ALIGNTO)));
	struct {
		struct nlmsghdr  nh;
		struct ifinfomsg ifi;
	} req;
	struct sockaddr_nl sa;
	int fd, rc = -1, done = 0;

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (fd < 0)
		return -1;
	memset(&req, 0, sizeof req);
	req.nh.nlmsg_len = NLMSG_LENGTH(sizeof req.ifi);
	req.nh.nlmsg_type = RTM_GETLINK;
	req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.nh.nlmsg_seq = 1;
	req.ifi.ifi_family = AF_UNSPEC;
	memset(&sa, 0, sizeof sa);
	sa.nl_family = AF_NETLINK;
	if (sendto(fd, &req, req.nh.nlmsg_len, 0, (struct sockaddr *)&sa, sizeof sa) < 0)
		goto out;

	while (!done) {
		struct sockaddr_nl from;
		socklen_t fl = sizeof from;
		const struct nlmsghdr *nh;
		ssize_t n = recvfrom(fd, buf, sizeof buf, 0, (struct sockaddr *)&from, &fl);
		int rem;

		if (n < 0) {
			if (errno == EINTR)
				continue;
			goto out;
		}
		if (fl < sizeof from || from.nl_pid != 0)
			continue;
		rem = (int)n;
		for (nh = (const struct nlmsghdr *)buf; NLMSG_OK(nh, rem); nh = NLMSG_NEXT(nh, rem))
			if (nh->nlmsg_type == NLMSG_DONE || nh->nlmsg_type == NLMSG_ERROR)
				done = 1;
		if (netmon_parse(buf, (size_t)n, cb, ctx) < 0)
			goto out;
	}
	rc = 0;
out:
	close(fd);
	return rc;
}
