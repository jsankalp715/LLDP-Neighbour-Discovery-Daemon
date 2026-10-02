/*
 * rawsock.c - AF_PACKET raw socket bound to a single interface for LLDP
 *
 * LLDP runs directly over the MAC service (802.1AB clause 7), so frames are
 * sent and received with a packet(7) socket and the Ethernet header is built
 * by hand in frame.c.
 */
#include "rawsock.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int lldp_sock_open(struct lldp_sock *s, const char *ifname, const uint8_t *group)
{
	struct sockaddr_ll sll;
	struct packet_mreq mr;
	unsigned idx;
	int saved;

	memset(s, 0, sizeof *s);
	memcpy(s->group, group ? group : LLDP_MCAST_NEAREST_BRIDGE, ETH_ADDR_LEN);
	s->fd = -1;

	if (strlen(ifname) >= sizeof s->ifname) {
		fprintf(stderr, "interface name too long: %s\n", ifname);
		errno = ENAMETOOLONG;
		return -1;
	}
	memcpy(s->ifname, ifname, strlen(ifname) + 1);

	idx = if_nametoindex(ifname);
	if (idx == 0) {
		fprintf(stderr, "if_nametoindex(%s): %s\n", ifname, strerror(errno));
		return -1;
	}
	s->ifindex = (int)idx;

	if (eth_get_ifmac(ifname, s->mac) < 0) {
		fprintf(stderr, "SIOCGIFHWADDR(%s): %s\n", ifname, strerror(errno));
		return -1;
	}

	/*
	 * Create the socket with protocol 0 so that it receives nothing at
	 * all until bind() attaches it to one interface *and* the LLDP
	 * Ethertype. Creating it with ETH_P_LLDP directly would briefly
	 * deliver LLDP frames from every interface before the bind.
	 */
	s->fd = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (s->fd < 0) {
		perror("socket(AF_PACKET, SOCK_RAW)");
		return -1;
	}

	memset(&sll, 0, sizeof sll);
	sll.sll_family   = AF_PACKET;
	sll.sll_protocol = htons(ETHERTYPE_LLDP);   /* 7.2: 0x88CC only */
	sll.sll_ifindex  = s->ifindex;
	if (bind(s->fd, (struct sockaddr *)&sll, sizeof sll) < 0) {
		fprintf(stderr, "bind(%s): %s\n", ifname, strerror(errno));
		goto fail;
	}

	/*
	 * 7.1: LLDPDUs are addressed to a reserved group MAC; ask the NIC to
	 * accept it (programs the device multicast filter) so we do not
	 * depend on promiscuous mode.
	 */
	memset(&mr, 0, sizeof mr);
	mr.mr_ifindex = s->ifindex;
	mr.mr_type    = PACKET_MR_MULTICAST;
	mr.mr_alen    = ETH_ADDR_LEN;
	memcpy(mr.mr_address, s->group, ETH_ADDR_LEN);
	if (setsockopt(s->fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof mr) < 0) {
		fprintf(stderr, "PACKET_ADD_MEMBERSHIP(%s): %s\n", ifname, strerror(errno));
		goto fail;
	}
	return 0;

fail:
	saved = errno;
	close(s->fd);
	s->fd = -1;
	errno = saved;
	return -1;
}

int lldp_sock_send(struct lldp_sock *s, const uint8_t *frame, size_t len)
{
	struct sockaddr_ll sll;
	ssize_t n;

	memset(&sll, 0, sizeof sll);
	sll.sll_family   = AF_PACKET;
	sll.sll_protocol = htons(ETHERTYPE_LLDP);
	sll.sll_ifindex  = s->ifindex;
	sll.sll_halen    = ETH_ADDR_LEN;
	memcpy(sll.sll_addr, s->group, ETH_ADDR_LEN);

	n = sendto(s->fd, frame, len, 0, (struct sockaddr *)&sll, sizeof sll);
	if (n < 0)
		return -1;
	if ((size_t)n != len) {
		errno = EMSGSIZE;
		return -1;
	}
	return 0;
}

ssize_t lldp_sock_recv(struct lldp_sock *s, uint8_t *buf, size_t cap,
		       int *truncated, int *outgoing)
{
	struct sockaddr_ll from;
	socklen_t fromlen = sizeof from;
	ssize_t n;

	*truncated = 0;
	*outgoing = 0;
	/* MSG_TRUNC: return the real frame length even if it exceeds cap */
	n = recvfrom(s->fd, buf, cap, MSG_TRUNC, (struct sockaddr *)&from, &fromlen);
	if (n < 0) {
		/* ENETDOWN: the link went down; reported once, then cleared */
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ||
		    errno == ENETDOWN)
			return 0;
		return -1;
	}
	if ((size_t)n > cap) {
		*truncated = 1;
		n = (ssize_t)cap;
	}
	if (fromlen > offsetof(struct sockaddr_ll, sll_pkttype) &&
	    from.sll_pkttype == PACKET_OUTGOING)
		*outgoing = 1;
	return n;
}

void lldp_sock_close(struct lldp_sock *s)
{
	if (s->fd >= 0)
		close(s->fd);
	s->fd = -1;
}
