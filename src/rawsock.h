/*
 * rawsock.h - AF_PACKET raw socket bound to a single interface for LLDP
 */
#ifndef LLDP_RAWSOCK_H
#define LLDP_RAWSOCK_H

#include <net/if.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "frame.h"

struct lldp_sock {
	int     fd;
	int     ifindex;
	uint8_t mac[ETH_ADDR_LEN];
	char    ifname[IF_NAMESIZE];
};

/*
 * Open a non-blocking AF_PACKET/SOCK_RAW socket that receives only frames
 * with EtherType 0x88CC on ifname, joined to the LLDP nearest-bridge group
 * address. Returns 0 or -1 (errno set; message printed to stderr).
 */
int lldp_sock_open(struct lldp_sock *s, const char *ifname);

/* Transmit a complete Ethernet frame. Returns 0 or -1. */
int lldp_sock_send(struct lldp_sock *s, const uint8_t *frame, size_t len);

/*
 * Receive one frame. Returns its length, 0 if nothing is pending (EAGAIN),
 * or -1 on error. *truncated is set if the frame exceeded cap and was cut.
 * *outgoing is set for frames this host itself transmitted (PACKET_OUTGOING).
 */
ssize_t lldp_sock_recv(struct lldp_sock *s, uint8_t *buf, size_t cap,
		       int *truncated, int *outgoing);

void lldp_sock_close(struct lldp_sock *s);

#endif
