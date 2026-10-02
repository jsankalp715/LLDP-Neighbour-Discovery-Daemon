/*
 * frame.h - Ethernet II framing for LLDPDUs (IEEE Std 802.1AB-2016, clause 7)
 */
#ifndef LLDP_FRAME_H
#define LLDP_FRAME_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define ETH_ADDR_LEN     6u
#define ETH_HDR_LEN      14u
#define ETH_MIN_FRAME    60u     /* 64-octet minimum less the 4-octet FCS */
#define ETH_MAX_PAYLOAD  1500u

/* 7.2: LLDP Ethertype */
#define ETHERTYPE_LLDP   0x88CCu

/* 7.1, Table 7-1: nearest bridge group address, used by this agent */
extern const uint8_t LLDP_MCAST_NEAREST_BRIDGE[ETH_ADDR_LEN];

/* Read-only view of a received Ethernet II frame */
struct eth_view {
	const uint8_t *dst;
	const uint8_t *src;
	uint16_t       ethertype;
	const uint8_t *payload;
	size_t         payload_len;
};

/*
 * Build dst|src|ethertype|payload into out, zero-padding to the 60-octet
 * Ethernet minimum (the FCS is appended by the NIC/driver). Returns the
 * frame length or -1 if it would not fit / payload exceeds 1500 octets.
 */
ssize_t eth_frame_build(uint8_t *out, size_t cap,
			const uint8_t dst[ETH_ADDR_LEN],
			const uint8_t src[ETH_ADDR_LEN],
			uint16_t ethertype,
			const uint8_t *payload, size_t payload_len);

/* Parse an Ethernet II header. Returns 0, or -1 if shorter than 14 octets. */
int eth_frame_parse(const uint8_t *frame, size_t len, struct eth_view *v);

/* Fetch an interface's MAC via SIOCGIFHWADDR. Returns 0, or -1 (errno set). */
int eth_get_ifmac(const char *ifname, uint8_t mac[ETH_ADDR_LEN]);

/* "aa:bb:cc:dd:ee:ff" into buf (>= 18 octets) */
void eth_ntoa(const uint8_t mac[ETH_ADDR_LEN], char buf[18]);

#endif
