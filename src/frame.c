/*
 * frame.c - Ethernet II framing for LLDPDUs (IEEE Std 802.1AB-2016, clause 7)
 */
#include "frame.h"

#include <errno.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

const uint8_t LLDP_MCAST_NEAREST_BRIDGE[ETH_ADDR_LEN] = {
	0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e
};

ssize_t eth_frame_build(uint8_t *out, size_t cap,
			const uint8_t dst[ETH_ADDR_LEN],
			const uint8_t src[ETH_ADDR_LEN],
			uint16_t ethertype,
			const uint8_t *payload, size_t payload_len)
{
	size_t len;

	if (payload_len > ETH_MAX_PAYLOAD || (payload_len > 0 && payload == NULL))
		return -1;
	len = ETH_HDR_LEN + payload_len;
	if (len < ETH_MIN_FRAME)
		len = ETH_MIN_FRAME;
	if (cap < len)
		return -1;

	/*
	 * 7.1/7.2: destination = LLDP group address, source = the MAC of the
	 * transmitting port, then the LLDP Ethertype, network byte order.
	 */
	memcpy(out, dst, ETH_ADDR_LEN);
	memcpy(out + ETH_ADDR_LEN, src, ETH_ADDR_LEN);
	out[12] = (uint8_t)(ethertype >> 8);
	out[13] = (uint8_t)(ethertype & 0xffu);
	if (payload_len > 0)
		memcpy(out + ETH_HDR_LEN, payload, payload_len);
	/* pad: octets after End Of LLDPDU are ignored by receivers (8.2) */
	memset(out + ETH_HDR_LEN + payload_len, 0, len - ETH_HDR_LEN - payload_len);
	return (ssize_t)len;
}

int eth_frame_parse(const uint8_t *frame, size_t len, struct eth_view *v)
{
	if (frame == NULL || len < ETH_HDR_LEN)
		return -1;
	v->dst = frame;
	v->src = frame + ETH_ADDR_LEN;
	v->ethertype = (uint16_t)((frame[12] << 8) | frame[13]);
	v->payload = frame + ETH_HDR_LEN;
	v->payload_len = len - ETH_HDR_LEN;
	return 0;
}

int eth_get_ifmac(const char *ifname, uint8_t mac[ETH_ADDR_LEN])
{
	struct ifreq ifr;
	int fd, rc = -1, saved;

	if (strlen(ifname) >= IFNAMSIZ) {
		errno = ENAMETOOLONG;
		return -1;
	}
	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;
	memset(&ifr, 0, sizeof ifr);
	memcpy(ifr.ifr_name, ifname, strlen(ifname) + 1);
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
		/* only Ethernet-like links carry a 48-bit MAC we can use */
		if (ifr.ifr_hwaddr.sa_family == ARPHRD_ETHER) {
			memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ADDR_LEN);
			rc = 0;
		} else {
			errno = EAFNOSUPPORT;
		}
	}
	saved = errno;
	close(fd);
	errno = saved;
	return rc;
}

void eth_ntoa(const uint8_t mac[ETH_ADDR_LEN], char buf[18])
{
	snprintf(buf, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
		 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}
