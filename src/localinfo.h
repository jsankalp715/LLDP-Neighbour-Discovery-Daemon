/*
 * localinfo.h - gather what this system advertises: system name and
 * description, system capabilities (8.5.8) and management addresses (8.5.9)
 */
#ifndef LLDP_LOCALINFO_H
#define LLDP_LOCALINFO_H

#include <ifaddrs.h>
#include <stddef.h>
#include <stdint.h>

#include "lldpdu.h"

/*
 * Choose management addresses for one port from a getifaddrs() list:
 * the first IPv4 address, then the first global IPv6 address (or the first
 * link-local one if there is no global one). With no IP address at all the
 * port MAC is advertised (IANA family 6, "all 802"). Interface numbering is
 * the ifIndex. Returns the number written to out (<= max).
 */
unsigned localinfo_mgmt(const struct ifaddrs *list, const char *ifname,
			unsigned ifindex, const uint8_t mac[6],
			struct lldp_mgmt *out, unsigned max);

/*
 * System capabilities of a Linux host: router and station supported;
 * router enabled when IPv4 or IPv6 forwarding is on, station otherwise.
 */
void localinfo_caps(int forwarding, uint16_t *supported, uint16_t *enabled);

/* 1 if net.ipv4.conf.all.forwarding or net.ipv6.conf.all.forwarding is set */
int localinfo_forwarding(void);

/* gethostname(), always NUL-terminated, at most 255 octets (8.5.6) */
void localinfo_hostname(char *out, size_t cap);

/* "sysname release version machine" from uname(2), at most 255 octets */
void localinfo_sysdesc(char *out, size_t cap);

#endif
