/*
 * localinfo.c - gather what this system advertises
 */
#include "localinfo.h"

#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <unistd.h>

static int is_link_local6(const struct in6_addr *a)
{
	return a->s6_addr[0] == 0xfe && (a->s6_addr[1] & 0xc0) == 0x80;
}

unsigned localinfo_mgmt(const struct ifaddrs *list, const char *ifname,
			unsigned ifindex, const uint8_t mac[6],
			struct lldp_mgmt *out, unsigned max)
{
	const struct ifaddrs *ifa;
	const struct in_addr *v4 = NULL;
	const struct in6_addr *v6 = NULL, *v6ll = NULL;
	unsigned n = 0;

	if (max == 0)
		return 0;
	for (ifa = list; ifa; ifa = ifa->ifa_next) {
		if (!ifa->ifa_addr || !ifa->ifa_name || strcmp(ifa->ifa_name, ifname) != 0)
			continue;
		if (ifa->ifa_addr->sa_family == AF_INET && !v4) {
			v4 = &((const struct sockaddr_in *)(const void *)ifa->ifa_addr)->sin_addr;
		} else if (ifa->ifa_addr->sa_family == AF_INET6) {
			const struct in6_addr *a =
				&((const struct sockaddr_in6 *)(const void *)ifa->ifa_addr)->sin6_addr;
			if (is_link_local6(a)) {
				if (!v6ll)
					v6ll = a;
			} else if (!v6) {
				v6 = a;
			}
		}
	}
	if (!v6)
		v6 = v6ll;

	if (v4 && n < max) {
		memset(&out[n], 0, sizeof out[n]);
		out[n].subtype = LLDP_AF_IPV4;
		out[n].len = 4;
		memcpy(out[n].addr, v4, 4);
		out[n].if_subtype = LLDP_IFNUM_IFINDEX;
		out[n].if_number = ifindex;
		n++;
	}
	if (v6 && n < max) {
		memset(&out[n], 0, sizeof out[n]);
		out[n].subtype = LLDP_AF_IPV6;
		out[n].len = 16;
		memcpy(out[n].addr, v6, 16);
		out[n].if_subtype = LLDP_IFNUM_IFINDEX;
		out[n].if_number = ifindex;
		n++;
	}
	if (n == 0) {
		memset(&out[0], 0, sizeof out[0]);
		out[0].subtype = LLDP_AF_ALL802;
		out[0].len = 6;
		memcpy(out[0].addr, mac, 6);
		out[0].if_subtype = LLDP_IFNUM_IFINDEX;
		out[0].if_number = ifindex;
		n = 1;
	}
	return n;
}

void localinfo_caps(int forwarding, uint16_t *supported, uint16_t *enabled)
{
	*supported = LLDP_CAP_ROUTER | LLDP_CAP_STATION;
	*enabled = forwarding ? LLDP_CAP_ROUTER : LLDP_CAP_STATION;
}

static int read_flag(const char *path)
{
	char c = '0';
	int fd = open(path, O_RDONLY | O_CLOEXEC);

	if (fd < 0)
		return 0;
	if (read(fd, &c, 1) != 1)
		c = '0';
	close(fd);
	return c == '1';
}

int localinfo_forwarding(void)
{
	/* /proc/sys/net is per network namespace: these are ours */
	return read_flag("/proc/sys/net/ipv4/conf/all/forwarding") ||
	       read_flag("/proc/sys/net/ipv6/conf/all/forwarding");
}

void localinfo_hostname(char *out, size_t cap)
{
	if (cap == 0)
		return;
	if (gethostname(out, cap - 1) < 0)
		snprintf(out, cap, "unknown");
	out[cap - 1] = '\0';
	if (cap > LLDP_STR_MAX_LEN)
		out[LLDP_STR_MAX_LEN] = '\0';
}

void localinfo_sysdesc(char *out, size_t cap)
{
	struct utsname u;
	char tmp[4 * sizeof u.sysname + 4];

	if (cap == 0)
		return;
	if (uname(&u) == 0)
		snprintf(tmp, sizeof tmp, "%s %s %s %s",
			 u.sysname, u.release, u.version, u.machine);
	else
		snprintf(tmp, sizeof tmp, "Linux");
	tmp[LLDP_STR_MAX_LEN] = '\0';           /* 8.5.7: at most 255 octets */
	snprintf(out, cap, "%s", tmp);
}
