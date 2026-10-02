/* test_netmon.c - rtnetlink parsing and local-information selection */
#include "test.h"
#include "../src/localinfo.h"
#include "../src/netmon.h"

#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <stdlib.h>

/* ------------------------------------------------ netlink message builder */

static unsigned char nlbuf[4096] __attribute__((aligned(4)));
static size_t nllen;
static struct nlmsghdr *cur;

static void msg_begin(unsigned type, size_t hdrlen)
{
	cur = (struct nlmsghdr *)(nlbuf + nllen);
	memset(cur, 0, NLMSG_LENGTH(hdrlen));
	cur->nlmsg_type = (uint16_t)type;
	cur->nlmsg_len = (uint32_t)NLMSG_LENGTH(hdrlen);
}

static void attr(unsigned type, const void *data, size_t len)
{
	struct rtattr *rta = (struct rtattr *)((unsigned char *)cur + NLMSG_ALIGN(cur->nlmsg_len));
	rta->rta_type = (unsigned short)type;
	rta->rta_len = (unsigned short)RTA_LENGTH(len);
	memcpy(RTA_DATA(rta), data, len);
	cur->nlmsg_len = (uint32_t)(NLMSG_ALIGN(cur->nlmsg_len) + RTA_ALIGN(rta->rta_len));
}

static void msg_end(void)
{
	nllen += NLMSG_ALIGN(cur->nlmsg_len);
}

static void link_msg(unsigned type, int ifindex, unsigned flags, const char *name,
		     const uint8_t *mac, const char *alias)
{
	struct ifinfomsg *ifi;

	msg_begin(type, sizeof *ifi);
	ifi = NLMSG_DATA(cur);
	ifi->ifi_index = ifindex;
	ifi->ifi_flags = flags;
	if (name)
		attr(IFLA_IFNAME, name, strlen(name) + 1);
	if (mac)
		attr(IFLA_ADDRESS, mac, 6);
	if (alias)
		attr(IFLA_IFALIAS, alias, strlen(alias) + 1);
	msg_end();
}

static struct nm_event got[16];
static int ngot;

static void collect(const struct nm_event *ev, void *ctx)
{
	(void)ctx;
	if (ngot < 16)
		got[ngot++] = *ev;
}

static void reset(void)
{
	memset(nlbuf, 0, sizeof nlbuf);
	nllen = 0;
	ngot = 0;
}

static void test_parse_link_events(void)
{
	const uint8_t mac[6] = { 0x02, 1, 2, 3, 4, 5 };
	struct ifaddrmsg *ifa;

	reset();
	link_msg(RTM_NEWLINK, 7, IFF_UP | IFF_RUNNING, "eth0", mac, "uplink to core");
	link_msg(RTM_DELLINK, 9, 0, "eth9", NULL, NULL);
	msg_begin(RTM_NEWADDR, sizeof *ifa);
	ifa = NLMSG_DATA(cur);
	ifa->ifa_index = 7;
	msg_end();
	msg_begin(RTM_DELADDR, sizeof *ifa);
	ifa = NLMSG_DATA(cur);
	ifa->ifa_index = 8;
	msg_end();
	link_msg(RTM_NEWLINK, 3, IFF_UP, "eth1", NULL, NULL);

	CHECK(netmon_parse(nlbuf, nllen, collect, NULL) == 5);
	CHECK(ngot == 5);
	CHECK(got[0].type == NM_LINK && got[0].ifindex == 7);
	CHECK(got[0].flags == (IFF_UP | IFF_RUNNING));
	CHECK(strcmp(got[0].ifname, "eth0") == 0);
	CHECK(got[0].has_mac && memcmp(got[0].mac, mac, 6) == 0);
	CHECK(got[0].has_alias && strcmp(got[0].alias, "uplink to core") == 0);
	CHECK(got[1].type == NM_DELLINK && got[1].ifindex == 9);
	CHECK(got[2].type == NM_ADDR && got[2].ifindex == 7);
	CHECK(got[3].type == NM_ADDR && got[3].ifindex == 8);
	CHECK(got[4].type == NM_LINK && !got[4].has_mac && !got[4].has_alias);
}

static void test_parse_done_error_and_garbage(void)
{
	char longname[40];
	const uint8_t shortmac[4] = { 1, 2, 3, 4 };
	struct ifinfomsg *ifi;

	/* NLMSG_DONE stops processing */
	reset();
	link_msg(RTM_NEWLINK, 1, 0, "a", NULL, NULL);
	msg_begin(NLMSG_DONE, 4);
	msg_end();
	link_msg(RTM_NEWLINK, 2, 0, "b", NULL, NULL);
	CHECK(netmon_parse(nlbuf, nllen, collect, NULL) == 1 && ngot == 1);

	/* NLMSG_ERROR is reported */
	reset();
	msg_begin(NLMSG_ERROR, sizeof(struct nlmsgerr));
	msg_end();
	CHECK(netmon_parse(nlbuf, nllen, collect, NULL) == -1);

	/* truncated buffers deliver nothing and do not over-read */
	reset();
	link_msg(RTM_NEWLINK, 1, 0, "eth0", NULL, NULL);
	CHECK(netmon_parse(nlbuf, nllen - 1, collect, NULL) == 0);
	CHECK(netmon_parse(nlbuf, 10, collect, NULL) == 0);
	CHECK(netmon_parse(nlbuf, 0, collect, NULL) == 0 && ngot == 0);

	/* message claiming to be shorter than its fixed header is skipped */
	reset();
	msg_begin(RTM_NEWLINK, 0);
	msg_end();
	CHECK(netmon_parse(nlbuf, nllen, collect, NULL) == 0);

	/* over-long name and wrong-size MAC are ignored, not truncated/copied */
	reset();
	memset(longname, 'x', sizeof longname - 1);
	longname[sizeof longname - 1] = '\0';
	link_msg(RTM_NEWLINK, 4, 0, longname, NULL, NULL);
	msg_begin(RTM_NEWLINK, sizeof *ifi);
	ifi = NLMSG_DATA(cur);
	ifi->ifi_index = 5;
	attr(IFLA_ADDRESS, shortmac, sizeof shortmac);
	attr(IFLA_IFNAME, "noterm", 6);           /* not NUL-terminated */
	msg_end();
	CHECK(netmon_parse(nlbuf, nllen, collect, NULL) == 2);
	CHECK(got[0].ifname[0] == '\0');
	CHECK(!got[1].has_mac);
	CHECK(strlen(got[1].ifname) < sizeof got[1].ifname);
	CHECK(strcmp(got[1].ifname, "noter") == 0);   /* last octet forced to NUL */

	/*
	 * Regression (found by fuzzing): a final message whose length is not
	 * a multiple of 4 made an unsigned remaining-length wrap in
	 * NLMSG_NEXT, walking past the buffer. Exact-size heap copy so ASan
	 * would flag a single byte of over-read.
	 */
	reset();
	link_msg(RTM_NEWLINK, 6, 0, "ab", NULL, NULL);
	{
		size_t odd = NLMSG_LENGTH(sizeof(struct ifinfomsg)) + 1;
		unsigned char *exact = malloc(odd);
		((struct nlmsghdr *)nlbuf)->nlmsg_len = (uint32_t)odd;
		if (exact) {
			memcpy(exact, nlbuf, odd);
			CHECK(netmon_parse(exact, odd, collect, NULL) == 1);
			free(exact);
		}
	}

	/* ifindex 0 is not an interface */
	reset();
	link_msg(RTM_NEWLINK, 0, 0, "x", NULL, NULL);
	netmon_parse(nlbuf, nllen, collect, NULL);
	CHECK(ngot == 0);
}

/* --------------------------------------------------------- localinfo */

static struct ifaddrs ifas[8];
static struct sockaddr_in sin4[8];      /* indexed like ifas[] */
static struct sockaddr_in6 sin6[8];

static void add4(int i, const char *ifname, const char *addr, struct ifaddrs *next)
{
	sin4[i].sin_family = AF_INET;
	inet_pton(AF_INET, addr, &sin4[i].sin_addr);
	ifas[i].ifa_name = (char *)ifname;
	ifas[i].ifa_addr = (struct sockaddr *)&sin4[i];
	ifas[i].ifa_next = next;
}

static void add6(int i, int j, const char *ifname, const char *addr, struct ifaddrs *next)
{
	sin6[j].sin6_family = AF_INET6;
	inet_pton(AF_INET6, addr, &sin6[j].sin6_addr);
	ifas[i].ifa_name = (char *)ifname;
	ifas[i].ifa_addr = (struct sockaddr *)&sin6[j];
	ifas[i].ifa_next = next;
}

static void test_mgmt_selection(void)
{
	const uint8_t mac[6] = { 0x02, 0, 0, 0, 0, 0x77 };
	struct lldp_mgmt m[LLDP_MAX_MGMT];
	char s[LLDP_MGMTFMT_MAX];
	unsigned n;

	memset(ifas, 0, sizeof ifas);
	/* list: other-if v4, link-local v6, our v4, global v6, 2nd v4, no-addr entry */
	add4(0, "eth1", "198.51.100.1", &ifas[1]);
	add6(1, 0, "eth0", "fe80::1", &ifas[2]);
	add4(2, "eth0", "192.0.2.10", &ifas[3]);
	add6(3, 1, "eth0", "2001:db8::10", &ifas[4]);
	add4(4, "eth0", "192.0.2.11", &ifas[5]);
	ifas[5].ifa_name = (char *)"eth0";         /* entry with no address */
	ifas[5].ifa_addr = NULL;

	n = localinfo_mgmt(&ifas[0], "eth0", 4, mac, m, LLDP_MAX_MGMT);
	CHECK(n == 2);
	lldp_mgmt_format(&m[0], s, sizeof s);
	CHECK(strcmp(s, "192.0.2.10") == 0);
	CHECK(m[0].if_subtype == LLDP_IFNUM_IFINDEX && m[0].if_number == 4);
	lldp_mgmt_format(&m[1], s, sizeof s);
	CHECK(strcmp(s, "2001:db8::10") == 0);     /* global preferred over fe80:: */

	/* only a link-local IPv6 address: use it */
	n = localinfo_mgmt(&ifas[1], "eth0", 4, mac, m, 1);
	CHECK(n == 1);                             /* max honoured */
	ifas[1].ifa_next = NULL;
	n = localinfo_mgmt(&ifas[1], "eth0", 4, mac, m, LLDP_MAX_MGMT);
	CHECK(n == 1);
	lldp_mgmt_format(&m[0], s, sizeof s);
	CHECK(strcmp(s, "fe80::1") == 0);

	/* no addresses at all: the port MAC */
	n = localinfo_mgmt(&ifas[0], "eth9", 12, mac, m, LLDP_MAX_MGMT);
	CHECK(n == 1);
	lldp_mgmt_format(&m[0], s, sizeof s);
	CHECK(strcmp(s, "mac 02:00:00:00:00:77") == 0);
	CHECK(m[0].if_number == 12);
	n = localinfo_mgmt(NULL, "eth0", 1, mac, m, LLDP_MAX_MGMT);
	CHECK(n == 1 && m[0].subtype == LLDP_AF_ALL802);
	CHECK(localinfo_mgmt(&ifas[0], "eth0", 1, mac, m, 0) == 0);
}

static void test_caps_and_system(void)
{
	uint16_t s, e;
	char host[256], desc[256];

	localinfo_caps(0, &s, &e);
	CHECK(s == (LLDP_CAP_ROUTER | LLDP_CAP_STATION) && e == LLDP_CAP_STATION);
	localinfo_caps(1, &s, &e);
	CHECK(e == LLDP_CAP_ROUTER);
	CHECK(localinfo_forwarding() == 0 || localinfo_forwarding() == 1);

	localinfo_hostname(host, sizeof host);
	CHECK(host[0] != '\0' && strlen(host) <= 255);
	localinfo_hostname(host, 4);                /* truncates safely */
	CHECK(strlen(host) <= 3);
	localinfo_sysdesc(desc, sizeof desc);
	CHECK(strncmp(desc, "Linux ", 6) == 0 && strlen(desc) <= 255);
}

int main(void)
{
	RUN(test_parse_link_events);
	RUN(test_parse_done_error_and_garbage);
	RUN(test_mgmt_selection);
	RUN(test_caps_and_system);
	return test_report("test_netmon");
}
