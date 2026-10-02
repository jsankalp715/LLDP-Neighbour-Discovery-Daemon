/*
 * test_rawsock.c - raw AF_PACKET socket integration test.
 *
 * Needs CAP_NET_RAW and a veth pair; `make rawsock-test` creates one inside
 * a throwaway network namespace and runs: test_rawsock <ifA> <ifB>
 */
#include "test.h"
#include "../src/lldpdu.h"
#include "../src/rawsock.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <poll.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

/* wait up to ms for one frame on s; returns length, 0 on timeout */
static ssize_t recv_wait(struct lldp_sock *s, uint8_t *buf, size_t cap, int ms,
			 int *trunc, int *outgoing)
{
	struct pollfd p = { .fd = s->fd, .events = POLLIN };

	for (;;) {
		int r = poll(&p, 1, ms);
		if (r <= 0)
			return 0;
		ssize_t n = lldp_sock_recv(s, buf, cap, trunc, outgoing);
		if (n != 0)
			return n;
	}
}

/* send an arbitrary frame through an unfiltered raw socket on ifindex */
static int send_any(int ifindex, const uint8_t *frame, size_t len)
{
	struct sockaddr_ll sll;
	int fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, 0);
	ssize_t n;

	if (fd < 0)
		return -1;
	memset(&sll, 0, sizeof sll);
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifindex;
	sll.sll_halen = 6;
	memcpy(sll.sll_addr, frame, 6);
	n = sendto(fd, frame, len, 0, (struct sockaddr *)&sll, sizeof sll);
	close(fd);
	return n == (ssize_t)len ? 0 : -1;
}

/* is the LLDP group address in the device's multicast list? */
static int mcast_joined(const char *ifname, const char *group_hex)
{
	char line[256], name[64], addr[64];
	int idx, users, global, found = 0;
	FILE *f = fopen("/proc/net/dev_mcast", "r");

	if (!f)
		return 0;
	while (fgets(line, sizeof line, f))
		if (sscanf(line, "%d %63s %d %d %63s", &idx, name, &users, &global, addr) == 5 &&
		    strcmp(name, ifname) == 0 && strcmp(addr, group_hex) == 0)
			found = 1;
	fclose(f);
	return found;
}

int main(int argc, char **argv)
{
	struct lldp_sock a, b, bad;
	uint8_t tx[LLDP_FRAME_MAX], rx[LLDP_FRAME_MAX + 64];
	struct lldp_local_info li = {
		.ifname = "rsA", .ttl = 120,
		.port_desc = "port A", .sys_name = "test", .sys_desc = "rawsock test",
	};
	struct lldp_msg msg;
	struct eth_view v;
	ssize_t n, flen;
	int trunc, outg, i;

	if (argc != 3) {
		fprintf(stderr, "usage: %s <ifA> <ifB>\n", argv[0]);
		return 2;
	}

	/* open errors */
	CHECK(lldp_sock_open(&bad, "does-not-exist0", NULL) == -1);
	CHECK(lldp_sock_open(&bad, "lo", NULL) == -1);           /* not Ethernet */
	CHECK(bad.fd == -1);

	CHECK(lldp_sock_open(&a, argv[1], NULL) == 0);
	CHECK(lldp_sock_open(&b, argv[2], NULL) == 0);
	if (t_failures)
		return test_report("test_rawsock");

	/* SIOCGIFHWADDR result matches what the Makefile assigned */
	{
		const uint8_t want_a[6] = { 0x02, 0, 0, 0, 0xaa, 0x01 };
		CHECK_MEM(a.mac, want_a, 6);
	}
	CHECK(a.ifindex > 0 && b.ifindex > 0 && a.ifindex != b.ifindex);

	/* PACKET_ADD_MEMBERSHIP programmed the device multicast list */
	CHECK(mcast_joined(argv[1], "0180c200000e"));
	CHECK(mcast_joined(argv[2], "0180c200000e"));

	/* 1. LLDP frame A -> B arrives byte-identical and parses */
	memcpy(li.chassis_mac, a.mac, 6);
	memcpy(li.port_mac, a.mac, 6);
	li.ifname = argv[1];
	flen = lldp_frame_build(&li, tx, sizeof tx);
	CHECK(flen == 14 + 9 + 2 + 1 + (ssize_t)strlen(argv[1]) + 4 + 8 + 6 + 14 + 2);
	CHECK(lldp_sock_send(&a, tx, (size_t)flen) == 0);
	n = recv_wait(&b, rx, sizeof rx, 1000, &trunc, &outg);
	CHECK(n == flen);
	CHECK(!trunc && !outg);
	CHECK(n == flen && memcmp(rx, tx, (size_t)flen) == 0);
	CHECK(eth_frame_parse(rx, (size_t)n, &v) == 0);
	CHECK(v.ethertype == ETHERTYPE_LLDP);
	CHECK(lldpdu_parse(v.payload, v.payload_len, &msg) == LLDP_OK);
	CHECK(msg.ttl == 120 && msg.chassis.subtype == 4);

	/* 2. the sender sees its own frame only as PACKET_OUTGOING */
	for (i = 0; i < 4; i++) {
		n = recv_wait(&a, rx, sizeof rx, 100, &trunc, &outg);
		if (n == 0)
			break;
		CHECK(outg == 1);
	}

	/* 3. Ethertype filter: IPv4 / other frames are not delivered */
	{
		uint8_t f[60];
		memcpy(f, tx, 60);
		f[12] = 0x08; f[13] = 0x00;                   /* IPv4 */
		CHECK(send_any(a.ifindex, f, 60) == 0);
		f[12] = 0x88; f[13] = 0xb5;                   /* local experimental */
		CHECK(send_any(a.ifindex, f, 60) == 0);
		f[12] = 0x88; f[13] = 0xcd;                   /* off by one */
		CHECK(send_any(a.ifindex, f, 60) == 0);
		n = recv_wait(&b, rx, sizeof rx, 300, &trunc, &outg);
		CHECK(n == 0);
	}

	/* 4. a frame larger than the receive buffer is flagged truncated */
	{
		uint8_t big[1514];
		memset(big, 0x41, sizeof big);
		memcpy(big, tx, 14);
		CHECK(send_any(a.ifindex, big, sizeof big) == 0);
		n = recv_wait(&b, rx, 100, 1000, &trunc, &outg);
		CHECK(n == 100 && trunc == 1);
	}

	/* 5. B -> A direction also works */
	memcpy(li.chassis_mac, b.mac, 6);
	memcpy(li.port_mac, b.mac, 6);
	li.ifname = argv[2];
	flen = lldp_frame_build(&li, tx, sizeof tx);
	CHECK(lldp_sock_send(&b, tx, (size_t)flen) == 0);
	do {
		n = recv_wait(&a, rx, sizeof rx, 1000, &trunc, &outg);
	} while (n > 0 && outg);
	CHECK(n == flen && memcmp(rx, tx, (size_t)flen) == 0);

	/* 6. another LLDP group address (7.1): joined and used as destination */
	{
		struct lldp_sock c;
		struct eth_view cv;
		CHECK(!mcast_joined(argv[1], "0180c2000003"));
		CHECK(lldp_sock_open(&c, argv[1], LLDP_MCAST_NEAREST_NONTPMR) == 0);
		CHECK(mcast_joined(argv[1], "0180c2000003"));
		li.dst = LLDP_MCAST_NEAREST_NONTPMR;
		memcpy(li.port_mac, c.mac, 6);
		flen = lldp_frame_build(&li, tx, sizeof tx);
		CHECK(lldp_sock_send(&c, tx, (size_t)flen) == 0);
		do {
			n = recv_wait(&b, rx, sizeof rx, 1000, &trunc, &outg);
		} while (n > 0 && outg);
		CHECK(n == flen && eth_frame_parse(rx, (size_t)n, &cv) == 0);
		CHECK(n == flen && memcmp(cv.dst, LLDP_MCAST_NEAREST_NONTPMR, 6) == 0);
		lldp_sock_close(&c);
		li.dst = NULL;
		CHECK(strcmp(lldp_group_name(LLDP_MCAST_NEAREST_CUSTOMER), "nearest-customer") == 0);
		CHECK(lldp_group_by_name("nearest-nontpmr") == LLDP_MCAST_NEAREST_NONTPMR);
		CHECK(lldp_group_by_name("bogus") == NULL);
	}

	/* nothing pending returns 0, not an error */
	while (lldp_sock_recv(&b, rx, sizeof rx, &trunc, &outg) > 0)
		;
	CHECK(lldp_sock_recv(&b, rx, sizeof rx, &trunc, &outg) == 0);

	lldp_sock_close(&a);
	lldp_sock_close(&b);
	lldp_sock_close(&b);                               /* idempotent */
	return test_report("test_rawsock");
}
