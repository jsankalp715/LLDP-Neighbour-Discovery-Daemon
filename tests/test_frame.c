/* test_frame.c - Ethernet frame layer tests (802.1AB clause 7) */
#include "test.h"
#include "../src/frame.h"
#include "../src/lldpdu.h"

#include <errno.h>

/*
 * Hand-computed expected frame for:
 *   MAC 02:00:00:00:00:01, port "eth0", TTL 121,
 *   port desc "uplink", sys name "ns1", sys desc "Linux".
 * TLV header = (type << 9) | length, big-endian.
 */
static const uint8_t expected_frame[60] = {
	/* dst: nearest bridge group address (7.1) */
	0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e,
	/* src */
	0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
	/* EtherType 0x88CC (7.2) */
	0x88, 0xcc,
	/* Chassis ID: type 1, len 7 -> 0x0207; subtype 4 (MAC) */
	0x02, 0x07, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
	/* Port ID: type 2, len 5 -> 0x0405; subtype 5 (ifName) "eth0" */
	0x04, 0x05, 0x05, 0x65, 0x74, 0x68, 0x30,
	/* TTL: type 3, len 2 -> 0x0602; 121 = 0x0079 */
	0x06, 0x02, 0x00, 0x79,
	/* Port Description: type 4, len 6 -> 0x0806; "uplink" */
	0x08, 0x06, 0x75, 0x70, 0x6c, 0x69, 0x6e, 0x6b,
	/* System Name: type 5, len 3 -> 0x0a03; "ns1" */
	0x0a, 0x03, 0x6e, 0x73, 0x31,
	/* System Description: type 6, len 5 -> 0x0c05; "Linux" */
	0x0c, 0x05, 0x4c, 0x69, 0x6e, 0x75, 0x78,
	/* End Of LLDPDU: 0x0000 */
	0x00, 0x00,
	/* 14 + 42 = 56 octets, zero-padded to the 60-octet minimum */
	0x00, 0x00, 0x00, 0x00,
};

/* Shutdown LLDPDU (TTL 0): mandatory TLVs only, padded to 60 */
static const uint8_t expected_shutdown[60] = {
	0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e,
	0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
	0x88, 0xcc,
	0x02, 0x07, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
	0x04, 0x05, 0x05, 0x65, 0x74, 0x68, 0x30,
	0x06, 0x02, 0x00, 0x00,
	0x00, 0x00,
	/* 36 octets of content, 24 of padding */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

static struct lldp_local_info sample(void)
{
	struct lldp_local_info li = {
		.chassis_mac = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 },
		.port_mac = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 },
		.ifname = "eth0",
		.ttl = 121,
		.port_desc = "uplink",
		.sys_name = "ns1",
		.sys_desc = "Linux",
	};
	return li;
}

static void test_full_frame_bytes(void)
{
	uint8_t out[LLDP_FRAME_MAX];
	struct lldp_local_info li = sample();
	ssize_t n;
	size_t i;

	memset(out, 0xa5, sizeof out);   /* make sure padding is written */
	n = lldp_frame_build(&li, out, sizeof out);
	CHECK(n == 60);
	CHECK_MEM(out, expected_frame, sizeof expected_frame);
	for (i = 0; n == 60 && i < 60; i++)
		if (out[i] != expected_frame[i])
			fprintf(stderr, "  byte %zu: got %02x want %02x\n",
				i, out[i], expected_frame[i]);
}

static void test_shutdown_frame_bytes(void)
{
	uint8_t out[LLDP_FRAME_MAX];
	struct lldp_local_info li = sample();

	li.ttl = 0;
	CHECK(lldp_frame_build(&li, out, sizeof out) == 60);
	CHECK_MEM(out, expected_shutdown, sizeof expected_shutdown);
}

static void test_no_padding_when_large(void)
{
	uint8_t out[LLDP_FRAME_MAX];
	struct lldp_local_info li = sample();
	char desc[201];
	ssize_t n;

	memset(desc, 'd', 200);
	desc[200] = '\0';
	li.sys_desc = desc;
	n = lldp_frame_build(&li, out, sizeof out);
	/* 14 + 9 + 7 + 4 + 8 + 5 + (2+200) + 2 */
	CHECK(n == 14 + 9 + 7 + 4 + 8 + 5 + 202 + 2);
	CHECK(out[n - 2] == 0 && out[n - 1] == 0);           /* ends with End */
	CHECK(out[n - 3] == 'd');
}

static void test_eth_build_limits(void)
{
	uint8_t out[LLDP_FRAME_MAX + 10];
	uint8_t payload[ETH_MAX_PAYLOAD + 1];
	const uint8_t a[6] = { 1, 2, 3, 4, 5, 6 };

	memset(payload, 0x11, sizeof payload);
	CHECK(eth_frame_build(out, sizeof out, a, a, 0x88cc, payload,
			      ETH_MAX_PAYLOAD) == (ssize_t)LLDP_FRAME_MAX);
	CHECK(eth_frame_build(out, sizeof out, a, a, 0x88cc, payload,
			      ETH_MAX_PAYLOAD + 1) == -1);
	CHECK(eth_frame_build(out, 59, a, a, 0x88cc, payload, 1) == -1);
	CHECK(eth_frame_build(out, 60, a, a, 0x88cc, payload, 1) == 60);
	CHECK(eth_frame_build(out, 60, a, a, 0x88cc, NULL, 0) == 60);
	CHECK(eth_frame_build(out, 60, a, a, 0x88cc, NULL, 5) == -1);
	/* an LLDPDU that cannot fit in the caller's buffer */
	{
		struct lldp_local_info li = sample();
		CHECK(lldp_frame_build(&li, out, 59) == -1);
	}
}

static void test_eth_parse(void)
{
	struct eth_view v;

	CHECK(eth_frame_parse(expected_frame, 13, &v) == -1);
	CHECK(eth_frame_parse(NULL, 60, &v) == -1);
	CHECK(eth_frame_parse(expected_frame, 14, &v) == 0);
	CHECK(v.payload_len == 0);
	CHECK(eth_frame_parse(expected_frame, sizeof expected_frame, &v) == 0);
	CHECK(v.ethertype == ETHERTYPE_LLDP);
	CHECK_MEM(v.dst, LLDP_MCAST_NEAREST_BRIDGE, 6);
	CHECK(v.src[5] == 0x01);
	CHECK(v.payload == expected_frame + 14 && v.payload_len == 46);
}

static void test_ifmac(void)
{
	uint8_t mac[6];
	char s[18];

	/* loopback is not ARPHRD_ETHER, nonexistent interface fails */
	CHECK(eth_get_ifmac("lo", mac) == -1);
	CHECK(eth_get_ifmac("no-such-if0", mac) == -1);
	CHECK(eth_get_ifmac("this-name-is-far-too-long", mac) == -1 &&
	      errno == ENAMETOOLONG);
	eth_ntoa(expected_frame + 6, s);
	CHECK(strcmp(s, "02:00:00:00:00:01") == 0);
}

int main(void)
{
	RUN(test_full_frame_bytes);
	RUN(test_shutdown_frame_bytes);
	RUN(test_no_padding_when_large);
	RUN(test_eth_build_limits);
	RUN(test_eth_parse);
	RUN(test_ifmac);
	return test_report("test_frame");
}
