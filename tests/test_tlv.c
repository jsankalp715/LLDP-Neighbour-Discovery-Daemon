/* test_tlv.c - unit tests for the TLV layer (802.1AB clause 8.4/8.5) */
#include "test.h"
#include "../src/tlv.h"

#include <stdint.h>

static void test_hdr_known_values(void)
{
	uint8_t h[2];
	unsigned type, len;

	/* hand-computed: (type << 9) | len, big-endian */
	CHECK(lldp_tlv_hdr_encode(h, 0, 0) == 0);
	CHECK(h[0] == 0x00 && h[1] == 0x00);
	CHECK(lldp_tlv_hdr_encode(h, 1, 7) == 0);           /* chassis MAC */
	CHECK(h[0] == 0x02 && h[1] == 0x07);
	CHECK(lldp_tlv_hdr_encode(h, 3, 2) == 0);           /* TTL */
	CHECK(h[0] == 0x06 && h[1] == 0x02);
	CHECK(lldp_tlv_hdr_encode(h, 4, 256) == 0);         /* 9th length bit */
	CHECK(h[0] == 0x09 && h[1] == 0x00);
	CHECK(lldp_tlv_hdr_encode(h, 127, 511) == 0);       /* all ones */
	CHECK(h[0] == 0xff && h[1] == 0xff);

	h[0] = 0x0b; h[1] = 0x45;                           /* 0000101 101000101 */
	lldp_tlv_hdr_decode(h, &type, &len);
	CHECK(type == 5 && len == 0x145);
}

static void test_hdr_roundtrip_exhaustive(void)
{
	uint8_t h[2];
	unsigned type, len, t2, l2;
	int ok = 1;

	for (type = 0; type <= LLDP_TLV_TYPE_MAX; type++)
		for (len = 0; len <= LLDP_TLV_LEN_MAX; len++) {
			if (lldp_tlv_hdr_encode(h, type, len) != 0) { ok = 0; continue; }
			lldp_tlv_hdr_decode(h, &t2, &l2);
			if (t2 != type || l2 != len) ok = 0;
		}
	CHECK(ok);
}

static void test_hdr_overflow(void)
{
	uint8_t h[2] = { 0xaa, 0xbb };

	CHECK(lldp_tlv_hdr_encode(h, 128, 0) == -1);
	CHECK(lldp_tlv_hdr_encode(h, 0, 512) == -1);
	CHECK(lldp_tlv_hdr_encode(h, 1000, 1000) == -1);
	CHECK(h[0] == 0xaa && h[1] == 0xbb);                /* untouched */
}

static void test_builders(void)
{
	uint8_t mem[128];
	struct lldp_buf b;
	const uint8_t mac[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
	static const uint8_t expect[] = {
		0x02, 0x07, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, /* chassis */
		0x04, 0x05, 0x05, 'e', 't', 'h', '0',                  /* port id */
		0x06, 0x02, 0x00, 0x78,                                /* TTL 120 */
		0x08, 0x02, 'p', '1',                                  /* port desc */
		0x0a, 0x03, 'h', 'o', 's',                             /* sys name */
		0x0c, 0x00,                                            /* sys desc "" */
		0x00, 0x00,                                            /* end */
	};

	lldp_buf_init(&b, mem, sizeof mem);
	CHECK(lldp_tlv_put_chassis_mac(&b, mac) == 0);
	CHECK(lldp_tlv_put_port_ifname(&b, "eth0") == 0);
	CHECK(lldp_tlv_put_ttl(&b, 120) == 0);
	CHECK(lldp_tlv_put_port_desc(&b, "p1") == 0);
	CHECK(lldp_tlv_put_sys_name(&b, "hos") == 0);
	CHECK(lldp_tlv_put_sys_desc(&b, "") == 0);
	CHECK(lldp_tlv_put_end(&b) == 0);
	CHECK(b.err == 0);
	CHECK(b.len == sizeof expect);
	CHECK_MEM(mem, expect, sizeof expect);
}

static void test_sys_cap_and_mgmt_builders(void)
{
	uint8_t mem[64];
	struct lldp_buf b;
	const uint8_t v4[4] = { 192, 0, 2, 1 };
	static const uint8_t expect[] = {
		/* System Capabilities: type 7, len 4 -> 0x0e04; station / station */
		0x0e, 0x04, 0x00, 0x80, 0x00, 0x80,
		/* Management Address: type 8, len 12 -> 0x100c
		 * asl 5 | IPv4 (1) | 192.0.2.1 | ifIndex (2) | 2 | OID len 0 */
		0x10, 0x0c, 0x05, 0x01, 0xc0, 0x00, 0x02, 0x01,
		0x02, 0x00, 0x00, 0x00, 0x02, 0x00,
	};
	uint8_t big[32];

	lldp_buf_init(&b, mem, sizeof mem);
	CHECK(lldp_tlv_put_sys_cap(&b, LLDP_CAP_STATION, LLDP_CAP_STATION) == 0);
	CHECK(lldp_tlv_put_mgmt_addr(&b, LLDP_AF_IPV4, v4, 4, LLDP_IFNUM_IFINDEX, 2) == 0);
	CHECK(b.err == 0 && b.len == sizeof expect);
	CHECK_MEM(mem, expect, sizeof expect);

	/* interface number is big-endian, all 32 bits */
	lldp_buf_init(&b, mem, sizeof mem);
	CHECK(lldp_tlv_put_mgmt_addr(&b, LLDP_AF_IPV4, v4, 4, 3, 0x01020304u) == 0);
	CHECK(mem[9] == 0x01 && mem[10] == 0x02 && mem[11] == 0x03 && mem[12] == 0x04);

	/* address length 1..31 (8.5.9.4) */
	memset(big, 0xab, sizeof big);
	lldp_buf_init(&b, mem, sizeof mem);
	CHECK(lldp_tlv_put_mgmt_addr(&b, 99, big, 31, 1, 0) == 0);
	CHECK(b.len == 2 + 1 + 1 + 31 + 1 + 4 + 1);
	lldp_buf_init(&b, mem, sizeof mem);
	CHECK(lldp_tlv_put_mgmt_addr(&b, 99, big, 32, 1, 0) == -1);
	lldp_buf_init(&b, mem, sizeof mem);
	CHECK(lldp_tlv_put_mgmt_addr(&b, 99, big, 0, 1, 0) == -1);
	lldp_buf_init(&b, mem, sizeof mem);
	CHECK(lldp_tlv_put_mgmt_addr(&b, 99, NULL, 4, 1, 0) == -1);
}

static void test_org_builders(void)
{
	uint8_t mem[600], info[508];
	struct lldp_buf b;
	static const uint8_t expect[] = {
		/* org TLV: type 127, len 6 -> 0xfe06; 802.3 OUI 00-12-0F, MFS (4), 1518 */
		0xfe, 0x06, 0x00, 0x12, 0x0f, 0x04, 0x05, 0xee,
		/* 802.1 OUI 00-80-C2, Port VLAN ID (1), PVID 100 */
		0xfe, 0x06, 0x00, 0x80, 0xc2, 0x01, 0x00, 0x64,
	};

	lldp_buf_init(&b, mem, sizeof mem);
	CHECK(lldp_tlv_put_dot3_mfs(&b, 1518) == 0);
	CHECK(lldp_tlv_put_org(&b, LLDP_OUI_IEEE_8021, LLDP_8021_PORT_VLAN_ID, "\x00\x64", 2) == 0);
	CHECK(b.err == 0 && b.len == sizeof expect);
	CHECK_MEM(mem, expect, sizeof expect);

	memset(info, 0x5a, sizeof info);
	lldp_buf_init(&b, mem, sizeof mem);
	CHECK(lldp_tlv_put_org(&b, 0xabcdef, 9, info, 507) == 0);  /* TLV len 511 */
	CHECK(mem[0] == 0xff && mem[1] == 0xff);
	lldp_buf_init(&b, mem, sizeof mem);
	CHECK(lldp_tlv_put_org(&b, 0xabcdef, 9, info, 508) == -1);
	lldp_buf_init(&b, mem, sizeof mem);
	CHECK(lldp_tlv_put_org(&b, 0x1000000, 1, NULL, 0) == -1); /* OUI is 24 bits */
	lldp_buf_init(&b, mem, sizeof mem);
	CHECK(lldp_tlv_put_org(&b, 1, 1, NULL, 1) == -1);
	lldp_buf_init(&b, mem, sizeof mem);
	CHECK(lldp_tlv_put_org(&b, 1, 1, NULL, 0) == 0 && b.len == 6);
}

static void test_builder_limits(void)
{
	uint8_t mem[600];
	char big[300];
	struct lldp_buf b;

	memset(big, 'x', sizeof big);

	/* exactly 255 is legal for strings, 256 is not (8.5.5-8.5.7) */
	big[255] = '\0';
	lldp_buf_init(&b, mem, sizeof mem);
	CHECK(lldp_tlv_put_sys_desc(&b, big) == 0);
	CHECK(b.len == 2 + 255);
	big[255] = 'x'; big[256] = '\0';
	lldp_buf_init(&b, mem, sizeof mem);
	CHECK(lldp_tlv_put_sys_desc(&b, big) == -1);
	CHECK(b.err == 1);

	/* empty ID is illegal (1..255 octets, 8.5.2.3 / 8.5.3.3) */
	lldp_buf_init(&b, mem, sizeof mem);
	CHECK(lldp_tlv_put_port_ifname(&b, "") == -1);
	lldp_buf_init(&b, mem, sizeof mem);
	CHECK(lldp_tlv_put_id(&b, LLDP_TLV_PORT_ID, 7, big, 255) == 0);
	CHECK(b.len == 2 + 256);
	CHECK(mem[0] == 0x05 && mem[1] == 0x00);            /* type 2, len 256 */
	lldp_buf_init(&b, mem, sizeof mem);
	CHECK(lldp_tlv_put_id(&b, LLDP_TLV_PORT_ID, 7, big, 256) == -1);

	/* generic put rejects > 511 */
	lldp_buf_init(&b, mem, sizeof mem);
	CHECK(lldp_tlv_put(&b, 127, mem, 512) == -1);
	lldp_buf_init(&b, mem, sizeof mem);
	CHECK(lldp_tlv_put(&b, 128, NULL, 0) == -1);
	lldp_buf_init(&b, mem, sizeof mem);
	CHECK(lldp_tlv_put(&b, 1, NULL, 3) == -1);

	/* capacity: exactly fits, then one more fails and latches */
	lldp_buf_init(&b, mem, 4);
	CHECK(lldp_tlv_put_ttl(&b, 1) == 0);
	CHECK(b.len == 4);
	CHECK(lldp_tlv_put_end(&b) == -1);
	CHECK(b.err == 1);
	lldp_buf_init(&b, mem, 3);
	CHECK(lldp_tlv_put_ttl(&b, 1) == -1);
	CHECK(b.len == 0);
	/* latched: even a fitting write is refused afterwards */
	b.cap = sizeof mem;
	CHECK(lldp_tlv_put_end(&b) == -1);
}

static void test_iter_roundtrip(void)
{
	uint8_t mem[64];
	struct lldp_buf b;
	struct lldp_tlv_iter it;
	struct lldp_tlv t;
	const uint8_t mac[6] = { 1, 2, 3, 4, 5, 6 };

	lldp_buf_init(&b, mem, sizeof mem);
	lldp_tlv_put_chassis_mac(&b, mac);
	lldp_tlv_put_port_ifname(&b, "veth0");
	lldp_tlv_put_ttl(&b, 0xbeef);
	lldp_tlv_put_end(&b);
	CHECK(b.err == 0);

	lldp_tlv_iter_init(&it, mem, b.len);
	CHECK(lldp_tlv_next(&it, &t) == 1);
	CHECK(t.type == 1 && t.len == 7 && t.value[0] == 4);
	CHECK_MEM(t.value + 1, mac, 6);
	CHECK(lldp_tlv_next(&it, &t) == 1);
	CHECK(t.type == 2 && t.len == 6 && t.value[0] == 5);
	CHECK_MEM(t.value + 1, "veth0", 5);
	CHECK(lldp_tlv_next(&it, &t) == 1);
	CHECK(t.type == 3 && t.len == 2);
	CHECK(t.value[0] == 0xbe && t.value[1] == 0xef);
	CHECK(lldp_tlv_next(&it, &t) == 1);
	CHECK(t.type == 0 && t.len == 0);
	CHECK(lldp_tlv_next(&it, &t) == 0);
	CHECK(lldp_tlv_next(&it, &t) == 0);                  /* stays at end */
}

static void test_iter_malformed(void)
{
	struct lldp_tlv_iter it;
	struct lldp_tlv t;
	static const uint8_t one_byte[] = { 0x02 };
	static const uint8_t overrun[]  = { 0x02, 0x07, 0x04, 0x01, 0x02 };
	static const uint8_t max_len[]  = { 0xff, 0xff };    /* claims 511 */
	static const uint8_t good_then_trunc[] = { 0x06, 0x02, 0x00, 0x10, 0x00 };

	lldp_tlv_iter_init(&it, one_byte, sizeof one_byte);
	CHECK(lldp_tlv_next(&it, &t) == -1);

	lldp_tlv_iter_init(&it, overrun, sizeof overrun);
	CHECK(lldp_tlv_next(&it, &t) == -1);

	lldp_tlv_iter_init(&it, max_len, sizeof max_len);
	CHECK(lldp_tlv_next(&it, &t) == -1);

	lldp_tlv_iter_init(&it, good_then_trunc, sizeof good_then_trunc);
	CHECK(lldp_tlv_next(&it, &t) == 1);
	CHECK(lldp_tlv_next(&it, &t) == -1);

	lldp_tlv_iter_init(&it, NULL, 10);
	CHECK(lldp_tlv_next(&it, &t) == 0);
}

int main(void)
{
	RUN(test_hdr_known_values);
	RUN(test_hdr_roundtrip_exhaustive);
	RUN(test_hdr_overflow);
	RUN(test_builders);
	RUN(test_sys_cap_and_mgmt_builders);
	RUN(test_org_builders);
	RUN(test_builder_limits);
	RUN(test_iter_roundtrip);
	RUN(test_iter_malformed);
	return test_report("test_tlv");
}
