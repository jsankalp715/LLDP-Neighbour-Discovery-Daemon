/* test_lldpdu.c - receive-side LLDPDU validation tests (802.1AB 8.2, 8.5, 9.2.7) */
#include "test.h"
#include "../src/lldpdu.h"

static const uint8_t MAC[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x07 };

/* Raw TLV assembly helpers that bypass the builders' own validation. */
struct pdu { uint8_t b[2048]; size_t n; };

static void raw(struct pdu *p, unsigned type, unsigned len, const void *v)
{
	lldp_tlv_hdr_encode(p->b + p->n, type, len);
	if (len)
		memcpy(p->b + p->n + 2, v, len);
	p->n += 2 + len;
}

static void chassis(struct pdu *p)
{
	uint8_t v[7] = { 4 };
	memcpy(v + 1, MAC, 6);
	raw(p, 1, 7, v);
}
static void port(struct pdu *p)  { raw(p, 2, 5, "\x05" "eth0"); }
static void ttl(struct pdu *p, uint16_t s)
{
	uint8_t v[2] = { (uint8_t)(s >> 8), (uint8_t)s };
	raw(p, 3, 2, v);
}
static void end(struct pdu *p)   { raw(p, 0, 0, NULL); }
static void mandatory(struct pdu *p) { chassis(p); port(p); ttl(p, 120); }

static int parse(const struct pdu *p)
{
	struct lldp_msg m;
	return lldpdu_parse(p->b, p->n, &m);
}

static void test_roundtrip_builder(void)
{
	uint8_t buf[1500];
	struct lldp_local_info li = {
		.chassis_mac = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff },
		.port_mac = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01 },
		.ifname = "veth-ns1", .ttl = 4321,
		.port_desc = "to bridge", .sys_name = "host-1",
		.sys_desc = "Linux 6.6 x86_64",
	};
	struct lldp_msg m;
	ssize_t n = lldpdu_build(&li, buf, sizeof buf);

	CHECK(n > 0);
	CHECK(lldpdu_parse(buf, (size_t)n, &m) == LLDP_OK);
	CHECK(m.chassis.subtype == LLDP_CHASSIS_MAC && m.chassis.len == 6);
	CHECK_MEM(m.chassis.id, li.chassis_mac, 6);
	CHECK(m.port.subtype == LLDP_PORT_IF_NAME && m.port.len == 8);
	CHECK_MEM(m.port.id, "veth-ns1", 8);
	CHECK(m.ttl == 4321);
	CHECK(m.port_desc.present && m.port_desc.len == 9);
	CHECK_MEM(m.port_desc.s, "to bridge", 9);
	CHECK(m.sys_name.present && m.sys_name.len == 6);
	CHECK_MEM(m.sys_name.s, "host-1", 6);
	CHECK(m.sys_desc.present && m.sys_desc.len == 16);
	CHECK(!m.has_sys_cap && m.n_unknown_tlvs == 0);

	/* optional TLVs omitted */
	li.port_desc = li.sys_name = li.sys_desc = NULL;
	n = lldpdu_build(&li, buf, sizeof buf);
	CHECK(n == 9 + 11 + 4 + 2);
	CHECK(lldpdu_parse(buf, (size_t)n, &m) == LLDP_OK);
	CHECK(!m.port_desc.present && !m.sys_name.present && !m.sys_desc.present);

	/* shutdown LLDPDU parses with TTL 0 */
	li.ttl = 0;
	li.sys_name = "ignored";
	n = lldpdu_build(&li, buf, sizeof buf);
	CHECK(lldpdu_parse(buf, (size_t)n, &m) == LLDP_OK);
	CHECK(m.ttl == 0 && !m.sys_name.present);
}

static void test_accepts(void)
{
	struct pdu p;
	struct lldp_msg m;

	/* padding after End is ignored */
	memset(&p, 0, sizeof p); mandatory(&p); end(&p); p.n += 20;
	CHECK(parse(&p) == LLDP_OK);
	/* even non-zero junk after End */
	memset(&p, 0, sizeof p); mandatory(&p); end(&p);
	memset(p.b + p.n, 0xff, 7); p.n += 7;
	CHECK(parse(&p) == LLDP_OK);

	/* reserved types 9..126 are skipped and counted */
	memset(&p, 0, sizeof p); mandatory(&p);
	raw(&p, 9, 3, "abc"); raw(&p, 126, 0, NULL); end(&p);
	CHECK(lldpdu_parse(p.b, p.n, &m) == LLDP_OK);
	CHECK(m.n_unknown_tlvs == 2);

	/* org-specific (802.1 OUI) + system capabilities + mgmt addr */
	memset(&p, 0, sizeof p); mandatory(&p);
	raw(&p, 127, 6, "\x00\x80\xc2\x01\x00\x01");
	raw(&p, 7, 4, "\x00\x14\x00\x04");
	/* mgmt: asl=5 (IPv4 subtype 1 + 4 octets), ifIndex, OID len 0 */
	raw(&p, 8, 12, "\x05\x01\x0a\x00\x00\x01\x02\x00\x00\x00\x03\x00");
	raw(&p, 8, 12, "\x05\x01\x0a\x00\x00\x02\x02\x00\x00\x00\x03\x00");
	end(&p);
	CHECK(lldpdu_parse(p.b, p.n, &m) == LLDP_OK);
	CHECK(m.n_org_tlvs == 1 && m.n_mgmt_addr == 2);
	CHECK(m.has_sys_cap && m.sys_cap == 0x14 && m.sys_cap_enabled == 0x04);

	/* boundary lengths: 255-octet strings and IDs, 0-octet strings */
	{
		uint8_t big[256];
		memset(big, 'z', sizeof big);
		big[0] = 7;                                   /* locally assigned */
		memset(&p, 0, sizeof p);
		raw(&p, 1, 256, big); raw(&p, 2, 256, big); ttl(&p, 1);
		raw(&p, 4, 255, big + 1); raw(&p, 5, 0, NULL); raw(&p, 6, 255, big);
		end(&p);
		CHECK(lldpdu_parse(p.b, p.n, &m) == LLDP_OK);
		CHECK(m.chassis.len == 255 && m.port.len == 255);
		CHECK(m.port_desc.len == 255 && m.sys_name.present && m.sys_name.len == 0);
	}

	/* TTL 0 and 65535 */
	memset(&p, 0, sizeof p); chassis(&p); port(&p); ttl(&p, 0); end(&p);
	CHECK(lldpdu_parse(p.b, p.n, &m) == LLDP_OK && m.ttl == 0);
	memset(&p, 0, sizeof p); chassis(&p); port(&p); ttl(&p, 65535); end(&p);
	CHECK(lldpdu_parse(p.b, p.n, &m) == LLDP_OK && m.ttl == 65535);
}

static void test_missing_and_order(void)
{
	struct pdu p;

	memset(&p, 0, sizeof p);
	CHECK(parse(&p) == LLDP_E_FIRST_NOT_CHASSIS);           /* empty */
	end(&p);
	CHECK(parse(&p) == LLDP_E_FIRST_NOT_CHASSIS);           /* only End */

	memset(&p, 0, sizeof p); chassis(&p);
	CHECK(parse(&p) == LLDP_E_SECOND_NOT_PORT);
	memset(&p, 0, sizeof p); chassis(&p); port(&p);
	CHECK(parse(&p) == LLDP_E_THIRD_NOT_TTL);
	memset(&p, 0, sizeof p); mandatory(&p);
	CHECK(parse(&p) == LLDP_E_MISSING_END);
	memset(&p, 0, sizeof p); mandatory(&p); raw(&p, 5, 2, "hi");
	CHECK(parse(&p) == LLDP_E_MISSING_END);

	/* wrong orders */
	memset(&p, 0, sizeof p); port(&p); chassis(&p); ttl(&p, 1); end(&p);
	CHECK(parse(&p) == LLDP_E_FIRST_NOT_CHASSIS);
	memset(&p, 0, sizeof p); chassis(&p); ttl(&p, 1); port(&p); end(&p);
	CHECK(parse(&p) == LLDP_E_SECOND_NOT_PORT);
	memset(&p, 0, sizeof p); chassis(&p); port(&p); raw(&p, 5, 1, "x"); ttl(&p, 1); end(&p);
	CHECK(parse(&p) == LLDP_E_THIRD_NOT_TTL);
	memset(&p, 0, sizeof p); chassis(&p); port(&p); end(&p);
	CHECK(parse(&p) == LLDP_E_THIRD_NOT_TTL);
	memset(&p, 0, sizeof p); raw(&p, 5, 1, "x"); mandatory(&p); end(&p);
	CHECK(parse(&p) == LLDP_E_FIRST_NOT_CHASSIS);

	/* mandatory TLVs repeated */
	memset(&p, 0, sizeof p); mandatory(&p); chassis(&p); end(&p);
	CHECK(parse(&p) == LLDP_E_DUP_MANDATORY);
	memset(&p, 0, sizeof p); mandatory(&p); port(&p); end(&p);
	CHECK(parse(&p) == LLDP_E_DUP_MANDATORY);
	memset(&p, 0, sizeof p); mandatory(&p); ttl(&p, 5); end(&p);
	CHECK(parse(&p) == LLDP_E_DUP_MANDATORY);

	/* single-instance optional TLVs repeated */
	memset(&p, 0, sizeof p); mandatory(&p); raw(&p, 5, 1, "a"); raw(&p, 5, 1, "b"); end(&p);
	CHECK(parse(&p) == LLDP_E_DUP_OPTIONAL);
	memset(&p, 0, sizeof p); mandatory(&p); raw(&p, 4, 0, NULL); raw(&p, 4, 0, NULL); end(&p);
	CHECK(parse(&p) == LLDP_E_DUP_OPTIONAL);
	memset(&p, 0, sizeof p); mandatory(&p); raw(&p, 6, 1, "a"); raw(&p, 6, 1, "a"); end(&p);
	CHECK(parse(&p) == LLDP_E_DUP_OPTIONAL);
	memset(&p, 0, sizeof p); mandatory(&p);
	raw(&p, 7, 4, "\0\0\0\0"); raw(&p, 7, 4, "\0\0\0\0"); end(&p);
	CHECK(parse(&p) == LLDP_E_DUP_OPTIONAL);
}

static void test_bad_lengths(void)
{
	struct pdu p;
	uint8_t big[LLDP_TLV_LEN_MAX];   /* largest value any 9-bit length can claim */

	memset(big, 'q', sizeof big);

	/* truncation: TLV length runs past the end of the frame */
	memset(&p, 0, sizeof p); mandatory(&p); end(&p);
	CHECK(lldpdu_parse(p.b, 8, &(struct lldp_msg){0}) == LLDP_E_TRUNCATED);
	CHECK(lldpdu_parse(p.b, 1, &(struct lldp_msg){0}) == LLDP_E_TRUNCATED);
	CHECK(lldpdu_parse(p.b, p.n - 1, &(struct lldp_msg){0}) == LLDP_E_TRUNCATED);
	memset(&p, 0, sizeof p); mandatory(&p);
	lldp_tlv_hdr_encode(p.b + p.n, 5, 100); p.n += 2 + 10;  /* claims 100, has 10 */
	CHECK(parse(&p) == LLDP_E_TRUNCATED);

	/* End Of LLDPDU with a length */
	memset(&p, 0, sizeof p); mandatory(&p); raw(&p, 0, 1, "x");
	CHECK(parse(&p) == LLDP_E_BAD_END);

	/* Chassis ID: too short, bad subtypes, wrong MAC length, too long */
	memset(&p, 0, sizeof p); raw(&p, 1, 1, "\x04"); port(&p); ttl(&p, 1); end(&p);
	CHECK(parse(&p) == LLDP_E_BAD_CHASSIS);
	memset(&p, 0, sizeof p); raw(&p, 1, 0, NULL); port(&p); ttl(&p, 1); end(&p);
	CHECK(parse(&p) == LLDP_E_BAD_CHASSIS);
	memset(&p, 0, sizeof p); raw(&p, 1, 3, "\x00xy"); port(&p); ttl(&p, 1); end(&p);
	CHECK(parse(&p) == LLDP_E_BAD_CHASSIS);
	memset(&p, 0, sizeof p); raw(&p, 1, 3, "\x08xy"); port(&p); ttl(&p, 1); end(&p);
	CHECK(parse(&p) == LLDP_E_BAD_CHASSIS);
	memset(&p, 0, sizeof p); raw(&p, 1, 6, "\x04" "abcde"); port(&p); ttl(&p, 1); end(&p);
	CHECK(parse(&p) == LLDP_E_BAD_CHASSIS);
	memset(&p, 0, sizeof p); raw(&p, 1, 8, "\x04" "abcdefg"); port(&p); ttl(&p, 1); end(&p);
	CHECK(parse(&p) == LLDP_E_BAD_CHASSIS);
	memset(&p, 0, sizeof p); raw(&p, 1, 2, "\x05\x01"); port(&p); ttl(&p, 1); end(&p);
	CHECK(parse(&p) == LLDP_E_BAD_CHASSIS);                  /* netaddr: family only */
	big[0] = 7;
	memset(&p, 0, sizeof p); raw(&p, 1, 257, big); port(&p); ttl(&p, 1); end(&p);
	CHECK(parse(&p) == LLDP_E_BAD_CHASSIS);
	memset(&p, 0, sizeof p); raw(&p, 1, 511, big); port(&p); ttl(&p, 1); end(&p);
	CHECK(parse(&p) == LLDP_E_BAD_CHASSIS);

	/* Port ID */
	memset(&p, 0, sizeof p); chassis(&p); raw(&p, 2, 1, "\x05"); ttl(&p, 1); end(&p);
	CHECK(parse(&p) == LLDP_E_BAD_PORT);
	memset(&p, 0, sizeof p); chassis(&p); raw(&p, 2, 8, "\x03" "abcdefg"); ttl(&p, 1); end(&p);
	CHECK(parse(&p) == LLDP_E_BAD_PORT);                     /* MAC subtype, 7 octets */
	memset(&p, 0, sizeof p); chassis(&p); raw(&p, 2, 2, "\xff" "a"); ttl(&p, 1); end(&p);
	CHECK(parse(&p) == LLDP_E_BAD_PORT);
	memset(&p, 0, sizeof p); chassis(&p); raw(&p, 2, 257, big); ttl(&p, 1); end(&p);
	CHECK(parse(&p) == LLDP_E_BAD_PORT);

	/* TTL must be exactly 2 octets */
	memset(&p, 0, sizeof p); chassis(&p); port(&p); raw(&p, 3, 1, "\x01"); end(&p);
	CHECK(parse(&p) == LLDP_E_BAD_TTL);
	memset(&p, 0, sizeof p); chassis(&p); port(&p); raw(&p, 3, 3, "\x00\x01\x02"); end(&p);
	CHECK(parse(&p) == LLDP_E_BAD_TTL);
	memset(&p, 0, sizeof p); chassis(&p); port(&p); raw(&p, 3, 0, NULL); end(&p);
	CHECK(parse(&p) == LLDP_E_BAD_TTL);

	/* optional string TLVs > 255 octets */
	memset(&p, 0, sizeof p); mandatory(&p); raw(&p, 4, 256, big); end(&p);
	CHECK(parse(&p) == LLDP_E_BAD_LENGTH);
	memset(&p, 0, sizeof p); mandatory(&p); raw(&p, 5, 300, big); end(&p);
	CHECK(parse(&p) == LLDP_E_BAD_LENGTH);
	memset(&p, 0, sizeof p); mandatory(&p); raw(&p, 6, 511, big); end(&p);
	CHECK(parse(&p) == LLDP_E_BAD_LENGTH);

	/* system capabilities must be 4 */
	memset(&p, 0, sizeof p); mandatory(&p); raw(&p, 7, 3, "abc"); end(&p);
	CHECK(parse(&p) == LLDP_E_BAD_LENGTH);

	/* org-specific shorter than OUI + subtype */
	memset(&p, 0, sizeof p); mandatory(&p); raw(&p, 127, 3, "\x00\x80\xc2"); end(&p);
	CHECK(parse(&p) == LLDP_E_BAD_LENGTH);

	/* management address: inconsistent internal lengths */
	memset(&p, 0, sizeof p); mandatory(&p); raw(&p, 8, 8, "\x05\x01\x0a\x00\x00\x00\x00\x00"); end(&p);
	CHECK(parse(&p) == LLDP_E_BAD_LENGTH);                   /* too short */
	memset(&p, 0, sizeof p); mandatory(&p);
	raw(&p, 8, 12, "\x06\x01\x0a\x00\x00\x01\x02\x00\x00\x00\x03\x00"); end(&p);
	CHECK(parse(&p) == LLDP_E_BAD_LENGTH);                   /* asl off by one */
	memset(&p, 0, sizeof p); mandatory(&p);
	raw(&p, 8, 12, "\x05\x01\x0a\x00\x00\x01\x02\x00\x00\x00\x03\x05"); end(&p);
	CHECK(parse(&p) == LLDP_E_BAD_LENGTH);                   /* OID runs past TLV */
	memset(&p, 0, sizeof p); mandatory(&p);
	raw(&p, 8, 12, "\x01\x01\x0a\x00\x00\x01\x02\x00\x00\x00\x03\x00"); end(&p);
	CHECK(parse(&p) == LLDP_E_BAD_LENGTH);                   /* asl < 2 */
	memset(&p, 0, sizeof p); mandatory(&p);
	raw(&p, 8, 12, "\xff\x01\x0a\x00\x00\x01\x02\x00\x00\x00\x03\x00"); end(&p);
	CHECK(parse(&p) == LLDP_E_BAD_LENGTH);                   /* asl huge */
}

static void test_strerror_and_format(void)
{
	char out[64];
	int i, j;
	struct lldp_id id = { .subtype = LLDP_CHASSIS_MAC, .len = 6,
			      .id = { 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01 } };

	for (i = 0; i < LLDP_E_COUNT; i++) {
		CHECK(lldp_strerror(i) != NULL);
		for (j = 0; j < i; j++)
			CHECK(strcmp(lldp_strerror(i), lldp_strerror(j)) != 0);
	}
	CHECK(strcmp(lldp_strerror(-1), "unknown error") == 0);
	CHECK(strcmp(lldp_strerror(LLDP_E_COUNT), "unknown error") == 0);

	lldp_escape((const uint8_t *)"ok\x1b[2J\\\n\0z", 10, out, sizeof out);
	CHECK(strcmp(out, "ok\\x1b[2J\\x5c\\x0a\\x00z") == 0);
	/* never overflows: escape sequences are not split */
	lldp_escape((const uint8_t *)"ab\x01", 3, out, 6);
	CHECK(strcmp(out, "ab") == 0);
	lldp_escape((const uint8_t *)"abcdef", 6, out, 4);
	CHECK(strcmp(out, "abc") == 0);
	lldp_escape((const uint8_t *)"x", 1, out, 1);
	CHECK(out[0] == '\0');

	lldp_id_format(&id, 1, out, sizeof out);
	CHECK(strcmp(out, "de:ad:be:ef:00:01") == 0);
	lldp_id_format(&id, 0, out, sizeof out);                 /* port subtype 4 != MAC */
	CHECK(strcmp(out, "\\xde\\xad\\xbe\\xef\\x00\\x01(st4)") == 0);
	id.subtype = LLDP_PORT_IF_NAME; id.len = 4; memcpy(id.id, "eth0", 4);
	lldp_id_format(&id, 0, out, sizeof out);
	CHECK(strcmp(out, "eth0(st5)") == 0);
}

static void test_caps_and_mgmt(void)
{
	uint8_t buf[1500];
	struct lldp_local_info li = {
		.chassis_mac = { 0x02, 0, 0, 0, 0, 0x10 },
		.port_mac = { 0x02, 0, 0, 0, 0, 0x11 },
		.ifname = "eth0", .ttl = 120,
		.has_sys_cap = 1, .sys_cap = LLDP_CAP_BRIDGE | LLDP_CAP_ROUTER,
		.sys_cap_enabled = LLDP_CAP_ROUTER,
		.n_mgmt = 3,
		.mgmt = {
			{ LLDP_AF_IPV4, 4, { 192, 0, 2, 7 }, LLDP_IFNUM_IFINDEX, 5 },
			{ LLDP_AF_IPV6, 16, { 0x20, 0x01, 0x0d, 0xb8, [15] = 0x07 },
			  LLDP_IFNUM_IFINDEX, 5 },
			{ LLDP_AF_ALL802, 6, { 0x02, 0, 0, 0, 0, 0x11 }, LLDP_IFNUM_UNKNOWN, 0 },
		},
	};
	struct lldp_msg m;
	char out[LLDP_MGMTFMT_MAX];
	struct pdu p;
	ssize_t n;
	unsigned i;

	n = lldpdu_build(&li, buf, sizeof buf);
	CHECK(n > 0);
	CHECK(lldpdu_parse(buf, (size_t)n, &m) == LLDP_OK);
	CHECK(m.has_sys_cap && m.sys_cap == 0x14 && m.sys_cap_enabled == 0x10);
	CHECK(m.n_mgmt_addr == 3 && m.n_mgmt == 3);
	for (i = 0; i < 3; i++) {
		CHECK(m.mgmt[i].subtype == li.mgmt[i].subtype);
		CHECK(m.mgmt[i].len == li.mgmt[i].len);
		CHECK_MEM(m.mgmt[i].addr, li.mgmt[i].addr, li.mgmt[i].len);
		CHECK(m.mgmt[i].if_subtype == li.mgmt[i].if_subtype);
		CHECK(m.mgmt[i].if_number == li.mgmt[i].if_number);
	}
	lldp_mgmt_format(&m.mgmt[0], out, sizeof out);
	CHECK(strcmp(out, "192.0.2.7") == 0);
	lldp_mgmt_format(&m.mgmt[1], out, sizeof out);
	CHECK(strcmp(out, "2001:db8::7") == 0);
	lldp_mgmt_format(&m.mgmt[2], out, sizeof out);
	CHECK(strcmp(out, "mac 02:00:00:00:00:11") == 0);

	/* unknown family / wrong length falls back to hex */
	{
		struct lldp_mgmt odd = { 99, 3, { 0xde, 0xad, 0x01 }, 1, 0 };
		lldp_mgmt_format(&odd, out, sizeof out);
		CHECK(strcmp(out, "af99:dead01") == 0);
		odd.subtype = LLDP_AF_IPV4;               /* IPv4 but 3 octets */
		lldp_mgmt_format(&odd, out, sizeof out);
		CHECK(strcmp(out, "af1:dead01") == 0);
		lldp_mgmt_format(&odd, out, 5);           /* truncation is safe */
		CHECK(strlen(out) <= 4);
	}

	/* shutdown LLDPDU omits capabilities and addresses */
	li.ttl = 0;
	n = lldpdu_build(&li, buf, sizeof buf);
	CHECK(lldpdu_parse(buf, (size_t)n, &m) == LLDP_OK);
	CHECK(!m.has_sys_cap && m.n_mgmt_addr == 0);

	/* more Management Address TLVs than we store: all validated, 4 kept */
	memset(&p, 0, sizeof p); mandatory(&p);
	for (i = 0; i < 6; i++) {
		uint8_t v[12] = { 5, 1, 10, 0, 0, (uint8_t)i, 2, 0, 0, 0, 1, 0 };
		raw(&p, 8, sizeof v, v);
	}
	end(&p);
	CHECK(lldpdu_parse(p.b, p.n, &m) == LLDP_OK);
	CHECK(m.n_mgmt_addr == 6 && m.n_mgmt == LLDP_MAX_MGMT);
	CHECK(m.mgmt[3].addr[3] == 3);

	/* management address with an OID is accepted (OID not stored) */
	memset(&p, 0, sizeof p); mandatory(&p);
	raw(&p, 8, 15, "\x05\x01\x0a\x00\x00\x01\x02\x00\x00\x00\x03\x03\x2b\x06\x01");
	end(&p);
	CHECK(lldpdu_parse(p.b, p.n, &m) == LLDP_OK && m.n_mgmt == 1);
	CHECK(m.mgmt[0].if_number == 3);
}

static void test_extensions(void)
{
	struct pdu p;
	struct lldp_msg m;
	struct lldp_ext a, b;
	uint8_t vn[4 + 3 + 33];
	uint8_t buf[1500];
	ssize_t n;

	/* all five decoded extensions in one LLDPDU */
	memset(&p, 0, sizeof p); mandatory(&p);
	raw(&p, 127, 6, "\x00\x80\xc2\x01\x00\x64");                     /* PVID 100 */
	raw(&p, 127, 12, "\x00\x80\xc2\x03\x00\x64\x05voice");           /* VLAN 100 "voice" */
	raw(&p, 127, 10, "\x00\x80\xc2\x03\x00\xc8\x03" "dat");          /* 2nd name, counted */
	raw(&p, 127, 9, "\x00\x12\x0f\x01\x03\x6c\x01\x00\x10");         /* MAC/PHY */
	raw(&p, 127, 9, "\x00\x12\x0f\x03\x03\x00\x00\x00\x07");         /* LAG */
	raw(&p, 127, 6, "\x00\x12\x0f\x04\x05\xf2");                     /* MFS 1522 */
	end(&p);
	CHECK(lldpdu_parse(p.b, p.n, &m) == LLDP_OK);
	CHECK(m.n_org_tlvs == 6 && m.n_unknown_tlvs == 0);
	CHECK(m.ext.has_pvid && m.ext.pvid == 100);
	CHECK(m.ext.n_vlan_names == 2 && m.ext.vlan_id == 100 && m.ext.vlan_name_len == 5);
	CHECK_MEM(m.ext.vlan_name, "voice", 5);
	CHECK(m.ext.has_macphy && m.ext.autoneg == 3 && m.ext.pmd_cap == 0x6c01 &&
	      m.ext.mau_type == 16);
	CHECK(m.ext.has_lag && m.ext.lag_status == 3 && m.ext.lag_port_id == 7);
	CHECK(m.ext.has_mfs && m.ext.mfs == 1522);

	/* malformed, unknown and repeated extensions are ignored, never fatal */
	memset(&p, 0, sizeof p); mandatory(&p);
	raw(&p, 127, 5, "\x00\x80\xc2\x01\x00");                         /* PVID too short */
	raw(&p, 127, 7, "\x00\x12\x0f\x04\x05\xf2\x00");                 /* MFS too long */
	raw(&p, 127, 8, "\x00\x80\xc2\x03\x00\x01\x00x");                /* VLAN name len 0 */
	raw(&p, 127, 9, "\x00\x80\xc2\x03\x00\x01\x05" "ab");            /* name len lies */
	raw(&p, 127, 8, "\x00\x12\x0f\x01\x03\x00\x00\x00");             /* MAC/PHY short */
	raw(&p, 127, 6, "\x00\x12\x0f\x63\x00\x00");                     /* unknown subtype */
	raw(&p, 127, 6, "\xaa\xbb\xcc\x01\x00\x00");                     /* unknown OUI */
	raw(&p, 127, 6, "\x00\x12\x0f\x04\x05\xdc");                     /* MFS 1500 */
	raw(&p, 127, 6, "\x00\x12\x0f\x04\x23\x28");                     /* 2nd MFS ignored */
	end(&p);
	CHECK(lldpdu_parse(p.b, p.n, &m) == LLDP_OK);
	CHECK(m.n_org_tlvs == 9 && m.n_unknown_tlvs == 8);
	CHECK(!m.ext.has_pvid && m.ext.n_vlan_names == 0 && !m.ext.has_macphy);
	CHECK(m.ext.has_mfs && m.ext.mfs == 1500);

	/* VLAN name boundaries: 32 octets accepted, 33 not */
	memcpy(vn, "\x00\x80\xc2\x03\x00\x0a", 6);
	vn[6] = 32;
	memset(vn + 7, 'n', 33);
	memset(&p, 0, sizeof p); mandatory(&p); raw(&p, 127, 7 + 32, vn); end(&p);
	CHECK(lldpdu_parse(p.b, p.n, &m) == LLDP_OK && m.ext.vlan_name_len == 32);
	vn[6] = 33;
	memset(&p, 0, sizeof p); mandatory(&p); raw(&p, 127, 7 + 33, vn); end(&p);
	CHECK(lldpdu_parse(p.b, p.n, &m) == LLDP_OK && m.ext.n_vlan_names == 0 &&
	      m.n_unknown_tlvs == 1);

	/* builder: Maximum Frame Size is sent, not in a shutdown LLDPDU */
	{
		struct lldp_local_info li = {
			.chassis_mac = { 2, 0, 0, 0, 0, 1 }, .port_mac = { 2, 0, 0, 0, 0, 1 },
			.ifname = "eth0", .ttl = 120, .mfs = 9018,
		};
		n = lldpdu_build(&li, buf, sizeof buf);
		CHECK(lldpdu_parse(buf, (size_t)n, &m) == LLDP_OK);
		CHECK(m.ext.has_mfs && m.ext.mfs == 9018 && m.n_org_tlvs == 1);
		li.ttl = 0;
		n = lldpdu_build(&li, buf, sizeof buf);
		CHECK(lldpdu_parse(buf, (size_t)n, &m) == LLDP_OK && !m.ext.has_mfs);
	}

	/* equality ignores absent fields, sees every present one */
	memset(&a, 0, sizeof a);
	memset(&b, 0xff, sizeof b);
	b.has_pvid = b.n_vlan_names = b.has_macphy = b.has_lag = b.has_mfs = 0;
	CHECK(lldp_ext_equal(&a, &b));
	a.has_mfs = b.has_mfs = 1; a.mfs = 1518; b.mfs = 1518;
	CHECK(lldp_ext_equal(&a, &b));
	b.mfs = 1522;
	CHECK(!lldp_ext_equal(&a, &b));
	b.mfs = 1518; a.n_vlan_names = b.n_vlan_names = 1;
	a.vlan_name_len = b.vlan_name_len = 2; a.vlan_id = b.vlan_id = 5;
	memcpy(a.vlan_name, "ab", 2); memcpy(b.vlan_name, "ab", 2);
	CHECK(lldp_ext_equal(&a, &b));
	b.vlan_name[1] = 'c';
	CHECK(!lldp_ext_equal(&a, &b));
}

static void test_names(void)
{
	char out[LLDP_CAPFMT_MAX];

	lldp_caps_format(0, out, sizeof out);
	CHECK(strcmp(out, "-") == 0);
	lldp_caps_format(LLDP_CAP_BRIDGE | LLDP_CAP_ROUTER | LLDP_CAP_TPMR, out, sizeof out);
	CHECK(strcmp(out, "bridge,router,tpmr") == 0);
	lldp_caps_format(0x8001, out, sizeof out);           /* reserved bit 15 */
	CHECK(strcmp(out, "other,bit15") == 0);
	lldp_caps_format(0xffff, out, sizeof out);
	CHECK(strstr(out, "station") != NULL && strstr(out, "bit15") != NULL);
	lldp_caps_format(0xffff, out, 20);                   /* never overflows */
	CHECK(strlen(out) < 20);
	CHECK(lldp_cap_name(7) && strcmp(lldp_cap_name(7), "station") == 0);
	CHECK(lldp_cap_name(11) == NULL);

	CHECK(strcmp(lldp_id_subtype_name(4, 1), "mac") == 0);
	CHECK(strcmp(lldp_id_subtype_name(3, 0), "mac") == 0);
	CHECK(strcmp(lldp_id_subtype_name(5, 0), "ifname") == 0);
	CHECK(strcmp(lldp_id_subtype_name(6, 1), "ifname") == 0);
	CHECK(strcmp(lldp_id_subtype_name(0, 1), "reserved") == 0);
	CHECK(strcmp(lldp_id_subtype_name(200, 0), "reserved") == 0);
}

int main(void)
{
	RUN(test_roundtrip_builder);
	RUN(test_accepts);
	RUN(test_missing_and_order);
	RUN(test_bad_lengths);
	RUN(test_strerror_and_format);
	RUN(test_caps_and_mgmt);
	RUN(test_names);
	RUN(test_extensions);
	return test_report("test_lldpdu");
}
