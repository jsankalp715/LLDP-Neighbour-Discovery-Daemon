/* test_neigh.c - neighbour table: keying, refresh, TTL ageing, shutdown */
#include "test.h"
#include "../src/neigh.h"

#include <stdlib.h>

static struct neigh_table tbl;      /* ~50 KiB: keep it off the stack */
static const uint8_t SRC[6] = { 0x02, 0, 0, 0, 0, 0x09 };

static struct lldp_msg msg(uint8_t chassis_last, const char *port, uint16_t ttl)
{
	struct lldp_msg m;

	memset(&m, 0, sizeof m);
	m.chassis.subtype = LLDP_CHASSIS_MAC;
	m.chassis.len = 6;
	m.chassis.id[0] = 0x02;
	m.chassis.id[5] = chassis_last;
	m.port.subtype = LLDP_PORT_IF_NAME;
	m.port.len = (uint8_t)strlen(port);
	memcpy(m.port.id, port, m.port.len);
	m.ttl = ttl;
	return m;
}

static unsigned cb_hits;
static void count_cb(const struct neigh *n, void *ctx)
{
	(void)ctx;
	CHECK(n->in_use);
	cb_hits++;
}

static void test_add_refresh_update(void)
{
	struct lldp_msg m = msg(1, "eth0", 10);
	const struct neigh *n;
	uint64_t when;

	neigh_init(&tbl);
	CHECK(neigh_next_expiry(&tbl, &when) == 0);
	CHECK(neigh_update(&tbl, &m, SRC, 1000, &n) == NEIGH_ADDED);
	CHECK(tbl.count == 1 && n && n->expires_ms == 11000 && n->rx_count == 1);
	CHECK(neigh_next_expiry(&tbl, &when) == 1 && when == 11000);

	/* identical content: refresh, TTL timer restarts */
	CHECK(neigh_update(&tbl, &m, SRC, 5000, &n) == NEIGH_REFRESHED);
	CHECK(tbl.count == 1 && n->expires_ms == 15000 && n->rx_count == 2);
	CHECK(n->first_seen_ms == 1000 && n->last_seen_ms == 5000);

	/* changed optional TLV -> update, same key */
	m.sys_name.present = 1; m.sys_name.len = 2; memcpy(m.sys_name.s, "r1", 2);
	CHECK(neigh_update(&tbl, &m, SRC, 6000, &n) == NEIGH_UPDATED);
	CHECK(tbl.count == 1 && n->sys_name.present && n->sys_name.len == 2);
	/* changed TTL -> update and new expiry */
	m.ttl = 30;
	CHECK(neigh_update(&tbl, &m, SRC, 7000, &n) == NEIGH_UPDATED);
	CHECK(n->expires_ms == 37000);
}

static void test_keying(void)
{
	struct lldp_msg a = msg(1, "eth0", 10);
	struct lldp_msg b = msg(1, "eth1", 10);    /* same chassis, other port */
	struct lldp_msg c = msg(2, "eth0", 10);    /* other chassis, same port */
	struct lldp_msg d = msg(1, "eth0", 10);

	neigh_init(&tbl);
	CHECK(neigh_update(&tbl, &a, SRC, 0, NULL) == NEIGH_ADDED);
	CHECK(neigh_update(&tbl, &b, SRC, 0, NULL) == NEIGH_ADDED);
	CHECK(neigh_update(&tbl, &c, SRC, 0, NULL) == NEIGH_ADDED);
	CHECK(neigh_update(&tbl, &d, SRC, 0, NULL) == NEIGH_REFRESHED);
	/* same octets, different subtype => different MSAP */
	d.port.subtype = LLDP_PORT_LOCAL;
	CHECK(neigh_update(&tbl, &d, SRC, 0, NULL) == NEIGH_ADDED);
	/* prefix of an existing ID is a different ID */
	d = msg(1, "eth", 10);
	CHECK(neigh_update(&tbl, &d, SRC, 0, NULL) == NEIGH_ADDED);
	CHECK(tbl.count == 5);
}

static void test_ageing(void)
{
	struct lldp_msg a = msg(1, "eth0", 10), b = msg(2, "eth0", 20);
	uint64_t when;

	neigh_init(&tbl);
	neigh_update(&tbl, &a, SRC, 0, NULL);       /* expires 10000 */
	neigh_update(&tbl, &b, SRC, 0, NULL);       /* expires 20000 */
	cb_hits = 0;
	CHECK(neigh_age(&tbl, 9999, count_cb, NULL) == 0);
	CHECK(tbl.count == 2);
	CHECK(neigh_age(&tbl, 10000, count_cb, NULL) == 1);   /* exactly at TTL */
	CHECK(tbl.count == 1 && cb_hits == 1);
	CHECK(neigh_next_expiry(&tbl, &when) == 1 && when == 20000);

	/* re-reception before expiry keeps it alive */
	neigh_update(&tbl, &b, SRC, 15000, NULL);  /* now expires 35000 */
	CHECK(neigh_age(&tbl, 30000, count_cb, NULL) == 0);
	CHECK(neigh_age(&tbl, 35000, NULL, NULL) == 1);
	CHECK(tbl.count == 0 && neigh_next_expiry(&tbl, &when) == 0);

	/* a re-added neighbour after ageout is ADDED again */
	CHECK(neigh_update(&tbl, &a, SRC, 40000, NULL) == NEIGH_ADDED);

	/* max TTL does not overflow */
	a.ttl = 65535;
	neigh_update(&tbl, &a, SRC, UINT64_C(1) << 40, NULL);
	CHECK(neigh_next_expiry(&tbl, &when) == 1 &&
	      when == (UINT64_C(1) << 40) + 65535000u);
}

static void test_shutdown(void)
{
	struct lldp_msg a = msg(1, "eth0", 10), z = msg(1, "eth0", 0);
	struct lldp_msg u = msg(9, "eth9", 0);
	const struct neigh *n;

	neigh_init(&tbl);
	CHECK(neigh_update(&tbl, &u, SRC, 0, &n) == NEIGH_IGNORED && n == NULL);
	CHECK(tbl.count == 0);
	neigh_update(&tbl, &a, SRC, 0, NULL);
	CHECK(neigh_update(&tbl, &z, SRC, 100, &n) == NEIGH_DELETED);
	CHECK(tbl.count == 0 && n && n->chassis.id[5] == 1);
	CHECK(neigh_age(&tbl, 1000000, NULL, NULL) == 0);
}

static void test_full(void)
{
	char port[16];
	unsigned i;
	struct lldp_msg m;

	neigh_init(&tbl);
	for (i = 0; i < NEIGH_MAX; i++) {
		snprintf(port, sizeof port, "p%u", i);
		m = msg(1, port, 10);
		CHECK(neigh_update(&tbl, &m, SRC, 0, NULL) == NEIGH_ADDED);
	}
	CHECK(tbl.count == NEIGH_MAX);
	m = msg(2, "overflow", 10);
	CHECK(neigh_update(&tbl, &m, SRC, 0, NULL) == NEIGH_FULL);
	CHECK(tbl.count == NEIGH_MAX);
	/* existing entries still refresh while full */
	m = msg(1, "p7", 10);
	CHECK(neigh_update(&tbl, &m, SRC, 5, NULL) == NEIGH_REFRESHED);
	/* after ageing, space frees up */
	CHECK(neigh_age(&tbl, 10000, NULL, NULL) == NEIGH_MAX - 1);
	m = msg(2, "overflow", 10);
	CHECK(neigh_update(&tbl, &m, SRC, 10000, NULL) == NEIGH_ADDED);
	CHECK(tbl.count == 2);
}

static void test_print_escapes(void)
{
	struct lldp_msg m = msg(0xab, "eth0", 10);
	char *buf = NULL;
	size_t len = 0;
	FILE *f;

	neigh_init(&tbl);
	m.sys_name.present = 1;
	m.sys_name.len = 7;
	memcpy(m.sys_name.s, "\x1b[2Jevl", 7);   /* terminal escape injection */
	neigh_update(&tbl, &m, SRC, 0, NULL);

	f = open_memstream(&buf, &len);
	CHECK(f != NULL);
	if (!f)
		return;
	neigh_print(&tbl, 4000, f);
	fclose(f);
	CHECK(strstr(buf, "1 entry") != NULL);
	CHECK(strstr(buf, "chassis 02:00:00:00:00:ab port eth0(st5)") != NULL);
	CHECK(strstr(buf, "\\x1b[2Jevl") != NULL);
	CHECK(strchr(buf, 0x1b) == NULL);
	CHECK(strstr(buf, "expires in 6000 ms") != NULL);
	free(buf);
}

int main(void)
{
	RUN(test_add_refresh_update);
	RUN(test_keying);
	RUN(test_ageing);
	RUN(test_shutdown);
	RUN(test_full);
	RUN(test_print_escapes);
	return test_report("test_neigh");
}
