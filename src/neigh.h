/*
 * neigh.h - remote systems MIB (neighbour table) with TTL ageing
 *           (IEEE Std 802.1AB-2016, clauses 9.2.7, 9.2.9)
 */
#ifndef LLDP_NEIGH_H
#define LLDP_NEIGH_H

#include <stdint.h>
#include <stdio.h>

#include "lldpdu.h"

/*
 * Fixed-size table: no allocation on the receive path, and a hard cap on
 * the memory an attacker can make us commit. When full, new neighbours are
 * dropped (tooManyNeighbors, a 9.2.5 variable) while existing ones keep refreshing.
 */
#define NEIGH_MAX 32

struct neigh {
	int             in_use;
	/* key: 9.2.7 (rxProcessFrame) identifies an MSAP by Chassis ID + Port ID */
	struct lldp_id  chassis;
	struct lldp_id  port;
	uint16_t        ttl;
	uint64_t        first_seen_ms;
	uint64_t        last_seen_ms;
	uint64_t        expires_ms;      /* rxInfoTTL expiry, monotonic ms */
	uint8_t         src_mac[ETH_ADDR_LEN];
	struct lldp_str port_desc;
	struct lldp_str sys_name;
	struct lldp_str sys_desc;
	int             has_sys_cap;
	uint16_t        sys_cap;
	uint16_t        sys_cap_enabled;
	unsigned        n_mgmt;
	struct lldp_mgmt mgmt[LLDP_MAX_MGMT];
	unsigned        n_org_tlvs;
	unsigned        n_unknown_tlvs;
	uint32_t        rx_count;
};

struct neigh_table {
	struct neigh e[NEIGH_MAX];
	unsigned     count;
};

enum neigh_result {
	NEIGH_ADDED,          /* new MSAP */
	NEIGH_UPDATED,        /* known MSAP, information changed */
	NEIGH_REFRESHED,      /* known MSAP, identical information, TTL restarted */
	NEIGH_DELETED,        /* TTL 0 shutdown LLDPDU for a known MSAP */
	NEIGH_IGNORED,        /* TTL 0 for an unknown MSAP - nothing to do */
	NEIGH_FULL,           /* table full, new MSAP dropped */
};

void neigh_init(struct neigh_table *t);

/*
 * Apply a validated LLDPDU received at now_ms. *out (optional) points at the
 * affected entry for ADDED/UPDATED/REFRESHED; for DELETED it points at a
 * static copy of the removed entry, valid until the next neigh_update().
 */
enum neigh_result neigh_update(struct neigh_table *t, const struct lldp_msg *m,
			       const uint8_t src_mac[ETH_ADDR_LEN], uint64_t now_ms,
			       const struct neigh **out);

typedef void (*neigh_cb)(const struct neigh *n, void *ctx);

/* Remove every entry whose TTL has expired by now_ms; returns how many. */
unsigned neigh_age(struct neigh_table *t, uint64_t now_ms, neigh_cb cb, void *ctx);

/*
 * Remove every entry (the port stopped being operational: 9.2.9, the rx
 * state machine re-initialises and 9.2.7 rxInitializeLLDP() deletes all
 * remote information for the port). Returns how many.
 */
unsigned neigh_flush(struct neigh_table *t, neigh_cb cb, void *ctx);

/* Earliest expiry time; returns 0 if the table is empty, else 1. */
int neigh_next_expiry(const struct neigh_table *t, uint64_t *when_ms);

/* label (optional) is printed in the header, e.g. the port name */
void neigh_print(const struct neigh_table *t, const char *label, uint64_t now_ms, FILE *f);

const char *neigh_result_str(enum neigh_result r);

#endif
