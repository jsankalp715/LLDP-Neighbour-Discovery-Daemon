/*
 * neigh.c - remote systems MIB (neighbour table) with TTL ageing
 *           (IEEE Std 802.1AB-2016, clauses 9.2.7, 9.2.9)
 */
#include "neigh.h"

#include <string.h>

void neigh_init(struct neigh_table *t)
{
	memset(t, 0, sizeof *t);
}

static int id_eq(const struct lldp_id *a, const struct lldp_id *b)
{
	return a->subtype == b->subtype && a->len == b->len &&
	       memcmp(a->id, b->id, a->len) == 0;
}

static int str_eq(const struct lldp_str *a, const struct lldp_str *b)
{
	return a->present == b->present && a->len == b->len &&
	       memcmp(a->s, b->s, a->len) == 0;
}

static int mgmt_eq(const struct neigh *n, const struct lldp_msg *m)
{
	unsigned i;

	if (n->n_mgmt != m->n_mgmt)
		return 0;
	for (i = 0; i < m->n_mgmt; i++) {
		const struct lldp_mgmt *a = &n->mgmt[i], *b = &m->mgmt[i];
		if (a->subtype != b->subtype || a->len != b->len ||
		    a->if_subtype != b->if_subtype || a->if_number != b->if_number ||
		    memcmp(a->addr, b->addr, a->len) != 0)
			return 0;
	}
	return 1;
}

static struct neigh *find(struct neigh_table *t, const struct lldp_msg *m)
{
	unsigned i;

	for (i = 0; i < NEIGH_MAX; i++)
		if (t->e[i].in_use && id_eq(&t->e[i].chassis, &m->chassis) &&
		    id_eq(&t->e[i].port, &m->port))
			return &t->e[i];
	return NULL;
}

/* Slot used to hand a deleted entry back to the caller (see neigh.h). */
static struct neigh last_deleted;

enum neigh_result neigh_update(struct neigh_table *t, const struct lldp_msg *m,
			       const uint8_t src_mac[ETH_ADDR_LEN], uint64_t now_ms,
			       const struct neigh **out)
{
	struct neigh *n = find(t, m);
	enum neigh_result res;
	unsigned i;

	if (out)
		*out = NULL;

	/*
	 * 8.5.4 / 9.2.7: a TTL of zero means the remote agent is shutting
	 * down; its information is deleted immediately.
	 */
	if (m->ttl == 0) {
		if (!n)
			return NEIGH_IGNORED;
		last_deleted = *n;
		memset(n, 0, sizeof *n);
		t->count--;
		if (out)
			*out = &last_deleted;
		return NEIGH_DELETED;
	}

	if (n) {
		int same = n->ttl == m->ttl &&
			   str_eq(&n->port_desc, &m->port_desc) &&
			   str_eq(&n->sys_name, &m->sys_name) &&
			   str_eq(&n->sys_desc, &m->sys_desc) &&
			   n->has_sys_cap == m->has_sys_cap &&
			   n->sys_cap == m->sys_cap &&
			   n->sys_cap_enabled == m->sys_cap_enabled &&
			   mgmt_eq(n, m) &&
			   lldp_ext_equal(&n->ext, &m->ext) &&
			   memcmp(n->src_mac, src_mac, ETH_ADDR_LEN) == 0;
		res = same ? NEIGH_REFRESHED : NEIGH_UPDATED;
	} else {
		for (i = 0; i < NEIGH_MAX && t->e[i].in_use; i++)
			;
		if (i == NEIGH_MAX)
			return NEIGH_FULL;   /* 9.2.5 variable tooManyNeighbors */
		n = &t->e[i];
		memset(n, 0, sizeof *n);
		n->in_use = 1;
		n->chassis = m->chassis;
		n->port = m->port;
		n->first_seen_ms = now_ms;
		t->count++;
		res = NEIGH_ADDED;
	}

	/* refresh: restart the rxInfoTTL timer from the newly received TTL */
	n->ttl = m->ttl;
	n->last_seen_ms = now_ms;
	n->expires_ms = now_ms + (uint64_t)m->ttl * 1000u;
	memcpy(n->src_mac, src_mac, ETH_ADDR_LEN);
	n->port_desc = m->port_desc;
	n->sys_name = m->sys_name;
	n->sys_desc = m->sys_desc;
	n->has_sys_cap = m->has_sys_cap;
	n->sys_cap = m->sys_cap;
	n->sys_cap_enabled = m->sys_cap_enabled;
	n->n_mgmt = m->n_mgmt;
	memcpy(n->mgmt, m->mgmt, sizeof n->mgmt);
	n->n_org_tlvs = m->n_org_tlvs;
	n->n_unknown_tlvs = m->n_unknown_tlvs;
	n->ext = m->ext;
	n->rx_count++;
	if (out)
		*out = n;
	return res;
}

unsigned neigh_age(struct neigh_table *t, uint64_t now_ms, neigh_cb cb, void *ctx)
{
	unsigned i, aged = 0;

	for (i = 0; i < NEIGH_MAX; i++) {
		struct neigh *n = &t->e[i];
		/* 9.2.9 rx state machine: rxInfoAge when rxTTL reaches zero, 9.2.7 mibDeleteObjects() */
		if (n->in_use && now_ms >= n->expires_ms) {
			if (cb)
				cb(n, ctx);
			memset(n, 0, sizeof *n);
			t->count--;
			aged++;
		}
	}
	return aged;
}

unsigned neigh_flush(struct neigh_table *t, neigh_cb cb, void *ctx)
{
	unsigned i, n = 0;

	for (i = 0; i < NEIGH_MAX; i++)
		if (t->e[i].in_use) {
			if (cb)
				cb(&t->e[i], ctx);
			memset(&t->e[i], 0, sizeof t->e[i]);
			n++;
		}
	t->count = 0;
	return n;
}

int neigh_next_expiry(const struct neigh_table *t, uint64_t *when_ms)
{
	unsigned i;
	int found = 0;

	for (i = 0; i < NEIGH_MAX; i++)
		if (t->e[i].in_use && (!found || t->e[i].expires_ms < *when_ms)) {
			*when_ms = t->e[i].expires_ms;
			found = 1;
		}
	return found;
}

static void print_str(FILE *f, const char *label, const struct lldp_str *s)
{
	char esc[LLDP_ESC_MAX];

	if (!s->present)
		return;
	lldp_escape(s->s, s->len, esc, sizeof esc);
	fprintf(f, "    %-12s %s\n", label, esc);
}

static void print_ext(FILE *f, const struct lldp_ext *x)
{
	char esc[LLDP_ESC_MAX];

	if (x->has_pvid || x->n_vlan_names) {
		fprintf(f, "    %-12s", "vlan");
		if (x->has_pvid)
			fprintf(f, " pvid %u", x->pvid);
		if (x->n_vlan_names) {
			lldp_escape(x->vlan_name, x->vlan_name_len, esc, sizeof esc);
			fprintf(f, "%s vlan %u name \"%s\"", x->has_pvid ? "," : "",
				x->vlan_id, esc);
			if (x->n_vlan_names > 1)
				fprintf(f, " (+%u more)", x->n_vlan_names - 1);
		}
		fputc('\n', f);
	}
	if (x->has_macphy)
		fprintf(f, "    %-12s autoneg %s/%s, pmd-cap 0x%04x, mau type %u\n", "mac/phy",
			x->autoneg & 1 ? "supported" : "unsupported",
			x->autoneg & 2 ? "enabled" : "disabled", x->pmd_cap, x->mau_type);
	if (x->has_lag)
		fprintf(f, "    %-12s %s/%s, port id %u\n", "aggregation",
			x->lag_status & 1 ? "capable" : "not capable",
			x->lag_status & 2 ? "enabled" : "disabled", x->lag_port_id);
	if (x->has_mfs)
		fprintf(f, "    %-12s %u\n", "max frame", x->mfs);
}

void neigh_print(const struct neigh_table *t, const char *label, uint64_t now_ms, FILE *f)
{
	char cid[LLDP_IDFMT_MAX], pid[LLDP_IDFMT_MAX], mac[18];
	char caps[LLDP_CAPFMT_MAX], en[LLDP_CAPFMT_MAX], ma[LLDP_MGMTFMT_MAX];
	unsigned i, j, k = 0;

	fprintf(f, "---- %s%sneighbour table: %u entr%s ----\n",
		label ? label : "", label ? " " : "",
		t->count, t->count == 1 ? "y" : "ies");
	for (i = 0; i < NEIGH_MAX; i++) {
		const struct neigh *n = &t->e[i];
		if (!n->in_use)
			continue;
		lldp_id_format(&n->chassis, 1, cid, sizeof cid);
		lldp_id_format(&n->port, 0, pid, sizeof pid);
		eth_ntoa(n->src_mac, mac);
		fprintf(f, "  [%u] chassis %s port %s\n", k++, cid, pid);
		fprintf(f, "    %-12s %u s (expires in %llu ms), rx %u, src %s\n",
			"ttl", n->ttl,
			(unsigned long long)(n->expires_ms > now_ms ? n->expires_ms - now_ms : 0),
			n->rx_count, mac);
		print_str(f, "sys name", &n->sys_name);
		print_str(f, "sys desc", &n->sys_desc);
		print_str(f, "port desc", &n->port_desc);
		if (n->has_sys_cap) {
			lldp_caps_format(n->sys_cap, caps, sizeof caps);
			lldp_caps_format(n->sys_cap_enabled, en, sizeof en);
			fprintf(f, "    %-12s %s (enabled: %s)\n", "capabilities", caps, en);
		}
		for (j = 0; j < n->n_mgmt; j++) {
			lldp_mgmt_format(&n->mgmt[j], ma, sizeof ma);
			fprintf(f, "    %-12s %s (if %s %u)\n", "mgmt addr", ma,
				n->mgmt[j].if_subtype == LLDP_IFNUM_IFINDEX ? "ifindex" :
				n->mgmt[j].if_subtype == LLDP_IFNUM_SYSPORT ? "port" : "?",
				n->mgmt[j].if_number);
		}
		print_ext(f, &n->ext);
		if (n->n_org_tlvs || n->n_unknown_tlvs)
			fprintf(f, "    %-12s %u org-specific, %u unrecognised\n", "other TLVs",
				n->n_org_tlvs, n->n_unknown_tlvs);
	}
	fprintf(f, "----\n");
	fflush(f);
}

const char *neigh_result_str(enum neigh_result r)
{
	switch (r) {
	case NEIGH_ADDED:     return "ADD";
	case NEIGH_UPDATED:   return "UPDATE";
	case NEIGH_REFRESHED: return "REFRESH";
	case NEIGH_DELETED:   return "DELETE";
	case NEIGH_IGNORED:   return "IGNORE";
	case NEIGH_FULL:      return "FULL";
	}
	return "?";
}
