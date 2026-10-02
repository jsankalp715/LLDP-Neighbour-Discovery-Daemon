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
			   memcmp(n->src_mac, src_mac, ETH_ADDR_LEN) == 0;
		res = same ? NEIGH_REFRESHED : NEIGH_UPDATED;
	} else {
		for (i = 0; i < NEIGH_MAX && t->e[i].in_use; i++)
			;
		if (i == NEIGH_MAX)
			return NEIGH_FULL;   /* 9.2.7: tooManyNeighbors */
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
		/* 9.2.9: rxInfoAge when the TTL timer reaches zero */
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

void neigh_print(const struct neigh_table *t, uint64_t now_ms, FILE *f)
{
	char cid[LLDP_IDFMT_MAX], pid[LLDP_IDFMT_MAX], mac[18];
	unsigned i, k = 0;

	fprintf(f, "---- neighbour table: %u entr%s ----\n",
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
