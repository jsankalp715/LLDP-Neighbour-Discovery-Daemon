/*
 * report.c - human and JSON renderings of the agent state
 */
#include "report.h"

#include <arpa/inet.h>
#include <string.h>

void json_str(FILE *out, const uint8_t *s, size_t n)
{
	size_t i;

	fputc('"', out);
	for (i = 0; i < n; i++) {
		uint8_t c = s[i];
		switch (c) {
		case '"':  fputs("\\\"", out); break;
		case '\\': fputs("\\\\", out); break;
		case '\n': fputs("\\n", out); break;
		case '\r': fputs("\\r", out); break;
		case '\t': fputs("\\t", out); break;
		default:
			if (c < 0x20 || c >= 0x7f)
				fprintf(out, "\\u%04x", c);   /* octet as U+00XX */
			else
				fputc(c, out);
		}
	}
	fputc('"', out);
}

static void json_cstr(FILE *out, const char *s)
{
	json_str(out, (const uint8_t *)s, strlen(s));
}

static void json_caps(FILE *out, uint16_t caps)
{
	unsigned bit;
	int first = 1;

	fputc('[', out);
	for (bit = 0; bit < 16; bit++) {
		const char *name;
		char tmp[16];
		if (!(caps & (1u << bit)))
			continue;
		name = lldp_cap_name(bit);
		if (!name) {
			snprintf(tmp, sizeof tmp, "bit%u", bit);
			name = tmp;
		}
		fprintf(out, "%s", first ? "" : ",");
		json_cstr(out, name);
		first = 0;
	}
	fputc(']', out);
}

/* Chassis/Port ID: MAC and IP-address subtypes are decoded, others escaped */
static void json_id(FILE *out, const struct lldp_id *id, int is_chassis)
{
	uint8_t mac_st = is_chassis ? LLDP_CHASSIS_MAC : LLDP_PORT_MAC;
	uint8_t net_st = is_chassis ? LLDP_CHASSIS_NET_ADDR : LLDP_PORT_NET_ADDR;
	char buf[INET6_ADDRSTRLEN];

	fputs("{\"subtype\":", out);
	json_cstr(out, lldp_id_subtype_name(id->subtype, is_chassis));
	fputs(",\"value\":", out);
	if (id->subtype == mac_st && id->len == ETH_ADDR_LEN) {
		eth_ntoa(id->id, buf);
		json_cstr(out, buf);
	} else if (id->subtype == net_st && id->len == 5 && id->id[0] == LLDP_AF_IPV4 &&
		   inet_ntop(AF_INET, id->id + 1, buf, sizeof buf)) {
		json_cstr(out, buf);
	} else if (id->subtype == net_st && id->len == 17 && id->id[0] == LLDP_AF_IPV6 &&
		   inet_ntop(AF_INET6, id->id + 1, buf, sizeof buf)) {
		json_cstr(out, buf);
	} else {
		json_str(out, id->id, id->len);
	}
	fputc('}', out);
}

static void json_opt_str(FILE *out, const char *key, const struct lldp_str *s)
{
	fprintf(out, ",\"%s\":", key);
	if (s->present)
		json_str(out, s->s, s->len);
	else
		fputs("null", out);
}

static const char *family_name(uint8_t af)
{
	switch (af) {
	case LLDP_AF_IPV4:   return "ipv4";
	case LLDP_AF_IPV6:   return "ipv6";
	case LLDP_AF_ALL802: return "mac";
	default:             return "other";
	}
}

static const char *jbool(int v)
{
	return v ? "true" : "false";
}

/* decoded 802.1 / 802.3 extensions; absent ones are null */
static void json_ext(FILE *out, const struct lldp_ext *x)
{
	fputs("\"ieee8021\":{\"port_vlan_id\":", out);
	if (x->has_pvid)
		fprintf(out, "%u", x->pvid);
	else
		fputs("null", out);
	fputs(",\"vlan_name\":", out);
	if (x->n_vlan_names) {
		fprintf(out, "{\"vlan_id\":%u,\"name\":", x->vlan_id);
		json_str(out, x->vlan_name, x->vlan_name_len);
		fprintf(out, ",\"count\":%u}", x->n_vlan_names);
	} else {
		fputs("null", out);
	}
	fputs("},\"ieee8023\":{\"mac_phy\":", out);
	if (x->has_macphy)
		fprintf(out, "{\"autoneg_supported\":%s,\"autoneg_enabled\":%s,"
			"\"pmd_capability\":%u,\"mau_type\":%u}",
			jbool(x->autoneg & 1), jbool(x->autoneg & 2), x->pmd_cap, x->mau_type);
	else
		fputs("null", out);
	fputs(",\"link_aggregation\":", out);
	if (x->has_lag)
		fprintf(out, "{\"capable\":%s,\"enabled\":%s,\"port_id\":%u}",
			jbool(x->lag_status & 1), jbool(x->lag_status & 2), x->lag_port_id);
	else
		fputs("null", out);
	fputs(",\"max_frame_size\":", out);
	if (x->has_mfs)
		fprintf(out, "%u", x->mfs);
	else
		fputs("null", out);
	fputc('}', out);
}

void report_neigh_json(const struct neigh *n, uint64_t now_ms, FILE *out)
{
	char mac[18], addr[LLDP_MGMTFMT_MAX];
	unsigned i;

	fputs("{\"chassis_id\":", out);
	json_id(out, &n->chassis, 1);
	fputs(",\"port_id\":", out);
	json_id(out, &n->port, 0);
	eth_ntoa(n->src_mac, mac);
	fprintf(out, ",\"ttl\":%u,\"expires_in_ms\":%llu,\"last_rx_ms_ago\":%llu,"
		"\"rx_count\":%u,\"source_mac\":\"%s\"",
		n->ttl,
		(unsigned long long)(n->expires_ms > now_ms ? n->expires_ms - now_ms : 0),
		(unsigned long long)(now_ms > n->last_seen_ms ? now_ms - n->last_seen_ms : 0),
		n->rx_count, mac);
	json_opt_str(out, "system_name", &n->sys_name);
	json_opt_str(out, "system_description", &n->sys_desc);
	json_opt_str(out, "port_description", &n->port_desc);
	fputs(",\"capabilities\":", out);
	if (n->has_sys_cap) {
		fputs("{\"supported\":", out);
		json_caps(out, n->sys_cap);
		fputs(",\"enabled\":", out);
		json_caps(out, n->sys_cap_enabled);
		fputc('}', out);
	} else {
		fputs("null", out);
	}
	fputs(",\"management_addresses\":[", out);
	for (i = 0; i < n->n_mgmt && i < LLDP_MAX_MGMT; i++) {
		lldp_mgmt_format(&n->mgmt[i], addr, sizeof addr);
		fprintf(out, "%s{\"family\":\"%s\",\"address\":", i ? "," : "",
			family_name(n->mgmt[i].subtype));
		json_cstr(out, addr);
		fprintf(out, ",\"if_subtype\":%u,\"if_number\":%u}",
			n->mgmt[i].if_subtype, n->mgmt[i].if_number);
	}
	fprintf(out, "],\"org_specific_tlvs\":%u,\"unrecognized_tlvs\":%u,",
		n->n_org_tlvs, n->n_unknown_tlvs);
	json_ext(out, &n->ext);
	fputc('}', out);
}

static void json_stats(FILE *out, const struct port_stats *st)
{
	fprintf(out, "{\"frames_out\":%lu,\"frames_in\":%lu,\"frames_discarded\":%lu,"
		"\"frames_in_errors\":%lu,\"tlvs_unrecognized\":%lu,\"ageouts\":%lu,"
		"\"too_many_neighbors\":%lu,\"own_frames\":%lu,\"local_changes\":%lu}",
		st->frames_out, st->frames_in, st->frames_discarded, st->frames_in_errors,
		st->tlvs_unrecognized, st->ageouts, st->too_many_neighbors,
		st->own_frames, st->local_changes);
}

void report_json(const struct agent *ag, FILE *out)
{
	uint64_t now = agent_now_ms();
	char mac[18];
	unsigned i, j;

	eth_ntoa(ag->chassis_mac, mac);
	fprintf(out, "{\"chassis_id\":\"%s\",\"system_name\":", mac);
	json_cstr(out, ag->cfg.sys_name ? ag->cfg.sys_name : ag->hostname);
	fputs(",\"system_description\":", out);
	json_cstr(out, ag->cfg.sys_desc ? ag->cfg.sys_desc : ag->sysdesc);
	fputs(",\"capabilities\":{\"supported\":", out);
	json_caps(out, ag->caps);
	fputs(",\"enabled\":", out);
	json_caps(out, ag->caps_enabled);
	eth_ntoa(agent_group(ag), mac);
	fprintf(out, "},\"admin_status\":\"%s\",\"destination\":{\"name\":\"%s\",\"mac\":\"%s\"},"
		"\"tx_interval\":%u,\"tx_hold\":%u,\"ttl\":%u,\"uptime_ms\":%llu,"
		"\"ports\":[", agent_admin_name(ag->cfg.admin),
		lldp_group_name(agent_group(ag)), mac, ag->cfg.tx_interval,
		ag->cfg.tx_hold, ag->ttl, (unsigned long long)(now - ag->start_ms));
	for (i = 0; i < ag->nports; i++) {
		const struct port *p = ag->ports[i];
		int first = 1;

		eth_ntoa(p->mac, mac);
		fprintf(out, "%s{\"name\":", i ? "," : "");
		json_cstr(out, p->name);
		fprintf(out, ",\"ifindex\":%d,\"present\":%s,\"link_up\":%s,\"mac\":\"%s\","
			"\"mtu\":%u,\"stats\":", p->ifindex, p->ifindex > 0 ? "true" : "false",
			p->oper_up ? "true" : "false", mac, p->mtu);
		json_stats(out, &p->st);
		fputs(",\"neighbors\":[", out);
		for (j = 0; j < NEIGH_MAX; j++) {
			if (!p->table.e[j].in_use)
				continue;
			if (!first)
				fputc(',', out);
			report_neigh_json(&p->table.e[j], now, out);
			first = 0;
		}
		fputs("]}", out);
	}
	fputs("]}\n", out);
}

void report_show(const struct agent *ag, FILE *out)
{
	uint64_t now = agent_now_ms();
	unsigned i;

	for (i = 0; i < ag->nports; i++) {
		const struct port *p = ag->ports[i];
		fprintf(out, "port %s: %s%s\n", p->name,
			p->ifindex ? "present" : "absent",
			p->ifindex ? (p->oper_up ? ", link up" : ", link down") : "");
		neigh_print(&p->table, p->name, now, out);
	}
}

void report_stats(const struct agent *ag, FILE *out)
{
	unsigned i;

	fprintf(out, "%-12s %8s %8s %9s %9s %8s %7s %6s %6s\n", "port", "out", "in",
		"discarded", "in_errors", "unrecog", "ageouts", "toomany", "loop");
	for (i = 0; i < ag->nports; i++) {
		const struct port_stats *st = &ag->ports[i]->st;
		fprintf(out, "%-12s %8lu %8lu %9lu %9lu %8lu %7lu %6lu %6lu\n",
			ag->ports[i]->name, st->frames_out, st->frames_in,
			st->frames_discarded, st->frames_in_errors, st->tlvs_unrecognized,
			st->ageouts, st->too_many_neighbors, st->own_frames);
	}
}

void report_local(const struct agent *ag, FILE *out)
{
	char mac[18], caps[LLDP_CAPFMT_MAX], en[LLDP_CAPFMT_MAX], addr[LLDP_MGMTFMT_MAX];
	unsigned i, j;

	eth_ntoa(ag->chassis_mac, mac);
	lldp_caps_format(ag->caps, caps, sizeof caps);
	lldp_caps_format(ag->caps_enabled, en, sizeof en);
	fprintf(out, "chassis      %s (from %s)\n", mac, ag->cfg.chassis_if);
	fprintf(out, "system name  %s\n", ag->cfg.sys_name ? ag->cfg.sys_name : ag->hostname);
	fprintf(out, "system desc  %s\n", ag->cfg.sys_desc ? ag->cfg.sys_desc : ag->sysdesc);
	fprintf(out, "capabilities %s (enabled: %s)\n", caps, en);
	eth_ntoa(agent_group(ag), mac);
	fprintf(out, "mode         %s, destination %s (%s)\n",
		agent_admin_name(ag->cfg.admin), lldp_group_name(agent_group(ag)), mac);
	fprintf(out, "timers       tx-interval %us, hold %u, ttl %us, fast-init %u, credit-max %u\n",
		ag->cfg.tx_interval, ag->cfg.tx_hold, ag->ttl, ag->cfg.fast_init,
		ag->cfg.credit_max);
	for (i = 0; i < ag->nports; i++) {
		const struct port *p = ag->ports[i];
		struct lldp_local_info li;
		char pd[sizeof p->alias];

		agent_local_info(ag, p, &li, pd, sizeof pd);
		eth_ntoa(p->mac, mac);
		fprintf(out, "port %s: ifindex %d, mac %s, %s, port desc \"%s\"\n", p->name,
			p->ifindex, mac, p->oper_up ? "up" : "down", li.port_desc);
		for (j = 0; j < li.n_mgmt; j++) {
			lldp_mgmt_format(&li.mgmt[j], addr, sizeof addr);
			fprintf(out, "  mgmt addr %s\n", addr);
		}
	}
}

void report_command(const struct agent *ag, const char *cmd, FILE *out)
{
	if (cmd[0] == '\0' || strcmp(cmd, "show") == 0)
		report_show(ag, out);
	else if (strcmp(cmd, "json") == 0)
		report_json(ag, out);
	else if (strcmp(cmd, "stats") == 0)
		report_stats(ag, out);
	else if (strcmp(cmd, "local") == 0)
		report_local(ag, out);
	else if (strcmp(cmd, "help") == 0)
		fputs("commands: show | json | stats | local | help\n", out);
	else
		fputs("error: unknown command (try: help)\n", out);
}
