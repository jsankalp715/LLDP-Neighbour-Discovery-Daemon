/* test_report.c - JSON/text rendering of agent state from hostile neighbours */
#include "test.h"
#include "json_check.h"
#include "../src/report.h"

#include <stdlib.h>

static struct agent ag;          /* large: keep off the stack */
static struct port port0, port1;

static char *render(void (*fn)(const struct agent *, FILE *), size_t *len)
{
	char *buf = NULL;
	FILE *f = open_memstream(&buf, len);

	if (!f)
		return NULL;
	fn(&ag, f);
	fclose(f);
	return buf;
}

static struct lldp_msg hostile(void)
{
	struct lldp_msg m;
	unsigned i;

	memset(&m, 0, sizeof m);
	m.chassis.subtype = LLDP_CHASSIS_LOCAL;
	m.chassis.len = 255;
	for (i = 0; i < 255; i++)
		m.chassis.id[i] = (uint8_t)i;           /* every octet value but 255 */
	m.port.subtype = LLDP_PORT_IF_NAME;
	m.port.len = 6;
	memcpy(m.port.id, "e\"\\\n\x7f\xff", 6);
	m.ttl = 120;
	m.sys_name.present = 1;
	m.sys_name.len = 8;
	memcpy(m.sys_name.s, "\x1b[2J\"}]x", 8);    /* tries to close the JSON */
	m.sys_desc.present = 1;
	m.sys_desc.len = 4;
	memcpy(m.sys_desc.s, "\xc3\xa9\xff\x00", 4); /* UTF-8, invalid UTF-8, NUL */
	m.has_sys_cap = 1;
	m.sys_cap = 0xffff;
	m.sys_cap_enabled = 0x8010;
	m.n_mgmt = 2;
	m.mgmt[0] = (struct lldp_mgmt){ LLDP_AF_IPV4, 4, { 192, 0, 2, 9 }, 2, 3 };
	m.mgmt[1] = (struct lldp_mgmt){ 77, 3, { '"', '\\', 0 }, 1, 0xffffffffu };
	m.n_org_tlvs = 3;
	return m;
}

static void setup(void)
{
	struct lldp_msg m = hostile(), m2;
	const uint8_t src[6] = { 0x02, 0, 0, 0, 0, 0x42 };

	memset(&ag, 0, sizeof ag);
	memset(&port0, 0, sizeof port0);
	memset(&port1, 0, sizeof port1);
	ag.cfg.tx_interval = 30;
	ag.cfg.tx_hold = 4;
	ag.cfg.chassis_if = "eth0";
	ag.cfg.sys_name = "host\"name";
	ag.ttl = 121;
	ag.caps = LLDP_CAP_ROUTER | LLDP_CAP_STATION;
	ag.caps_enabled = LLDP_CAP_STATION;
	snprintf(ag.sysdesc, sizeof ag.sysdesc, "Linux test");
	ag.start_ms = agent_now_ms();
	ag.nports = 2;
	ag.ports[0] = &port0;
	ag.ports[1] = &port1;

	snprintf(port0.name, sizeof port0.name, "eth0");
	port0.ifindex = 0;                          /* absent: no getifaddrs lookup */
	port0.sock.fd = -1;
	neigh_init(&port0.table);
	neigh_update(&port0.table, &m, src, agent_now_ms(), NULL);
	m2 = m;
	m2.port.len = 1;                            /* second neighbour */
	m2.sys_name.present = 0;
	m2.has_sys_cap = 0;
	m2.n_mgmt = 0;
	neigh_update(&port0.table, &m2, src, agent_now_ms(), NULL);
	port0.st.frames_in = 7;

	snprintf(port1.name, sizeof port1.name, "eth1");
	port1.sock.fd = -1;
	neigh_init(&port1.table);                   /* empty table */
}

static void test_json_valid_and_escaped(void)
{
	size_t len = 0;
	char *s;

	setup();
	s = render(report_json, &len);
	CHECK(s != NULL);
	if (!s)
		return;
	CHECK(json_valid(s, len));
	if (!json_valid(s, len))
		fprintf(stderr, "invalid JSON: %s\n", s);
	CHECK(strstr(s, "\"system_name\":\"host\\\"name\"") != NULL);
	CHECK(strstr(s, "\"system_name\":\"\\u001b[2J\\\"}]x\"") != NULL);
	CHECK(strstr(s, "\\u00c3\\u00a9\\u00ff\\u0000") != NULL);
	CHECK(strstr(s, "\"subtype\":\"ifname\",\"value\":\"e\\\"\\\\\\n\\u007f\\u00ff\"") != NULL);
	CHECK(strstr(s, "\"subtype\":\"local\"") != NULL);
	CHECK(strstr(s, "\"system_name\":null") != NULL);
	CHECK(strstr(s, "\"capabilities\":null") != NULL);
	CHECK(strstr(s, "\"enabled\":[\"router\",\"bit15\"]") != NULL);
	CHECK(strstr(s, "{\"family\":\"ipv4\",\"address\":\"192.0.2.9\",\"if_subtype\":2,\"if_number\":3}") != NULL);
	CHECK(strstr(s, "\"family\":\"other\",\"address\":\"af77:225c00\"") != NULL);
	CHECK(strstr(s, "\"if_number\":4294967295") != NULL);
	CHECK(strstr(s, "\"name\":\"eth1\",\"ifindex\":0,\"present\":false") != NULL);
	CHECK(strstr(s, "\"neighbors\":[]") != NULL);
	CHECK(strstr(s, "\"frames_in\":7") != NULL);
	/* pure ASCII, no raw control characters except the final newline */
	for (size_t i = 0; i + 1 < len; i++)
		if ((unsigned char)s[i] < 0x20 || (unsigned char)s[i] >= 0x7f) {
			CHECK(!"raw control/non-ASCII octet in JSON");
			break;
		}
	free(s);
}

static void test_json_str_exhaustive(void)
{
	uint8_t all[256];
	char *buf = NULL;
	size_t len = 0, i;
	FILE *f;

	for (i = 0; i < 256; i++)
		all[i] = (uint8_t)i;
	f = open_memstream(&buf, &len);
	if (!f)
		return;
	json_str(f, all, sizeof all);
	json_str(f, all, 0);
	fclose(f);
	/* two concatenated strings are not one value; check them separately */
	CHECK(len > 2);
	CHECK(json_valid(buf, len - 2));            /* strip the trailing "" */
	CHECK(strcmp(buf + len - 2, "\"\"") == 0);
	free(buf);
}

static void test_text_views(void)
{
	size_t len = 0;
	char *s;

	setup();
	s = render(report_show, &len);
	CHECK(s && strstr(s, "port eth0: absent") != NULL);
	CHECK(s && strstr(s, "eth0 neighbour table: 2 entries") != NULL);
	CHECK(s && strstr(s, "eth1 neighbour table: 0 entries") != NULL);
	CHECK(s && strchr(s, 0x1b) == NULL);         /* escaped, not raw */
	free(s);

	s = render(report_stats, &len);
	CHECK(s && strstr(s, "eth0") != NULL && strstr(s, "discarded") != NULL);
	free(s);
}

static void cmd(const char *c, char **out)
{
	size_t len = 0;
	FILE *f = open_memstream(out, &len);
	if (!f)
		return;
	report_command(&ag, c, f);
	fclose(f);
}

static void test_commands(void)
{
	char *s = NULL;

	setup();
	cmd("help", &s);
	CHECK(s && strstr(s, "show | json") != NULL);
	free(s);
	cmd("bogus", &s);
	CHECK(s && strncmp(s, "error:", 6) == 0);
	free(s);
	cmd("", &s);                                 /* default is show */
	CHECK(s && strstr(s, "neighbour table") != NULL);
	free(s);
	cmd("json", &s);
	CHECK(s && json_valid(s, strlen(s)));
	free(s);
}

static void test_validator_itself(void)
{
	static const char *good[] = {
		"{}", "[]", "0", "-1.5e+3", "\"a\\u00ffb\"", "{\"a\":[1,true,null,{}]}",
		" [ 1 , 2 ] \n",
	};
	static const char *bad[] = {
		"", "{", "{\"a\"}", "[1,]", "01", "\"\x01\"", "\"\\x41\"", "tru",
		"{\"a\":1,}", "[1] [2]", "\"\xc3\xa9\"", "nul",
	};
	size_t i;

	for (i = 0; i < sizeof good / sizeof good[0]; i++)
		CHECK(json_valid(good[i], strlen(good[i])));
	for (i = 0; i < sizeof bad / sizeof bad[0]; i++)
		CHECK(!json_valid(bad[i], strlen(bad[i])));
}

int main(void)
{
	RUN(test_validator_itself);
	RUN(test_json_valid_and_escaped);
	RUN(test_json_str_exhaustive);
	RUN(test_text_views);
	RUN(test_commands);
	return test_report("test_report");
}
