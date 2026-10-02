/*
 * main.c - lldpnd: LLDP (IEEE Std 802.1AB-2016) neighbour discovery daemon
 *
 * Command-line parsing only; the agent lives in agent.c.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "agent.h"
#include "ctl.h"
#include "txsched.h"

/* 9.2.5 defaults: msgTxInterval 30 s (9.2.5.7), msgTxHold 4 (9.2.5.6) */
#define DEFAULT_TX_INTERVAL  30
#define DEFAULT_TX_HOLD      4

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s -i <interface>[,<interface>...] [options]\n"
		"  -i IF[,IF]  interface(s) to run LLDP on; repeatable (required)\n"
		"  -c IF       interface whose MAC is the chassis ID (default: first -i)\n"
		"  -m MODE     adminStatus: rxtx (default), tx (transmit only),\n"
		"              rx (receive only)\n"
		"  -a ADDR     destination group address: nearest-bridge (default),\n"
		"              nearest-nontpmr, nearest-customer\n"
		"  -t SECS     msgTxInterval, transmit interval (1-3600, default %d)\n"
		"  -H N        msgTxHold, hold multiplier (1-100, default %d);\n"
		"              advertised TTL = min(65535, SECS * N + 1)\n"
		"  -f N        txFastInit, frames sent 1 s apart at start-up, on link up\n"
		"              and for a new neighbour (0-8, default %u; 0 disables)\n"
		"  -C N        txCreditMax, max back-to-back frames (1-10, default %u)\n"
		"  -p SECS     print neighbour tables every SECS (default: on change)\n"
		"  -n NAME     System Name (default: hostname, followed live)\n"
		"  -d DESC     System Description (default: uname)\n"
		"  -P DESC     Port Description for every port (default: interface\n"
		"              alias, else the interface name)\n"
		"  -M          do not advertise Management Address TLVs\n"
		"  -S PATH     control socket (default %s; \"none\" disables)\n"
		"  -U USER     after start-up run as USER, keeping only CAP_NET_RAW\n"
		"  -h          this help\n",
		prog, DEFAULT_TX_INTERVAL, DEFAULT_TX_HOLD, TXS_DEFAULT_FAST_INIT,
		TXS_DEFAULT_CREDIT_MAX, CTL_DEFAULT_PATH);
}

static int parse_uint(const char *s, unsigned lo, unsigned hi, unsigned *out)
{
	char *end;
	unsigned long v;

	errno = 0;
	v = strtoul(s, &end, 10);
	if (errno || end == s || *end != '\0' || v < lo || v > hi || s[0] == '-')
		return -1;
	*out = (unsigned)v;
	return 0;
}

/* split a comma-separated -i argument in place */
static int add_ifnames(struct agent_cfg *cfg, char *arg)
{
	char *save = NULL, *tok;

	for (tok = strtok_r(arg, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
		if (cfg->n_ifnames >= AGENT_MAX_PORTS) {
			fprintf(stderr, "at most %d interfaces\n", AGENT_MAX_PORTS);
			return -1;
		}
		cfg->ifnames[cfg->n_ifnames++] = tok;
	}
	return 0;
}

static int check_str(const char *what, const char *s)
{
	if (s && strlen(s) > LLDP_STR_MAX_LEN) {
		fprintf(stderr, "%s is limited to 255 octets (8.5.5-8.5.7)\n", what);
		return -1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	static struct agent ag;
	struct agent_cfg cfg;
	const char *ctl_path = CTL_DEFAULT_PATH;
	int ctl_explicit = 0, c, rc;

	setvbuf(stdout, NULL, _IOLBF, 0);
	memset(&cfg, 0, sizeof cfg);
	cfg.tx_interval = DEFAULT_TX_INTERVAL;
	cfg.tx_hold = DEFAULT_TX_HOLD;
	cfg.fast_init = TXS_DEFAULT_FAST_INIT;
	cfg.credit_max = TXS_DEFAULT_CREDIT_MAX;

	while ((c = getopt(argc, argv, "i:c:m:a:t:H:f:C:p:n:d:P:MS:U:h")) != -1) {
		switch (c) {
		case 'm':
			if (strcmp(optarg, "rxtx") == 0)
				cfg.admin = ADMIN_RXTX;
			else if (strcmp(optarg, "tx") == 0)
				cfg.admin = ADMIN_TX_ONLY;
			else if (strcmp(optarg, "rx") == 0)
				cfg.admin = ADMIN_RX_ONLY;
			else {
				fprintf(stderr, "invalid -m %s (rxtx, tx or rx)\n", optarg);
				return 2;
			}
			break;
		case 'a':
			cfg.group = lldp_group_by_name(optarg);
			if (!cfg.group) {
				fprintf(stderr, "invalid -a %s (nearest-bridge, nearest-nontpmr, "
					"nearest-customer)\n", optarg);
				return 2;
			}
			break;
		case 'i':
			if (add_ifnames(&cfg, optarg) < 0)
				return 2;
			break;
		case 'c': cfg.chassis_if = optarg; break;
		case 't':
			if (parse_uint(optarg, 1, 3600, &cfg.tx_interval) < 0) {
				fprintf(stderr, "invalid -t %s (1-3600)\n", optarg);
				return 2;
			}
			break;
		case 'H':
			if (parse_uint(optarg, 1, 100, &cfg.tx_hold) < 0) {
				fprintf(stderr, "invalid -H %s (1-100)\n", optarg);
				return 2;
			}
			break;
		case 'f':
			if (parse_uint(optarg, 0, 8, &cfg.fast_init) < 0) {
				fprintf(stderr, "invalid -f %s (0-8)\n", optarg);
				return 2;
			}
			break;
		case 'C':
			if (parse_uint(optarg, 1, 10, &cfg.credit_max) < 0) {
				fprintf(stderr, "invalid -C %s (1-10)\n", optarg);
				return 2;
			}
			break;
		case 'p':
			if (parse_uint(optarg, 0, 86400, &cfg.print_secs) < 0) {
				fprintf(stderr, "invalid -p %s (0-86400)\n", optarg);
				return 2;
			}
			break;
		case 'n': cfg.sys_name = optarg; break;
		case 'd': cfg.sys_desc = optarg; break;
		case 'P': cfg.port_desc = optarg; break;
		case 'M': cfg.no_mgmt = 1; break;
		case 'S': ctl_path = optarg; ctl_explicit = 1; break;
		case 'U': cfg.run_as = optarg; break;
		case 'h': usage(argv[0]); return 0;
		default:  usage(argv[0]); return 2;
		}
	}
	if (optind != argc) {
		fprintf(stderr, "unexpected argument: %s\n", argv[optind]);
		usage(argv[0]);
		return 2;
	}
	if (cfg.n_ifnames == 0) {
		fprintf(stderr, "-i <interface> is required\n");
		usage(argv[0]);
		return 2;
	}
	if (check_str("-n", cfg.sys_name) < 0 || check_str("-d", cfg.sys_desc) < 0 ||
	    check_str("-P", cfg.port_desc) < 0)
		return 2;
	if (strcmp(ctl_path, "none") != 0)
		cfg.ctl_path = ctl_path;

	if (agent_init(&ag, &cfg) < 0) {
		/* the default socket path is a convenience, not a requirement */
		if (cfg.ctl_path && !ctl_explicit) {
			fprintf(stderr, "retrying without the control socket (-S none)\n");
			cfg.ctl_path = NULL;
			if (agent_init(&ag, &cfg) == 0)
				goto run;
		}
		return 1;
	}
run:
	rc = agent_run(&ag);
	agent_free(&ag);
	return rc;
}
