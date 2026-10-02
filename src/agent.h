/*
 * agent.h - the LLDP agent: one or more ports, each with its own raw socket,
 *           transmit schedule and remote systems table, driven by a single
 *           epoll loop (IEEE Std 802.1AB-2016, clause 9).
 */
#ifndef LLDP_AGENT_H
#define LLDP_AGENT_H

#include <net/if.h>
#include <stdint.h>
#include <stdio.h>

#include "lldpdu.h"
#include "neigh.h"
#include "rawsock.h"
#include "txsched.h"

#define AGENT_MAX_PORTS      32
#define AGENT_REINIT_DELAY_MS 2000u   /* reinitDelay default, 9.2.5.10 */

/* adminStatus (9.2.5.1) */
enum admin_status {
	ADMIN_RXTX,        /* enabledRxTx (default) */
	ADMIN_TX_ONLY,     /* enabledTxOnly */
	ADMIN_RX_ONLY,     /* enabledRxOnly */
};

struct agent_cfg {
	enum admin_status admin;
	const uint8_t *group;        /* destination group address (7.1), NULL = nearest bridge */
	const char *ifnames[AGENT_MAX_PORTS];
	unsigned    n_ifnames;
	const char *chassis_if;      /* interface whose MAC is the chassis ID */
	unsigned    tx_interval;     /* msgTxInterval, s (9.2.5.7) */
	unsigned    tx_hold;         /* msgTxHold (9.2.5.6) */
	unsigned    fast_init;       /* txFastInit (9.2.5.19); 0 disables fast tx */
	unsigned    credit_max;      /* txCreditMax (9.2.5.17) */
	unsigned    print_secs;      /* 0 = print a port's table when it changes */
	const char *sys_name;        /* NULL = hostname, tracked live */
	const char *sys_desc;        /* NULL = uname */
	const char *port_desc;       /* NULL = interface alias, else ifname */
	const char *ctl_path;        /* control socket, NULL = none */
	const char *run_as;          /* drop privileges to this user, NULL = stay */
	int         no_mgmt;         /* do not send Management Address TLVs */
};

/* Statistics counters, named after the 802.1AB statistics variables */
struct port_stats {
	unsigned long frames_out;          /* statsFramesOutTotal */
	unsigned long frames_in;           /* statsFramesInTotal */
	unsigned long frames_discarded;    /* statsFramesDiscardedTotal */
	unsigned long frames_in_errors;    /* statsFramesInErrorsTotal */
	unsigned long tlvs_unrecognized;   /* statsTLVsUnrecognizedTotal */
	unsigned long ageouts;             /* statsAgeoutsTotal */
	unsigned long too_many_neighbors;  /* tooManyNeighbors events */
	unsigned long own_frames;          /* our own chassis seen (loop) */
	unsigned long local_changes;       /* somethingChangedLocal events */
};

struct agent;

/* epoll user data: what a ready file descriptor belongs to */
enum ev_kind { EV_SOCK, EV_TX, EV_AGE, EV_SIGNAL, EV_NETLINK, EV_HOSTNAME,
	       EV_PRINT, EV_CTL };
struct ev {
	enum ev_kind kind;
	void        *obj;
};

struct port {
	struct agent     *ag;
	char              name[IF_NAMESIZE];   /* configured name: the port's key */
	int               ifindex;             /* 0 while the interface is absent */
	int               oper_up;             /* portEnabled (9.2.5) */
	uint8_t           mac[ETH_ADDR_LEN];
	unsigned          mtu;                 /* 0 = unknown */
	char              alias[256];
	struct lldp_sock  sock;                /* fd -1 when closed */
	int               tx_tfd, age_tfd;
	struct tx_sched   txs;
	struct neigh_table table;
	struct port_stats st;
	uint8_t           frame[LLDP_FRAME_MAX];  /* current information LLDPDU */
	size_t            frame_len;
	uint64_t          down_ms;             /* when the port last went down */
	int               loop_warned;
	int               dirty;               /* table changed since last print */
	struct ev         ev_sock, ev_tx, ev_age;
};

struct agent {
	struct agent_cfg  cfg;
	struct port      *ports[AGENT_MAX_PORTS];
	unsigned          nports;
	int               epfd, sig_fd, nl_fd, host_fd, print_tfd;
	struct ev         ev_sig, ev_nl, ev_host, ev_print;
	struct ctl       *ctl;
	uint8_t           chassis_mac[ETH_ADDR_LEN];
	int               have_chassis;
	char              hostname[LLDP_STR_MAX_LEN + 1];
	char              sysdesc[LLDP_STR_MAX_LEN + 1];
	uint16_t          caps, caps_enabled;
	uint16_t          ttl;                 /* txTTL (9.2.5.22) */
	uint64_t          start_ms;
	int               running;
};

uint64_t agent_now_ms(void);

/* adminStatus as text: "rxtx", "tx", "rx" */
const char *agent_admin_name(enum admin_status a);
/* the destination group address in use */
const uint8_t *agent_group(const struct agent *ag);

/* Validate config and open everything. Returns 0, or -1 (message printed). */
int  agent_init(struct agent *ag, const struct agent_cfg *cfg);
/* Run until SIGINT/SIGTERM; sends shutdown LLDPDUs. Returns exit status. */
int  agent_run(struct agent *ag);
void agent_free(struct agent *ag);

/* Fill li with what port p currently advertises (ttl = ag->ttl). */
void agent_local_info(const struct agent *ag, const struct port *p,
		      struct lldp_local_info *li, char *portdesc, size_t pdcap);

#endif
