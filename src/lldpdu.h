/*
 * lldpdu.h - LLDPDU construction and validating parser
 *            (IEEE Std 802.1AB-2016, clauses 8.2, 8.5, 9.2.7)
 */
#ifndef LLDP_LLDPDU_H
#define LLDP_LLDPDU_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "frame.h"
#include "tlv.h"

/* Largest frame we ever build or accept: header + 1500-octet payload */
#define LLDP_FRAME_MAX   (ETH_HDR_LEN + ETH_MAX_PAYLOAD)

/* Information this agent advertises about its own port */
struct lldp_local_info {
	uint8_t     mac[ETH_ADDR_LEN];  /* chassis ID (subtype 4) */
	const char *ifname;             /* port ID (subtype 5) */
	uint16_t    ttl;                /* 0 => shutdown LLDPDU */
	const char *port_desc;          /* optional, NULL to omit */
	const char *sys_name;           /* optional, NULL to omit */
	const char *sys_desc;           /* optional, NULL to omit */
};

/*
 * Build an LLDPDU (TLV sequence, no Ethernet header). When ttl == 0 a
 * shutdown LLDPDU is built: only Chassis ID, Port ID, TTL and End
 * (9.2.7, mkShutdownLLDPDU). Returns length or -1.
 */
ssize_t lldpdu_build(const struct lldp_local_info *li, uint8_t *out, size_t cap);

/* Build the complete Ethernet frame carrying the LLDPDU. */
ssize_t lldp_frame_build(const struct lldp_local_info *li, uint8_t *out, size_t cap);

/* --- receive side --- */

struct lldp_id {
	uint8_t subtype;
	uint8_t len;                       /* 1..255 */
	uint8_t id[LLDP_ID_MAX_LEN];
};

struct lldp_str {
	uint8_t present;
	uint8_t len;                       /* 0..255, raw octets, not NUL-terminated */
	uint8_t s[LLDP_STR_MAX_LEN];
};

struct lldp_msg {
	struct lldp_id  chassis;
	struct lldp_id  port;
	uint16_t        ttl;
	struct lldp_str port_desc;
	struct lldp_str sys_name;
	struct lldp_str sys_desc;
	int             has_sys_cap;
	uint16_t        sys_cap;
	uint16_t        sys_cap_enabled;
	unsigned        n_mgmt_addr;
	unsigned        n_org_tlvs;
	unsigned        n_unknown_tlvs;     /* reserved types 9..126 */
};

enum lldp_parse_err {
	LLDP_OK = 0,
	LLDP_E_TRUNCATED,          /* TLV header/length runs past the frame */
	LLDP_E_FIRST_NOT_CHASSIS,  /* 1st TLV must be Chassis ID */
	LLDP_E_SECOND_NOT_PORT,    /* 2nd TLV must be Port ID */
	LLDP_E_THIRD_NOT_TTL,      /* 3rd TLV must be TTL */
	LLDP_E_BAD_CHASSIS,        /* length/subtype invalid */
	LLDP_E_BAD_PORT,
	LLDP_E_BAD_TTL,
	LLDP_E_BAD_END,            /* End Of LLDPDU with nonzero length */
	LLDP_E_MISSING_END,
	LLDP_E_DUP_MANDATORY,      /* Chassis/Port/TTL repeated later */
	LLDP_E_DUP_OPTIONAL,       /* Port Desc/Sys Name/Sys Desc/Sys Cap repeated */
	LLDP_E_BAD_LENGTH,         /* optional TLV with an illegal length */
	LLDP_E_COUNT
};

const char *lldp_strerror(int err);

/*
 * Validate and decode an LLDPDU (the Ethernet payload). Never reads outside
 * [pdu, pdu+len). On error, *m contents are unspecified.
 */
int lldpdu_parse(const uint8_t *pdu, size_t len, struct lldp_msg *m);

/*
 * Escape untrusted octets for display: printable ASCII passes through, '\\'
 * and everything else becomes \xNN. Always NUL-terminates if cap > 0.
 */
void lldp_escape(const uint8_t *s, size_t n, char *out, size_t cap);

/* Human-readable chassis/port ID (MAC subtypes as aa:bb:.., names escaped) */
void lldp_id_format(const struct lldp_id *id, int is_chassis, char *out, size_t cap);

/* Buffer sizes sufficient for the formatters above */
#define LLDP_ESC_MAX     (4 * 255 + 1)
#define LLDP_IDFMT_MAX   (LLDP_ESC_MAX + 16)

#endif
