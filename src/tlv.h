/*
 * tlv.h - LLDP TLV encoding/decoding (IEEE Std 802.1AB-2016, clause 8.4/8.5)
 *
 * Every LLDPDU is a sequence of TLVs. Each TLV starts with a 2-octet header
 * (clause 8.4, Figure 8-2): a 7-bit TLV type in the most significant bits,
 * followed by a 9-bit information string length (0..511 octets).
 */
#ifndef LLDP_TLV_H
#define LLDP_TLV_H

#include <stddef.h>
#include <stdint.h>

#define LLDP_TLV_HDR_LEN   2u
#define LLDP_TLV_TYPE_MAX  127u   /* 7-bit type field  */
#define LLDP_TLV_LEN_MAX   511u   /* 9-bit length field */

/* TLV type values, clause 8.4.1 / Table 8-1 */
enum lldp_tlv_type {
	LLDP_TLV_END          = 0,   /* 8.5.1 End Of LLDPDU   (mandatory) */
	LLDP_TLV_CHASSIS_ID   = 1,   /* 8.5.2 Chassis ID      (mandatory) */
	LLDP_TLV_PORT_ID      = 2,   /* 8.5.3 Port ID         (mandatory) */
	LLDP_TLV_TTL          = 3,   /* 8.5.4 Time To Live    (mandatory) */
	LLDP_TLV_PORT_DESC    = 4,   /* 8.5.5 Port Description           */
	LLDP_TLV_SYS_NAME     = 5,   /* 8.5.6 System Name                */
	LLDP_TLV_SYS_DESC     = 6,   /* 8.5.7 System Description         */
	LLDP_TLV_SYS_CAP      = 7,   /* 8.5.8 System Capabilities        */
	LLDP_TLV_MGMT_ADDR    = 8,   /* 8.5.9 Management Address         */
	/* 9..126 reserved */
	LLDP_TLV_ORG_SPECIFIC = 127, /* 8.6   Organizationally Specific  */
};

/* Chassis ID subtypes, 8.5.2.2 / Table 8-2 */
enum lldp_chassis_subtype {
	LLDP_CHASSIS_COMPONENT   = 1,
	LLDP_CHASSIS_IF_ALIAS    = 2,
	LLDP_CHASSIS_PORT_COMP   = 3,
	LLDP_CHASSIS_MAC         = 4,
	LLDP_CHASSIS_NET_ADDR    = 5,
	LLDP_CHASSIS_IF_NAME     = 6,
	LLDP_CHASSIS_LOCAL       = 7,
};

/* Port ID subtypes, 8.5.3.2 / Table 8-3 */
enum lldp_port_subtype {
	LLDP_PORT_IF_ALIAS       = 1,
	LLDP_PORT_COMPONENT      = 2,
	LLDP_PORT_MAC            = 3,
	LLDP_PORT_NET_ADDR       = 4,
	LLDP_PORT_IF_NAME        = 5,
	LLDP_PORT_AGENT_CIRCUIT  = 6,
	LLDP_PORT_LOCAL          = 7,
};

/* Chassis ID / Port ID string is 1..255 octets (8.5.2.3, 8.5.3.3) */
#define LLDP_ID_MAX_LEN    255u
/* Port Description, System Name, System Description: 0..255 (8.5.5-8.5.7) */
#define LLDP_STR_MAX_LEN   255u

/* Header encode/decode. encode returns -1 if type or length overflow. */
int  lldp_tlv_hdr_encode(uint8_t out[2], unsigned type, unsigned len);
void lldp_tlv_hdr_decode(const uint8_t in[2], unsigned *type, unsigned *len);

/*
 * Bounded write buffer. Once any write fails, err is latched and all further
 * writes fail, so a builder can issue a sequence of puts and check once.
 */
struct lldp_buf {
	uint8_t *data;
	size_t   cap;
	size_t   len;
	int      err;
};

void lldp_buf_init(struct lldp_buf *b, uint8_t *data, size_t cap);

/* Generic TLV writer. Returns 0 on success, -1 on overflow/invalid. */
int lldp_tlv_put(struct lldp_buf *b, unsigned type, const void *val, size_t len);

/* Builders for the TLVs this agent emits. */
int lldp_tlv_put_id(struct lldp_buf *b, unsigned type, uint8_t subtype,
		    const void *id, size_t id_len);
int lldp_tlv_put_chassis_mac(struct lldp_buf *b, const uint8_t mac[6]);
int lldp_tlv_put_port_ifname(struct lldp_buf *b, const char *ifname);
int lldp_tlv_put_ttl(struct lldp_buf *b, uint16_t ttl);
int lldp_tlv_put_port_desc(struct lldp_buf *b, const char *s);
int lldp_tlv_put_sys_name(struct lldp_buf *b, const char *s);
int lldp_tlv_put_sys_desc(struct lldp_buf *b, const char *s);
int lldp_tlv_put_end(struct lldp_buf *b);

/* A decoded TLV; value points into the caller's buffer. */
struct lldp_tlv {
	unsigned       type;
	unsigned       len;
	const uint8_t *value;
};

struct lldp_tlv_iter {
	const uint8_t *p;
	size_t         remaining;
};

void lldp_tlv_iter_init(struct lldp_tlv_iter *it, const uint8_t *data, size_t len);

/*
 * Fetch the next TLV.
 *   1  a TLV was decoded into *t
 *   0  no bytes remain
 *  -1  malformed: truncated header, or length runs past the buffer
 */
int lldp_tlv_next(struct lldp_tlv_iter *it, struct lldp_tlv *t);

#endif
