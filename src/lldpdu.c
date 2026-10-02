/*
 * lldpdu.c - LLDPDU construction and validating parser
 *            (IEEE Std 802.1AB-2016, clauses 8.2, 8.5, 9.2.7)
 *
 * All received octets are untrusted. The parser walks the TLV chain through
 * lldp_tlv_next(), which refuses any length that runs past the buffer, and
 * then checks each TLV against the length/subtype rules of clause 8.5.
 */
#include "lldpdu.h"

#include <stdio.h>
#include <string.h>

ssize_t lldpdu_build(const struct lldp_local_info *li, uint8_t *out, size_t cap)
{
	struct lldp_buf b;

	lldp_buf_init(&b, out, cap);
	/* 8.2, Figure 8-1: Chassis ID, Port ID, TTL first, in that order */
	lldp_tlv_put_chassis_mac(&b, li->mac);
	lldp_tlv_put_port_ifname(&b, li->ifname);
	lldp_tlv_put_ttl(&b, li->ttl);
	/* 9.2.7 (mkShutdownLLDPDU): a shutdown LLDPDU carries only the mandatory TLVs */
	if (li->ttl != 0) {
		if (li->port_desc)
			lldp_tlv_put_port_desc(&b, li->port_desc);
		if (li->sys_name)
			lldp_tlv_put_sys_name(&b, li->sys_name);
		if (li->sys_desc)
			lldp_tlv_put_sys_desc(&b, li->sys_desc);
	}
	lldp_tlv_put_end(&b);
	if (b.err)
		return -1;
	return (ssize_t)b.len;
}

ssize_t lldp_frame_build(const struct lldp_local_info *li, uint8_t *out, size_t cap)
{
	uint8_t pdu[ETH_MAX_PAYLOAD];
	ssize_t n = lldpdu_build(li, pdu, sizeof pdu);

	if (n < 0)
		return -1;
	return eth_frame_build(out, cap, LLDP_MCAST_NEAREST_BRIDGE, li->mac,
			       ETHERTYPE_LLDP, pdu, (size_t)n);
}

static const char *const errstr[LLDP_E_COUNT] = {
	[LLDP_OK]                  = "ok",
	[LLDP_E_TRUNCATED]         = "truncated TLV / length exceeds frame",
	[LLDP_E_FIRST_NOT_CHASSIS] = "first TLV is not Chassis ID",
	[LLDP_E_SECOND_NOT_PORT]   = "second TLV is not Port ID",
	[LLDP_E_THIRD_NOT_TTL]     = "third TLV is not TTL",
	[LLDP_E_BAD_CHASSIS]       = "invalid Chassis ID TLV",
	[LLDP_E_BAD_PORT]          = "invalid Port ID TLV",
	[LLDP_E_BAD_TTL]           = "invalid TTL TLV length",
	[LLDP_E_BAD_END]           = "End Of LLDPDU TLV with nonzero length",
	[LLDP_E_MISSING_END]       = "missing End Of LLDPDU TLV",
	[LLDP_E_DUP_MANDATORY]     = "mandatory TLV repeated",
	[LLDP_E_DUP_OPTIONAL]      = "single-instance optional TLV repeated",
	[LLDP_E_BAD_LENGTH]        = "optional TLV has invalid length",
};

const char *lldp_strerror(int err)
{
	if (err < 0 || err >= LLDP_E_COUNT)
		return "unknown error";
	return errstr[err];
}

/*
 * Chassis ID (8.5.2) / Port ID (8.5.3): TLV length 2..256 (subtype + 1..255
 * octets of ID). Subtypes 0 and 8..255 are reserved (Tables 8-2, 8-3) and
 * rejected. MAC-address subtypes must carry exactly 6 octets; network-address
 * subtypes carry an IANA family octet plus at least one octet of address.
 */
static int decode_id(const struct lldp_tlv *t, struct lldp_id *id,
		     uint8_t mac_subtype, uint8_t netaddr_subtype)
{
	uint8_t subtype;
	unsigned id_len;

	if (t->len < 2 || t->len > 1 + LLDP_ID_MAX_LEN)
		return -1;
	subtype = t->value[0];
	id_len = t->len - 1;
	if (subtype < 1 || subtype > 7)
		return -1;
	if (subtype == mac_subtype && id_len != ETH_ADDR_LEN)
		return -1;
	if (subtype == netaddr_subtype && id_len < 2)
		return -1;
	id->subtype = subtype;
	id->len = (uint8_t)id_len;
	memcpy(id->id, t->value + 1, id_len);
	return 0;
}

static int decode_str(const struct lldp_tlv *t, struct lldp_str *s)
{
	if (s->present)
		return LLDP_E_DUP_OPTIONAL;
	if (t->len > LLDP_STR_MAX_LEN)          /* 8.5.5-8.5.7: 0..255 octets */
		return LLDP_E_BAD_LENGTH;
	s->present = 1;
	s->len = (uint8_t)t->len;
	if (t->len > 0)
		memcpy(s->s, t->value, t->len);
	return LLDP_OK;
}

/*
 * 8.5.9, Figure 8-11: Management Address TLV.
 *   addr str len (1) | addr subtype (1) | addr (1..31) |
 *   if subtype (1) | if number (4) | OID len (1) | OID (0..128)
 * TLV length 9..167, and the internal lengths must account for it exactly.
 */
static int check_mgmt_addr(const struct lldp_tlv *t)
{
	unsigned asl, oid_len, off;

	if (t->len < 9 || t->len > 167)
		return -1;
	asl = t->value[0];                     /* covers subtype + address */
	if (asl < 2 || asl > 32)
		return -1;
	off = 1 + asl + 1 + 4;                 /* index of OID length octet */
	if (off >= t->len)
		return -1;
	oid_len = t->value[off];
	if (oid_len > 128 || off + 1 + oid_len != t->len)
		return -1;
	return 0;
}

int lldpdu_parse(const uint8_t *pdu, size_t len, struct lldp_msg *m)
{
	struct lldp_tlv_iter it;
	struct lldp_tlv t;
	unsigned idx = 0;
	int r, rc;

	memset(m, 0, sizeof *m);
	lldp_tlv_iter_init(&it, pdu, len);

	while ((r = lldp_tlv_next(&it, &t)) == 1) {
		idx++;
		/*
		 * 8.2 / 9.2.7 (rxProcessFrame): an LLDPDU whose first three
		 * TLVs are not Chassis ID, Port ID and TTL, in that order, is
		 * discarded.
		 */
		if (idx == 1 && t.type != LLDP_TLV_CHASSIS_ID)
			return LLDP_E_FIRST_NOT_CHASSIS;
		if (idx == 2 && t.type != LLDP_TLV_PORT_ID)
			return LLDP_E_SECOND_NOT_PORT;
		if (idx == 3 && t.type != LLDP_TLV_TTL)
			return LLDP_E_THIRD_NOT_TTL;

		switch (t.type) {
		case LLDP_TLV_END:
			/* 8.5.1: End Of LLDPDU is always length 0 */
			if (t.len != 0)
				return LLDP_E_BAD_END;
			/* anything after End is padding and is ignored (8.2) */
			return LLDP_OK;

		case LLDP_TLV_CHASSIS_ID:
			if (idx != 1)
				return LLDP_E_DUP_MANDATORY;
			if (decode_id(&t, &m->chassis, LLDP_CHASSIS_MAC,
				      LLDP_CHASSIS_NET_ADDR) < 0)
				return LLDP_E_BAD_CHASSIS;
			break;

		case LLDP_TLV_PORT_ID:
			if (idx != 2)
				return LLDP_E_DUP_MANDATORY;
			if (decode_id(&t, &m->port, LLDP_PORT_MAC,
				      LLDP_PORT_NET_ADDR) < 0)
				return LLDP_E_BAD_PORT;
			break;

		case LLDP_TLV_TTL:
			if (idx != 3)
				return LLDP_E_DUP_MANDATORY;
			/* 8.5.4: TTL information string is exactly 2 octets */
			if (t.len != 2)
				return LLDP_E_BAD_TTL;
			m->ttl = (uint16_t)((t.value[0] << 8) | t.value[1]);
			break;

		case LLDP_TLV_PORT_DESC:
			if ((rc = decode_str(&t, &m->port_desc)) != LLDP_OK)
				return rc;
			break;
		case LLDP_TLV_SYS_NAME:
			if ((rc = decode_str(&t, &m->sys_name)) != LLDP_OK)
				return rc;
			break;
		case LLDP_TLV_SYS_DESC:
			if ((rc = decode_str(&t, &m->sys_desc)) != LLDP_OK)
				return rc;
			break;

		case LLDP_TLV_SYS_CAP:
			/* 8.5.8: two 2-octet bitmaps, length exactly 4 */
			if (m->has_sys_cap)
				return LLDP_E_DUP_OPTIONAL;
			if (t.len != 4)
				return LLDP_E_BAD_LENGTH;
			m->has_sys_cap = 1;
			m->sys_cap = (uint16_t)((t.value[0] << 8) | t.value[1]);
			m->sys_cap_enabled = (uint16_t)((t.value[2] << 8) | t.value[3]);
			break;

		case LLDP_TLV_MGMT_ADDR:
			/* 8.5.9: may appear more than once */
			if (check_mgmt_addr(&t) < 0)
				return LLDP_E_BAD_LENGTH;
			m->n_mgmt_addr++;
			break;

		case LLDP_TLV_ORG_SPECIFIC:
			/* 8.6: 3-octet OUI + 1-octet subtype + 0..507 octets */
			if (t.len < 4)
				return LLDP_E_BAD_LENGTH;
			m->n_org_tlvs++;
			break;

		default:
			/*
			 * Reserved types 9..126: 9.2.7 (rxProcessFrame) - unrecognized TLVs
			 * are counted (statsTLVsUnrecognizedTotal) and skipped,
			 * the LLDPDU itself is still accepted.
			 */
			m->n_unknown_tlvs++;
			break;
		}
	}

	if (r < 0)
		return LLDP_E_TRUNCATED;
	/* ran out of octets: report the earliest missing element */
	if (idx < 1)
		return LLDP_E_FIRST_NOT_CHASSIS;
	if (idx < 2)
		return LLDP_E_SECOND_NOT_PORT;
	if (idx < 3)
		return LLDP_E_THIRD_NOT_TTL;
	return LLDP_E_MISSING_END;
}

void lldp_escape(const uint8_t *s, size_t n, char *out, size_t cap)
{
	size_t o = 0, i;

	if (cap == 0)
		return;
	for (i = 0; i < n; i++) {
		uint8_t c = s[i];
		if (c >= 0x20 && c < 0x7f && c != '\\') {
			if (cap - o < 2)
				break;
			out[o++] = (char)c;
		} else {
			if (cap - o < 5)
				break;
			snprintf(out + o, 5, "\\x%02x", c);
			o += 4;
		}
	}
	out[o] = '\0';
}

void lldp_id_format(const struct lldp_id *id, int is_chassis, char *out, size_t cap)
{
	uint8_t mac_st = is_chassis ? LLDP_CHASSIS_MAC : LLDP_PORT_MAC;
	char esc[LLDP_ESC_MAX];

	if (cap == 0)
		return;
	if (id->subtype == mac_st && id->len == ETH_ADDR_LEN) {
		char mac[18];
		eth_ntoa(id->id, mac);
		snprintf(out, cap, "%s", mac);
		return;
	}
	lldp_escape(id->id, id->len, esc, sizeof esc);
	snprintf(out, cap, "%s(st%u)", esc, id->subtype);
}
