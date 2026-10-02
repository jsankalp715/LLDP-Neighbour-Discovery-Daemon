/*
 * tlv.c - LLDP TLV encoding/decoding (IEEE Std 802.1AB-2016, clause 8.4/8.5)
 */
#include "tlv.h"

#include <string.h>

int lldp_tlv_hdr_encode(uint8_t out[2], unsigned type, unsigned len)
{
	if (type > LLDP_TLV_TYPE_MAX || len > LLDP_TLV_LEN_MAX)
		return -1;
	/*
	 * 8.4, Figure 8-2: bits 7..1 of octet 1 carry the type, bit 0 of
	 * octet 1 is the MSB of the 9-bit length, octet 2 holds the rest.
	 * Transmitted most significant bit first (8.1).
	 */
	uint16_t h = (uint16_t)((type << 9) | len);
	out[0] = (uint8_t)(h >> 8);
	out[1] = (uint8_t)(h & 0xffu);
	return 0;
}

void lldp_tlv_hdr_decode(const uint8_t in[2], unsigned *type, unsigned *len)
{
	unsigned h = ((unsigned)in[0] << 8) | in[1];
	*type = h >> 9;
	*len  = h & 0x1ffu;
}

void lldp_buf_init(struct lldp_buf *b, uint8_t *data, size_t cap)
{
	b->data = data;
	b->cap  = cap;
	b->len  = 0;
	b->err  = 0;
}

int lldp_tlv_put(struct lldp_buf *b, unsigned type, const void *val, size_t len)
{
	if (b->err)
		return -1;
	if (len > LLDP_TLV_LEN_MAX || (len > 0 && val == NULL))
		goto fail;
	/* invariant: b->len <= b->cap, so the subtraction cannot wrap */
	if (b->cap - b->len < LLDP_TLV_HDR_LEN + len)
		goto fail;
	if (lldp_tlv_hdr_encode(b->data + b->len, type, (unsigned)len) < 0)
		goto fail;
	if (len > 0)
		memcpy(b->data + b->len + LLDP_TLV_HDR_LEN, val, len);
	b->len += LLDP_TLV_HDR_LEN + len;
	return 0;
fail:
	b->err = 1;
	return -1;
}

/*
 * Chassis ID (8.5.2) and Port ID (8.5.3) share a layout: a 1-octet subtype
 * followed by a 1..255 octet ID, giving a TLV length of 2..256.
 */
int lldp_tlv_put_id(struct lldp_buf *b, unsigned type, uint8_t subtype,
		    const void *id, size_t id_len)
{
	uint8_t tmp[1 + LLDP_ID_MAX_LEN];

	if (id_len < 1 || id_len > LLDP_ID_MAX_LEN || id == NULL) {
		b->err = 1;
		return -1;
	}
	tmp[0] = subtype;
	memcpy(tmp + 1, id, id_len);
	return lldp_tlv_put(b, type, tmp, 1 + id_len);
}

/* 8.5.2.2: chassis ID subtype 4 = MAC address (6 octets, canonical order) */
int lldp_tlv_put_chassis_mac(struct lldp_buf *b, const uint8_t mac[6])
{
	return lldp_tlv_put_id(b, LLDP_TLV_CHASSIS_ID, LLDP_CHASSIS_MAC, mac, 6);
}

/* 8.5.3.2: port ID subtype 5 = interface name (ifName, IETF RFC 2863) */
int lldp_tlv_put_port_ifname(struct lldp_buf *b, const char *ifname)
{
	if (ifname == NULL) {
		b->err = 1;
		return -1;
	}
	return lldp_tlv_put_id(b, LLDP_TLV_PORT_ID, LLDP_PORT_IF_NAME,
			       ifname, strlen(ifname));
}

/* 8.5.4: TTL is a 2-octet unsigned integer, seconds */
int lldp_tlv_put_ttl(struct lldp_buf *b, uint16_t ttl)
{
	uint8_t v[2] = { (uint8_t)(ttl >> 8), (uint8_t)(ttl & 0xffu) };
	return lldp_tlv_put(b, LLDP_TLV_TTL, v, sizeof v);
}

static int put_string(struct lldp_buf *b, unsigned type, const char *s)
{
	size_t n;

	if (s == NULL) {
		b->err = 1;
		return -1;
	}
	n = strlen(s);
	if (n > LLDP_STR_MAX_LEN) {
		b->err = 1;
		return -1;
	}
	return lldp_tlv_put(b, type, s, n);
}

/* 8.5.5 Port Description, 0..255 octets of alphanumeric string */
int lldp_tlv_put_port_desc(struct lldp_buf *b, const char *s)
{
	return put_string(b, LLDP_TLV_PORT_DESC, s);
}

/* 8.5.6 System Name, 0..255 octets */
int lldp_tlv_put_sys_name(struct lldp_buf *b, const char *s)
{
	return put_string(b, LLDP_TLV_SYS_NAME, s);
}

/* 8.5.7 System Description, 0..255 octets */
int lldp_tlv_put_sys_desc(struct lldp_buf *b, const char *s)
{
	return put_string(b, LLDP_TLV_SYS_DESC, s);
}

/* 8.5.8 System Capabilities: 2-octet supported bitmap, 2-octet enabled bitmap */
int lldp_tlv_put_sys_cap(struct lldp_buf *b, uint16_t supported, uint16_t enabled)
{
	uint8_t v[4] = {
		(uint8_t)(supported >> 8), (uint8_t)supported,
		(uint8_t)(enabled >> 8),   (uint8_t)enabled,
	};
	return lldp_tlv_put(b, LLDP_TLV_SYS_CAP, v, sizeof v);
}

/*
 * 8.5.9 Management Address, Figure 8-11:
 *   addr string length (1) = 1 + addr_len | addr subtype (1) | addr (1..31)
 *   | if numbering subtype (1) | if number (4) | OID length (1) = 0
 * No object identifier is advertised.
 */
int lldp_tlv_put_mgmt_addr(struct lldp_buf *b, uint8_t addr_subtype,
			   const void *addr, size_t addr_len,
			   uint8_t if_subtype, uint32_t if_number)
{
	uint8_t v[1 + 1 + LLDP_MGMT_ADDR_MAX + 1 + 4 + 1];
	size_t n = 0;

	if (addr == NULL || addr_len < 1 || addr_len > LLDP_MGMT_ADDR_MAX) {
		b->err = 1;
		return -1;
	}
	v[n++] = (uint8_t)(1 + addr_len);
	v[n++] = addr_subtype;
	memcpy(v + n, addr, addr_len);
	n += addr_len;
	v[n++] = if_subtype;
	v[n++] = (uint8_t)(if_number >> 24);
	v[n++] = (uint8_t)(if_number >> 16);
	v[n++] = (uint8_t)(if_number >> 8);
	v[n++] = (uint8_t)if_number;
	v[n++] = 0;                             /* OID string length */
	return lldp_tlv_put(b, LLDP_TLV_MGMT_ADDR, v, n);
}

int lldp_tlv_put_org(struct lldp_buf *b, uint32_t oui, uint8_t subtype,
		     const void *info, size_t len)
{
	uint8_t v[4 + LLDP_ORG_INFO_MAX];

	if (oui > 0xffffffu || len > LLDP_ORG_INFO_MAX || (len > 0 && info == NULL)) {
		b->err = 1;
		return -1;
	}
	v[0] = (uint8_t)(oui >> 16);
	v[1] = (uint8_t)(oui >> 8);
	v[2] = (uint8_t)oui;
	v[3] = subtype;
	if (len > 0)
		memcpy(v + 4, info, len);
	return lldp_tlv_put(b, LLDP_TLV_ORG_SPECIFIC, v, 4 + len);
}

/* 802.3 Clause 79.3.4: maximum frame size the MAC/PHY supports, 2 octets */
int lldp_tlv_put_dot3_mfs(struct lldp_buf *b, uint16_t mfs)
{
	uint8_t v[2] = { (uint8_t)(mfs >> 8), (uint8_t)mfs };
	return lldp_tlv_put_org(b, LLDP_OUI_IEEE_8023, LLDP_8023_MAX_FRAME, v, sizeof v);
}

/* 8.5.1 End Of LLDPDU: type 0, length 0 */
int lldp_tlv_put_end(struct lldp_buf *b)
{
	return lldp_tlv_put(b, LLDP_TLV_END, NULL, 0);
}

void lldp_tlv_iter_init(struct lldp_tlv_iter *it, const uint8_t *data, size_t len)
{
	it->p = data;
	it->remaining = data ? len : 0;
}

int lldp_tlv_next(struct lldp_tlv_iter *it, struct lldp_tlv *t)
{
	unsigned type, len;

	if (it->remaining == 0)
		return 0;
	if (it->remaining < LLDP_TLV_HDR_LEN)
		return -1;                      /* truncated header */
	lldp_tlv_hdr_decode(it->p, &type, &len);
	if (len > it->remaining - LLDP_TLV_HDR_LEN)
		return -1;                      /* length overruns buffer */
	t->type  = type;
	t->len   = len;
	t->value = it->p + LLDP_TLV_HDR_LEN;
	it->p         += LLDP_TLV_HDR_LEN + len;
	it->remaining -= LLDP_TLV_HDR_LEN + len;
	return 1;
}
