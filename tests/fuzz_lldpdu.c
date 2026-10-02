/*
 * fuzz_lldpdu.c - fuzz the receive path (Ethernet parse -> LLDPDU validation
 * -> neighbour table -> formatting) with untrusted input.
 *
 * Built two ways:
 *   -DLIBFUZZER  : a libFuzzer target (make libfuzzer, needs clang)
 *   default      : a self-contained driver with its own PRNG that generates
 *                  purely random frames, mutations of valid seed frames and
 *                  structure-aware random TLV chains (make fuzz).
 *
 * Every input is copied into an exactly-sized heap buffer so that ASan flags
 * a one-byte over-read. Accepted LLDPDUs are re-encoded and re-parsed, and
 * the result must be identical (abort() otherwise).
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/lldpdu.h"
#include "../src/neigh.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static struct neigh_table fz_table;
static struct lldp_msg fz_msg, fz_msg2;
static uint64_t fz_clock;
static FILE *fz_null;
static int last_rc = -1;

static void id_put(struct lldp_buf *b, unsigned type, const struct lldp_id *id)
{
	lldp_tlv_put_id(b, type, id->subtype, id->id, id->len);
}

static void str_put(struct lldp_buf *b, unsigned type, const struct lldp_str *s)
{
	if (s->present)
		lldp_tlv_put(b, type, s->s, s->len);
}

static int str_same(const struct lldp_str *a, const struct lldp_str *b)
{
	return a->present == b->present && a->len == b->len &&
	       memcmp(a->s, b->s, a->len) == 0;
}

static int id_same(const struct lldp_id *a, const struct lldp_id *b)
{
	return a->subtype == b->subtype && a->len == b->len &&
	       memcmp(a->id, b->id, a->len) == 0;
}

/* Invariant: what we accepted, we can re-encode, and it decodes the same. */
static void roundtrip(const struct lldp_msg *m)
{
	uint8_t buf[1500];
	struct lldp_buf b;
	int rc;

	lldp_buf_init(&b, buf, sizeof buf);
	id_put(&b, LLDP_TLV_CHASSIS_ID, &m->chassis);
	id_put(&b, LLDP_TLV_PORT_ID, &m->port);
	lldp_tlv_put_ttl(&b, m->ttl);
	str_put(&b, LLDP_TLV_PORT_DESC, &m->port_desc);
	str_put(&b, LLDP_TLV_SYS_NAME, &m->sys_name);
	str_put(&b, LLDP_TLV_SYS_DESC, &m->sys_desc);
	lldp_tlv_put_end(&b);
	if (b.err) {
		fprintf(stderr, "roundtrip: accepted message cannot be re-encoded\n");
		abort();
	}
	rc = lldpdu_parse(buf, b.len, &fz_msg2);
	if (rc != LLDP_OK || !id_same(&m->chassis, &fz_msg2.chassis) ||
	    !id_same(&m->port, &fz_msg2.port) || m->ttl != fz_msg2.ttl ||
	    !str_same(&m->port_desc, &fz_msg2.port_desc) ||
	    !str_same(&m->sys_name, &fz_msg2.sys_name) ||
	    !str_same(&m->sys_desc, &fz_msg2.sys_desc)) {
		fprintf(stderr, "roundtrip: mismatch (rc=%d)\n", rc);
		abort();
	}
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct eth_view v;
	const struct neigh *n;
	char out[LLDP_IDFMT_MAX];
	int rc;

	if (!fz_null) {
		fz_null = fopen("/dev/null", "w");
		neigh_init(&fz_table);
	}

	/* the raw input as a bare LLDPDU */
	(void)lldpdu_parse(data, size, &fz_msg);

	/* the raw input as an Ethernet frame, like the daemon sees it */
	if (eth_frame_parse(data, size, &v) < 0) {
		last_rc = -1;
		return 0;
	}
	rc = lldpdu_parse(v.payload, v.payload_len, &fz_msg);
	last_rc = rc;
	if (rc != LLDP_OK)
		return 0;

	roundtrip(&fz_msg);
	lldp_id_format(&fz_msg.chassis, 1, out, sizeof out);
	lldp_id_format(&fz_msg.port, 0, out, sizeof out);

	fz_clock += 250;
	(void)neigh_update(&fz_table, &fz_msg, v.src, fz_clock, &n);
	if ((fz_clock / 250) % 64 == 0) {
		neigh_age(&fz_table, fz_clock, NULL, NULL);
		if (fz_null)
			neigh_print(&fz_table, fz_clock, fz_null);
	}
	return 0;
}

#ifndef LIBFUZZER

static uint64_t rng_state = 0x9e3779b97f4a7c15ull;

static uint64_t rnd(void)
{
	/* xorshift64* */
	rng_state ^= rng_state >> 12;
	rng_state ^= rng_state << 25;
	rng_state ^= rng_state >> 27;
	return rng_state * 0x2545f4914f6cdd1dull;
}

static unsigned rn(unsigned n) { return n ? (unsigned)(rnd() % n) : 0; }

#define MAX_SEEDS 8
static uint8_t seeds[MAX_SEEDS][LLDP_FRAME_MAX];
static size_t seed_len[MAX_SEEDS];
static unsigned n_seeds;

static void add_seed(const uint8_t *f, size_t len)
{
	memcpy(seeds[n_seeds], f, len);
	seed_len[n_seeds++] = len;
}

static void make_seeds(void)
{
	uint8_t f[LLDP_FRAME_MAX], pdu[1500];
	char longs[256];
	struct lldp_local_info li = {
		.mac = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 }, .ifname = "eth0",
		.ttl = 121, .port_desc = "uplink", .sys_name = "fuzz",
		.sys_desc = "Linux fuzz",
	};
	struct lldp_buf b;
	ssize_t n;

	n = lldp_frame_build(&li, f, sizeof f);
	add_seed(f, (size_t)n);
	li.ttl = 0;
	n = lldp_frame_build(&li, f, sizeof f);                 /* shutdown */
	add_seed(f, (size_t)n);
	li.ttl = 65535;
	li.port_desc = li.sys_name = li.sys_desc = NULL;
	n = lldp_frame_build(&li, f, sizeof f);                 /* minimal */
	add_seed(f, (size_t)n);

	memset(longs, 'L', 255);
	longs[255] = '\0';
	li.port_desc = li.sys_name = li.sys_desc = longs;
	li.ttl = 9;
	n = lldp_frame_build(&li, f, sizeof f);                 /* maximal strings */
	add_seed(f, (size_t)n);

	/* every TLV kind we understand, plus unknown ones */
	lldp_buf_init(&b, pdu, sizeof pdu);
	lldp_tlv_put_id(&b, 1, 7, "chassis-local", 13);
	lldp_tlv_put_id(&b, 2, 3, "\x02\x00\x00\x00\x00\x01", 6);
	lldp_tlv_put_ttl(&b, 120);
	lldp_tlv_put(&b, 7, "\x00\x14\x00\x04", 4);
	lldp_tlv_put(&b, 8, "\x05\x01\x0a\x00\x00\x01\x02\x00\x00\x00\x03\x00", 12);
	lldp_tlv_put(&b, 127, "\x00\x80\xc2\x01\x00\x01", 6);
	lldp_tlv_put(&b, 42, "unknown", 7);
	lldp_tlv_put_sys_name(&b, "all-tlvs");
	lldp_tlv_put_end(&b);
	n = eth_frame_build(f, sizeof f, LLDP_MCAST_NEAREST_BRIDGE, li.mac,
			    ETHERTYPE_LLDP, pdu, b.len);
	add_seed(f, (size_t)n);
}

static size_t mutate(uint8_t *buf, size_t len, size_t cap)
{
	static const uint8_t interesting[] = { 0x00, 0x01, 0x02, 0x7f, 0x80, 0xfe, 0xff };
	unsigned k, rounds = 1 + rn(8);

	for (k = 0; k < rounds; k++) {
		size_t pos = len ? rn((unsigned)len) : 0;
		switch (rn(9)) {
		case 0: if (len) buf[pos] ^= (uint8_t)(1u << rn(8)); break;
		case 1: if (len) buf[pos] = (uint8_t)rnd(); break;
		case 2: if (len) buf[pos] = interesting[rn(sizeof interesting)]; break;
		case 3: /* corrupt something that is likely a TLV length octet */
			if (len > 15) {
				pos = 14 + rn((unsigned)(len - 14));
				buf[pos] = (uint8_t)rnd();
				if (pos + 1 < len) buf[pos + 1] = (uint8_t)rnd();
			}
			break;
		case 4: len = rn((unsigned)len + 1); break;        /* truncate */
		case 5: /* extend with random bytes */
			while (len < cap && rn(16)) buf[len++] = (uint8_t)rnd();
			break;
		case 6: /* delete a range */
			if (len > 1) {
				size_t dl = 1 + rn((unsigned)(len - pos));
				if (pos + dl > len) dl = len - pos;
				memmove(buf + pos, buf + pos + dl, len - pos - dl);
				len -= dl;
			}
			break;
		case 7: /* duplicate a chunk (repeat TLVs) */
			if (len > 16) {
				size_t from = 14 + rn((unsigned)(len - 14));
				size_t cl = 1 + rn(32);
				if (from + cl > len) cl = len - from;
				if (len + cl <= cap) {
					memmove(buf + pos + cl, buf + pos, len - pos);
					memcpy(buf + pos, buf + (from < pos ? from : from + cl), cl);
					len += cl;
				}
			}
			break;
		case 8: /* splice the tail of another seed */
			{
				unsigned s = rn(n_seeds);
				size_t off = rn((unsigned)seed_len[s]);
				size_t cl = seed_len[s] - off;
				if (pos + cl > cap) cl = cap - pos;
				memcpy(buf + pos, seeds[s] + off, cl);
				len = pos + cl;
			}
			break;
		}
	}
	return len;
}

/* random TLV chain: valid header layout, adversarial types and lengths */
static size_t structured(uint8_t *buf, size_t cap)
{
	static const unsigned types[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 127, 9, 126 };
	struct lldp_buf b;
	uint8_t val[511];
	unsigned i, ntlv = rn(12);
	size_t j;

	memcpy(buf, LLDP_MCAST_NEAREST_BRIDGE, 6);
	for (j = 6; j < 12; j++) buf[j] = (uint8_t)rnd();
	buf[12] = 0x88; buf[13] = 0xcc;
	lldp_buf_init(&b, buf + 14, cap - 14);
	if (rn(4)) {                              /* usually start plausibly */
		uint8_t st = (uint8_t)(rn(10));
		static const uint8_t cid[8] = { 0x02, 0, 0, 0, 0, 0x01, 0xaa, 0xbb };
		lldp_tlv_put_id(&b, 1, st, cid, 1 + rn(sizeof cid));
		lldp_tlv_put_id(&b, 2, (uint8_t)rn(10), "eth0eth0", 1 + rn(8));
		if (rn(4)) lldp_tlv_put_ttl(&b, (uint16_t)rnd());
	}
	for (i = 0; i < ntlv; i++) {
		unsigned t = rn(3) ? types[rn(sizeof types / sizeof types[0])] : rn(128);
		unsigned l = rn(4) ? rn(16) : rn(512);
		for (j = 0; j < l; j++) val[j] = (uint8_t)rnd();
		if (t == 8 && l > 0) val[0] = (uint8_t)rn(40);
		lldp_tlv_put(&b, t, val, l);
	}
	if (rn(4)) lldp_tlv_put_end(&b);
	return 14 + b.len - (rn(8) == 0 && b.len ? 1 + rn((unsigned)b.len) : 0);
}

int main(int argc, char **argv)
{
	unsigned long iters = argc > 1 ? strtoul(argv[1], NULL, 10) : 1000000ul;
	unsigned long i, hist[LLDP_E_COUNT + 1] = { 0 }, per_strategy[3] = { 0 };
	uint8_t work[LLDP_FRAME_MAX + 128];
	int r;

	if (argc > 2)
		rng_state = strtoull(argv[2], NULL, 0) | 1;
	make_seeds();

	/* every seed must be accepted, or the fuzzer starts from garbage */
	for (i = 0; i < n_seeds; i++) {
		LLVMFuzzerTestOneInput(seeds[i], seed_len[i]);
		if (last_rc != LLDP_OK) {
			fprintf(stderr, "seed %lu rejected: %s\n", i, lldp_strerror(last_rc));
			return 1;
		}
	}

	for (i = 0; i < iters; i++) {
		size_t len;
		unsigned strat = rn(3);
		uint8_t *exact;

		switch (strat) {
		case 0:                                 /* pure random */
			len = rn(sizeof work);
			for (size_t j = 0; j < len; j++) work[j] = (uint8_t)rnd();
			if (rn(2)) {                    /* give it a valid header */
				memcpy(work, LLDP_MCAST_NEAREST_BRIDGE, 6);
				if (len > 14) { work[12] = 0x88; work[13] = 0xcc; }
			}
			break;
		case 1: {                               /* mutate a seed */
			unsigned s = rn(n_seeds);
			memcpy(work, seeds[s], seed_len[s]);
			len = mutate(work, seed_len[s], sizeof work);
			break;
		}
		default:
			len = structured(work, sizeof work);
			break;
		}
		per_strategy[strat]++;

		exact = malloc(len ? len : 1);
		if (!exact)
			return 1;
		memcpy(exact, work, len);
		LLVMFuzzerTestOneInput(exact, len);
		free(exact);

		r = last_rc;
		hist[r < 0 ? LLDP_E_COUNT : r]++;
	}

	printf("fuzz_lldpdu: %lu iterations (random %lu, mutated %lu, structured %lu)\n",
	       iters, per_strategy[0], per_strategy[1], per_strategy[2]);
	for (r = 0; r < LLDP_E_COUNT; r++)
		printf("  %-42s %lu\n", lldp_strerror(r), hist[r]);
	printf("  %-42s %lu\n", "runt (< 14 octets)", hist[LLDP_E_COUNT]);
	printf("  neighbour table at end: %u entries\n", fz_table.count);
	if (fz_null)
		fclose(fz_null);
	printf("fuzz_lldpdu: PASS (no crashes, no sanitizer reports, round-trip held)\n");
	return 0;
}
#endif
