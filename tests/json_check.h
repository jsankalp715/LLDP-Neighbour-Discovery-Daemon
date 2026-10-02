/*
 * json_check.h - minimal strict JSON syntax validator (RFC 8259 grammar),
 * used to assert that everything the daemon emits as JSON parses, even when
 * it is built from hostile LLDPDU contents. Also rejects raw octets >= 0x80
 * because report.c promises pure-ASCII output.
 */
#ifndef LLDP_JSON_CHECK_H
#define LLDP_JSON_CHECK_H

#include <stddef.h>

struct jc { const char *p, *end; int depth; };

static int jc_value(struct jc *j);

static void jc_ws(struct jc *j)
{
	while (j->p < j->end && (*j->p == ' ' || *j->p == '\t' || *j->p == '\n' || *j->p == '\r'))
		j->p++;
}

static int jc_lit(struct jc *j, const char *s)
{
	size_t n = 0;
	while (s[n])
		n++;
	if ((size_t)(j->end - j->p) < n)
		return 0;
	for (size_t i = 0; i < n; i++)
		if (j->p[i] != s[i])
			return 0;
	j->p += n;
	return 1;
}

static int jc_hex(char c)
{
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static int jc_string(struct jc *j)
{
	if (j->p >= j->end || *j->p != '"')
		return 0;
	j->p++;
	while (j->p < j->end) {
		unsigned char c = (unsigned char)*j->p++;
		if (c == '"')
			return 1;
		if (c < 0x20 || c >= 0x80)
			return 0;
		if (c == '\\') {
			if (j->p >= j->end)
				return 0;
			c = (unsigned char)*j->p++;
			if (c == 'u') {
				if (j->end - j->p < 4)
					return 0;
				for (int i = 0; i < 4; i++)
					if (!jc_hex(j->p[i]))
						return 0;
				j->p += 4;
			} else if (!(c == '"' || c == '\\' || c == '/' || c == 'b' ||
				     c == 'f' || c == 'n' || c == 'r' || c == 't')) {
				return 0;
			}
		}
	}
	return 0;
}

static int jc_digits(struct jc *j)
{
	const char *s = j->p;
	while (j->p < j->end && *j->p >= '0' && *j->p <= '9')
		j->p++;
	return j->p > s;
}

static int jc_number(struct jc *j)
{
	if (j->p < j->end && *j->p == '-')
		j->p++;
	if (j->p < j->end && *j->p == '0')
		j->p++;
	else if (!jc_digits(j))
		return 0;
	if (j->p < j->end && *j->p == '.') {
		j->p++;
		if (!jc_digits(j))
			return 0;
	}
	if (j->p < j->end && (*j->p == 'e' || *j->p == 'E')) {
		j->p++;
		if (j->p < j->end && (*j->p == '+' || *j->p == '-'))
			j->p++;
		if (!jc_digits(j))
			return 0;
	}
	return 1;
}

static int jc_container(struct jc *j, char close, int object)
{
	if (++j->depth > 64)
		return 0;
	j->p++;
	jc_ws(j);
	if (j->p < j->end && *j->p == close) {
		j->p++;
		j->depth--;
		return 1;
	}
	for (;;) {
		jc_ws(j);
		if (object) {
			if (!jc_string(j))
				return 0;
			jc_ws(j);
			if (j->p >= j->end || *j->p++ != ':')
				return 0;
		}
		if (!jc_value(j))
			return 0;
		jc_ws(j);
		if (j->p >= j->end)
			return 0;
		if (*j->p == ',') {
			j->p++;
			continue;
		}
		if (*j->p == close) {
			j->p++;
			j->depth--;
			return 1;
		}
		return 0;
	}
}

static int jc_value(struct jc *j)
{
	jc_ws(j);
	if (j->p >= j->end)
		return 0;
	switch (*j->p) {
	case '{': return jc_container(j, '}', 1);
	case '[': return jc_container(j, ']', 0);
	case '"': return jc_string(j);
	case 't': return jc_lit(j, "true");
	case 'f': return jc_lit(j, "false");
	case 'n': return jc_lit(j, "null");
	default:  return jc_number(j);
	}
}

/* 1 if [s, s+n) is exactly one JSON value (plus surrounding whitespace) */
static inline int json_valid(const char *s, size_t n)
{
	struct jc j = { s, s + n, 0 };
	if (!jc_value(&j))
		return 0;
	jc_ws(&j);
	return j.p == j.end;
}

#endif
