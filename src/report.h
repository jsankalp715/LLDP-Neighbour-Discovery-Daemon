/*
 * report.h - human and JSON renderings of the agent state, served on the
 *            control socket (ctl.c)
 */
#ifndef LLDP_REPORT_H
#define LLDP_REPORT_H

#include <stdint.h>
#include <stdio.h>

#include "agent.h"

/* Dispatch a control command: show | json | stats | local | help */
void report_command(const struct agent *ag, const char *cmd, FILE *out);

void report_show(const struct agent *ag, FILE *out);
void report_stats(const struct agent *ag, FILE *out);
void report_local(const struct agent *ag, FILE *out);
void report_json(const struct agent *ag, FILE *out);

/* One neighbour as a JSON object (exposed for tests and fuzzing). */
void report_neigh_json(const struct neigh *n, uint64_t now_ms, FILE *out);

/*
 * Write octets as a JSON string literal. Untrusted input: quote, backslash,
 * control characters and every non-ASCII octet are \u-escaped, so the
 * output is valid JSON (and valid UTF-8) whatever the input.
 */
void json_str(FILE *out, const uint8_t *s, size_t n);

#endif
