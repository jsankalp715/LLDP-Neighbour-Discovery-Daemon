/* test.h - minimal assertion harness shared by the unit tests */
#ifndef LLDP_TEST_H
#define LLDP_TEST_H

#include <stdio.h>
#include <string.h>

static int t_checks;
static int t_failures;

#define CHECK(cond) do {                                                    \
	t_checks++;                                                         \
	if (!(cond)) {                                                      \
		t_failures++;                                               \
		fprintf(stderr, "%s:%d: CHECK failed: %s\n",                \
			__FILE__, __LINE__, #cond);                         \
	}                                                                   \
} while (0)

#define CHECK_MEM(a, b, n) CHECK(memcmp((a), (b), (n)) == 0)

#define RUN(fn) do { fn(); } while (0)

static inline int test_report(const char *name)
{
	if (t_failures) {
		fprintf(stderr, "%s: FAIL (%d of %d checks failed)\n",
			name, t_failures, t_checks);
		return 1;
	}
	printf("%s: PASS (%d checks)\n", name, t_checks);
	return 0;
}

#endif
