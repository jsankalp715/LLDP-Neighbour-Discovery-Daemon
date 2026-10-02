/* test_txsched.c - transmit timing (802.1AB 9.2.8 / 9.2.10) on a simulated clock */
#include "test.h"
#include "../src/txsched.h"

#include <stdint.h>

/*
 * Run the scheduler the way the daemon does: sleep until txs_deadline(),
 * call txs_poll(). Records transmit times until `until` (exclusive) or
 * `max` transmissions.
 */
static unsigned run(struct tx_sched *s, uint64_t *t, uint64_t until,
		    uint64_t *times, unsigned max)
{
	unsigned n = 0;
	int guard = 0;

	while (n < max && guard++ < 10000) {
		uint64_t d = txs_deadline(s, *t);
		CHECK(d >= *t);
		if (d >= until)
			break;
		*t = d;
		if (txs_poll(s, *t))
			times[n++] = *t;
	}
	return n;
}

static void test_fast_start_then_interval(void)
{
	struct tx_sched s;
	uint64_t t = 5000, times[16];
	unsigned n;

	txs_init(&s, 30000, TXS_DEFAULT_FAST_MS, TXS_DEFAULT_FAST_INIT,
		 TXS_DEFAULT_CREDIT_MAX, t);
	n = run(&s, &t, 5000 + 100000, times, 16);
	/* 4 frames at msgFastTx = 1 s, then every msgTxInterval = 30 s */
	CHECK(n == 7);
	CHECK(times[0] == 5000 && times[1] == 6000 && times[2] == 7000 &&
	      times[3] == 8000);
	CHECK(times[4] == 38000 && times[5] == 68000 && times[6] == 98000);
	CHECK(s.sent == 7);
}

static void test_no_fast_start(void)
{
	struct tx_sched s;
	uint64_t t = 0, times[8];

	txs_init(&s, 2000, 1000, 0, 5, t);
	CHECK(run(&s, &t, 7000, times, 8) == 4);
	CHECK(times[0] == 0 && times[1] == 2000 && times[2] == 4000 && times[3] == 6000);
}

static void test_poll_only_when_due(void)
{
	struct tx_sched s;

	txs_init(&s, 10000, 1000, 0, 5, 0);
	CHECK(txs_poll(&s, 0) == 1);
	CHECK(txs_poll(&s, 1) == 0);           /* next is at 10000 */
	CHECK(txs_poll(&s, 9999) == 0);
	CHECK(txs_deadline(&s, 50) == 10000);
	CHECK(txs_poll(&s, 10000) == 1);
	/* late wakeup: deadline never lies in the past */
	CHECK(txs_deadline(&s, 25000) == 25000);
	CHECK(txs_poll(&s, 25000) == 1);
	CHECK(txs_deadline(&s, 25000) == 35000);
}

static void test_credit_limits_bursts(void)
{
	struct tx_sched s;
	uint64_t t = 0, times[32];
	unsigned i, n = 0;

	txs_init(&s, 30000, 1000, 0, 5, t);
	CHECK(txs_poll(&s, 0) == 1);           /* initial frame, credit now 4 */
	t = 100000;                            /* long idle: credit refilled to 5 */
	CHECK(txs_credit(&s, t) == 5);

	/* 12 local changes in a row: 5 go out at once, then one per txTick */
	for (i = 0; i < 12; i++) {
		uint64_t d;
		txs_trigger(&s);
		d = txs_deadline(&s, t);
		t = d;
		CHECK(txs_poll(&s, t) == 1);
		times[n++] = t;
	}
	for (i = 0; i < 5; i++)
		CHECK(times[i] == 100000);
	for (i = 5; i < 12; i++)
		CHECK(times[i] == 100000 + (i - 4) * 1000);
	CHECK(txs_credit(&s, t) == 0);
	/* credit refills by 1 per second up to the maximum, no further */
	CHECK(txs_credit(&s, t + 999) == 0);
	CHECK(txs_credit(&s, t + 1000) == 1);
	CHECK(txs_credit(&s, t + 3500) == 3);
	CHECK(txs_credit(&s, t + 3600000) == 5);
}

static void test_credit_blocks_periodic_too(void)
{
	struct tx_sched s;

	/* credit max 1, fast rate faster than tick refill would allow */
	txs_init(&s, 1000, 1000, 3, 1, 0);
	CHECK(txs_poll(&s, 0) == 1);           /* credit 0 */
	CHECK(txs_deadline(&s, 0) == 1000);    /* next tick */
	CHECK(txs_poll(&s, 500) == 0);
	CHECK(txs_poll(&s, 1000) == 1);
}

static void test_new_neighbour(void)
{
	struct tx_sched s;
	uint64_t t = 0, times[16];
	unsigned n;

	txs_init(&s, 30000, 1000, 4, 5, 0);
	n = run(&s, &t, 40000, times, 16);
	CHECK(n == 5);                          /* 0,1,2,3 s + 33 s */
	t = 50000;
	txs_new_neighbour(&s);
	CHECK(txs_deadline(&s, t) == 50000);
	n = run(&s, &t, 50000 + 40000, times, 16);
	/* immediate frame + 3 more at 1 s, then back to 30 s */
	CHECK(n == 5);
	CHECK(times[0] == 50000 && times[1] == 51000 && times[2] == 52000 &&
	      times[3] == 53000 && times[4] == 83000);
}

static void test_new_neighbour_during_fast(void)
{
	struct tx_sched s;

	txs_init(&s, 30000, 1000, 4, 5, 0);
	CHECK(txs_poll(&s, 0) == 1 && s.fast == 3);
	txs_new_neighbour(&s);                  /* ongoing fast phase: not extended */
	CHECK(s.fast == 3 && txs_deadline(&s, 100) == 100);
	CHECK(txs_poll(&s, 100) == 1 && s.fast == 2);

	/* fast transmission disabled: a new neighbour changes nothing */
	txs_init(&s, 30000, 1000, 0, 5, 0);
	CHECK(txs_poll(&s, 0) == 1);
	txs_new_neighbour(&s);
	CHECK(txs_deadline(&s, 10) == 30000);
}

static void test_trigger_resets_period(void)
{
	struct tx_sched s;

	txs_init(&s, 30000, 1000, 0, 5, 0);
	CHECK(txs_poll(&s, 0) == 1);
	txs_trigger(&s);
	CHECK(txs_deadline(&s, 12000) == 12000);
	CHECK(txs_poll(&s, 12000) == 1);
	/* the next periodic frame is a full interval after the triggered one */
	CHECK(txs_deadline(&s, 12000) == 42000);
}

static void test_degenerate_parameters(void)
{
	struct tx_sched s;

	txs_init(&s, 0, 0, 0, 0, 7);           /* clamped, never divides by zero */
	CHECK(s.interval_ms == 1 && s.fast_ms == 1 && s.credit_max == 1);
	CHECK(txs_poll(&s, 7) == 1);
	CHECK(txs_deadline(&s, 7) >= 7);
}

int main(void)
{
	RUN(test_fast_start_then_interval);
	RUN(test_no_fast_start);
	RUN(test_poll_only_when_due);
	RUN(test_credit_limits_bursts);
	RUN(test_credit_blocks_periodic_too);
	RUN(test_new_neighbour);
	RUN(test_new_neighbour_during_fast);
	RUN(test_trigger_resets_period);
	RUN(test_degenerate_parameters);
	return test_report("test_txsched");
}
