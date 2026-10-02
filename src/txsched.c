/*
 * txsched.c - transmit timing: txTTR / txFast / txCredit / txNow
 *             (IEEE Std 802.1AB-2016, 9.2.5, 9.2.8, 9.2.10)
 *
 * The standard decrements txTTR and increments txCredit from a one-second
 * txTick. Instead of waking every second, credit is computed lazily from
 * the time elapsed since it last ticked, so an idle agent only wakes for
 * the transmissions it actually makes.
 */
#include "txsched.h"

#include <stddef.h>

void txs_init(struct tx_sched *s, uint32_t interval_ms, uint32_t fast_ms,
	      unsigned fast_init, unsigned credit_max, uint64_t now)
{
	s->interval_ms = interval_ms ? interval_ms : 1;
	s->fast_ms = fast_ms ? fast_ms : 1;
	s->fast_init = fast_init;
	s->credit_max = credit_max ? credit_max : 1;
	s->fast = fast_init;
	s->credit = s->credit_max;
	s->credit_ts = now;
	s->next_ms = now;          /* first LLDPDU immediately */
	s->now = 0;
	s->sent = 0;
}

void txs_trigger(struct tx_sched *s)
{
	s->now = 1;
}

void txs_new_neighbour(struct tx_sched *s)
{
	/*
	 * 9.2.10 TX_FAST_START: newNeighbor -> if txFast is 0 it is reloaded
	 * with txFastInit and the timer expires at once. An ongoing fast
	 * phase is not extended. txFastInit 0 (our "-f 0") disables this.
	 */
	if (s->fast_init == 0)
		return;
	if (s->fast == 0)
		s->fast = s->fast_init;
	s->now = 1;
}

/* credit after the whole seconds elapsed since credit_ts (txTick) */
static unsigned credit_at(const struct tx_sched *s, uint64_t t, uint64_t *ts_out)
{
	uint64_t ticks = t > s->credit_ts ? (t - s->credit_ts) / 1000u : 0;
	uint64_t c = (uint64_t)s->credit + ticks;

	if (ts_out)
		*ts_out = s->credit_ts + ticks * 1000u;
	return c >= s->credit_max ? s->credit_max : (unsigned)c;
}

unsigned txs_credit(const struct tx_sched *s, uint64_t now)
{
	return credit_at(s, now, NULL);
}

uint64_t txs_deadline(const struct tx_sched *s, uint64_t now)
{
	uint64_t due = s->now ? now : s->next_ms;

	if (due < now)
		due = now;
	if (credit_at(s, due, NULL) == 0) {
		/* no credit: wait for the next txTick that grants one */
		uint64_t tick = s->credit_ts + 1000u;
		while (tick <= due)
			tick += 1000u;
		due = tick;
	}
	return due;
}

int txs_poll(struct tx_sched *s, uint64_t now)
{
	uint64_t ts;
	unsigned c = credit_at(s, now, &ts);

	/* bring the credit accounting forward */
	if (c >= s->credit_max) {
		s->credit = s->credit_max;
		s->credit_ts = now;        /* full: the tick clock restarts on use */
	} else {
		s->credit = c;
		s->credit_ts = ts;
	}

	if (!s->now && now < s->next_ms)
		return 0;                  /* nothing due */
	if (s->credit == 0)
		return 0;                  /* 9.2.8: transmit only while txCredit > 0 */

	s->credit--;
	s->now = 0;
	if (s->fast > 0)
		s->fast--;
	/* 9.2.10: txTTR restarts at msgFastTx while fast, else msgTxInterval */
	s->next_ms = now + (s->fast > 0 ? s->fast_ms : s->interval_ms);
	s->sent++;
	return 1;
}
