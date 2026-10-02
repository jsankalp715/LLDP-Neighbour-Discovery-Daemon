/*
 * txsched.h - when to transmit: the transmit timer state machine
 *             (IEEE Std 802.1AB-2016, 9.2.10) and the credit/fast-start
 *             variables of the transmit state machine (9.2.8, 9.2.5).
 *
 * Pure logic on an injected monotonic clock (ms) so it can be unit-tested
 * without sleeping. The daemon asks txs_deadline() when to wake up, arms a
 * timerfd for that instant, and calls txs_poll() when it fires.
 *
 *   txTTR      next periodic transmission (msgTxInterval, or msgFastTx
 *              while txFast > 0)
 *   txFast     transmissions left at the fast rate (txFastInit, 9.2.5.19)
 *   txCredit   transmissions allowed back-to-back (txCreditMax, 9.2.5.17),
 *              refilled by one per second (txTick)
 *   txNow      transmit as soon as credit allows (local change)
 */
#ifndef LLDP_TXSCHED_H
#define LLDP_TXSCHED_H

#include <stdint.h>

/* defaults from 9.2.5: msgFastTx 1 s, txFastInit 4, txCreditMax 5 */
#define TXS_DEFAULT_FAST_MS     1000u
#define TXS_DEFAULT_FAST_INIT   4u
#define TXS_DEFAULT_CREDIT_MAX  5u

struct tx_sched {
	uint32_t interval_ms;     /* msgTxInterval (9.2.5.7) */
	uint32_t fast_ms;         /* msgFastTx (9.2.5.5) */
	unsigned fast_init;       /* txFastInit (9.2.5.19) */
	unsigned credit_max;      /* txCreditMax (9.2.5.17) */

	unsigned fast;            /* txFast */
	unsigned credit;          /* txCredit as of credit_ts */
	uint64_t credit_ts;       /* when credit last ticked (whole seconds) */
	uint64_t next_ms;         /* txTTR expiry */
	int      now;             /* txNow */
	uint64_t sent;            /* transmissions granted */
};

/*
 * Initialise (txInitializeLLDP, 9.2.7.12): full credit, and a fast start of
 * fast_init frames so new neighbours learn this port quickly.
 */
void txs_init(struct tx_sched *s, uint32_t interval_ms, uint32_t fast_ms,
	      unsigned fast_init, unsigned credit_max, uint64_t now);

/* Local information changed (somethingChangedLocal): transmit ASAP. */
void txs_trigger(struct tx_sched *s);

/* A new neighbour was detected (newNeighbor): restart the fast phase. */
void txs_new_neighbour(struct tx_sched *s);

/* Monotonic time at which txs_poll() should next be called (>= now). */
uint64_t txs_deadline(const struct tx_sched *s, uint64_t now);

/* Returns 1 if an LLDPDU should be sent now (state advanced), else 0. */
int txs_poll(struct tx_sched *s, uint64_t now);

/* Credit available at time now (for display/tests). */
unsigned txs_credit(const struct tx_sched *s, uint64_t now);

#endif
