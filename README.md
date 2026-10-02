# lldpnd: an LLDP (IEEE 802.1AB) neighbour discovery daemon in C

`lldpnd` implements the Link Layer Discovery Protocol from the standard over raw
`AF_PACKET` sockets. It builds and parses the Ethernet II frames and TLVs by hand,
with no libpcap, lldpd or LLDP library. It keeps a neighbour table with TTL-based
ageing, transmits periodically, and treats every received byte as untrusted.

* C11, Linux only, `-Wall -Wextra -Werror` (plus `-Wshadow -Wstrict-prototypes
  -Wmissing-prototypes -Wvla -Wformat=2 -Wpointer-arith`)
* single-threaded `epoll` loop: a socket, three `timerfd`s and a `signalfd`, with no busy-waiting
* clean under AddressSanitizer + UBSan and valgrind memcheck. The parser was fuzzed
  with 12 M driver iterations and 15 M libFuzzer executions.
* tested end to end on a 3-namespace Linux bridge testbed, with captures decoded by
  Wireshark's dissector (`tshark`)

```
src/
  tlv.[ch]      TLV header encode/decode (7-bit type, 9-bit length), builders, iterator
  frame.[ch]    Ethernet II build/parse, SIOCGIFHWADDR, 01:80:C2:00:00:0E, 0x88CC
  lldpdu.[ch]   LLDPDU builder + validating parser, safe formatting of untrusted strings
  neigh.[ch]    neighbour table keyed by (Chassis ID, Port ID), TTL expiry, refresh
  rawsock.[ch]  AF_PACKET socket: bind to ifindex + 0x88CC, PACKET_ADD_MEMBERSHIP
  main.c        CLI, epoll/timerfd/signalfd event loop, statistics
tests/
  test_tlv.c test_frame.c test_lldpdu.c test_neigh.c   unit tests (350 checks)
  test_rawsock.c                                       raw socket integration test (root)
  fuzz_lldpdu.c                                        fuzz driver / libFuzzer target
scripts/
  testbed.sh       3-namespace bridge testbed (root)
  inject_lldp.py   crafts malformed/edge-case LLDP frames for the testbed
  idle_check.sh    proves the daemon sleeps in epoll_wait when idle
```

## Build and run

```bash
make                  # daemon + tests into build/
make test             # unit tests
make check            # unit tests + valgrind + ASan/UBSan + fuzz driver
sudo make rawsock-test
sudo make testbed
sudo make libfuzzer FUZZ_SECS=120   # needs clang
```

```
usage: lldpnd -i <interface> [options]
  -i IF     interface to run LLDP on (required)
  -t SECS   transmit interval, msgTxInterval (1-3600, default 30)
  -H N      hold multiplier, msgTxHold (1-100, default 4);
            advertised TTL = min(65535, SECS * N + 1)
  -p SECS   print neighbour table every SECS (default: on change only)
  -n NAME   System Name TLV (default: hostname)
  -d DESC   System Description TLV (default: uname)
  -P DESC   Port Description TLV (default: "LLDP port <IF>")
```

It needs `CAP_NET_RAW` (root). SIGINT or SIGTERM sends a shutdown LLDPDU, prints the
table and statistics, and exits 0. A real log excerpt from the testbed:

```
22:48:22.260 [eth0] lldpnd started: ifindex=2 chassis=02:00:00:00:00:01 port=eth0 tx-interval=2s ttl=7s
22:48:28.261 [eth0] NEIGHBOUR ADD chassis=02:00:00:00:00:02 port=eth0(st5) name=ns2 ttl=7
22:48:31.386 [eth0] rx: discard from 02:00:00:00:00:99: truncated TLV / length exceeds frame
22:48:31.436 [eth0] rx: discard from 02:00:00:00:00:99: third TLV is not TTL
22:48:37.262 [eth0] NEIGHBOUR AGEOUT chassis=02:00:00:00:00:03 port=eth0(st5) name=ns3 ttl=7 (TTL expired, last rx 7000 ms ago)
22:48:37.328 [eth0] NEIGHBOUR DELETE chassis=02:00:00:00:00:02 port=eth0(st5) name=ns2 ttl=7 (shutdown LLDPDU)
22:48:38.364 [eth0] stats: out=10 in=20 discarded=10 in_errors=10 tlvs_unrecognized=1 ageouts=1 too_many_neighbors=0
```

## Design

### Layers

Each layer was built and tested before the next one was started.

1. **TLV (`tlv.c`, clause 8.4).** The header is `(type << 9) | length`, big-endian.
   The builders write into a bounded `lldp_buf` whose error flag latches, so a
   builder can issue a sequence of puts and check once. Each builder enforces its
   TLV's legal length: IDs 1..255 octets, strings 0..255, TTL exactly 2. The iterator
   (`lldp_tlv_next`) is the only code that walks received TLVs. It rejects a
   truncated header and any length that runs past the buffer, so nothing downstream
   ever sees an out-of-bounds value pointer.
2. **Ethernet (`frame.c`, clause 7).** Each frame is dst `01:80:C2:00:00:0E`, src (from
   `SIOCGIFHWADDR`, which must be `ARPHRD_ETHER`), EtherType `0x88CC`, then the LLDPDU.
   Frames are zero-padded to the 60-octet minimum (the NIC appends the FCS).
3. **Raw socket (`rawsock.c`).** The socket is `socket(AF_PACKET, SOCK_RAW, 0)`, followed
   by `bind()` with `sll_protocol = htons(0x88CC)` and the interface index. Creating it
   with protocol 0 means it receives nothing until it is bound to one interface *and* the
   LLDP EtherType. Creating it with `ETH_P_LLDP` directly would briefly receive LLDP from
   every interface. `PACKET_ADD_MEMBERSHIP` (`PACKET_MR_MULTICAST`) programs the group
   address into the device filter, which the integration test verifies via
   `/proc/net/dev_mcast`. `recvfrom(MSG_TRUNC)` detects oversized frames, and
   `sll_pkttype == PACKET_OUTGOING` identifies our own transmissions.
4. **Parser + neighbour table (`lldpdu.c`, `neigh.c`).** These are covered in the next two sections.
5. **Event loop (`main.c`).**
   * tx `timerfd`: fires once immediately, then every `msgTxInterval`.
   * age `timerfd`: one-shot, absolute `CLOCK_MONOTONIC`, re-armed after every change
     to the *earliest* neighbour expiry. It wakes exactly when an entry expires rather
     than polling every second.
   * print `timerfd`: optional (`-p`). Without it, the table is printed whenever it changes.
   * `signalfd`: SIGINT and SIGTERM are blocked and read as events, so no code runs in
     signal context.
   * socket: drained up to 64 frames per wakeup.

   `scripts/idle_check.sh` measured **4 wakeups in 20 s with `-t 5` (one per transmit),
   0 ms of CPU, and the process parked in `do_epoll_wait`**.

### Receive validation (clauses 8.2, 8.5, and 9.2.7 rxProcessFrame)

All received data is untrusted. An LLDPDU is discarded, and counted in
`statsFramesDiscardedTotal` / `statsFramesInErrorsTotal`, if any of these hold:

| Rule | Error |
|---|---|
| a TLV header or length runs past the end of the frame | `truncated TLV / length exceeds frame` |
| TLV 1, 2 and 3 are not Chassis ID, Port ID and TTL, in that order (this also covers a missing mandatory TLV) | `first/second/third TLV is not …` |
| no End Of LLDPDU before the data runs out | `missing End Of LLDPDU TLV` |
| End Of LLDPDU has a nonzero length | `End Of LLDPDU TLV with nonzero length` |
| Chassis/Port ID length is not 2..256, its subtype is reserved (0 or 8..255), a MAC subtype carries other than 6 octets, or a network-address subtype carries fewer than 2 | `invalid Chassis ID / Port ID TLV` |
| TTL length ≠ 2 | `invalid TTL TLV length` |
| Chassis ID, Port ID or TTL appears again later | `mandatory TLV repeated` |
| Port Desc / Sys Name / Sys Desc / Sys Cap appears twice | `single-instance optional TLV repeated` |
| a string TLV is over 255, Sys Cap ≠ 4, an org-specific TLV is under 4, or a Management Address has internal lengths that don't add up (8.5.9) | `optional TLV has invalid length` |

Two cases are accepted rather than rejected:

* Reserved TLV types 9..126 and well-formed org-specific (127) TLVs are skipped and
  counted (`statsTLVsUnrecognizedTotal`).
* Anything after End Of LLDPDU is treated as padding and ignored.

The parser copies values into fixed-size fields of `struct lldp_msg`, so it needs no
allocation. Every string printed from the network is escaped (`\xNN` for anything
non-printable, including `\`). This prevents terminal-escape injection, and a test
covers it.

### Neighbour table (9.2.7, 9.2.9)

* **Key and capacity.** Entries are keyed by Chassis ID and Port ID, comparing subtype,
  length and bytes. The table has a fixed 32 entries: memory is bounded and there is no
  allocation on the receive path. When it is full, new neighbours are dropped
  (`tooManyNeighbors`) while existing ones keep refreshing.
* **On reception.** A received LLDPDU makes an entry `ADD`ed (new), `UPDATE`d (content
  or TTL changed) or `REFRESH`ed (identical). Either way its expiry restarts at
  `now + TTL`.
* **Shutdown and expiry.** TTL 0 is a shutdown LLDPDU and deletes the entry
  immediately. An expired entry is removed with an `AGEOUT` log line that includes the
  monotonic time since its last LLDPDU.

### Transmit

The transmitted TLVs are Chassis ID (subtype 4, MAC), Port ID (subtype 5, ifName), TTL,
Port Description, System Name, System Description and End. The advertised TTL is
`min(65535, msgTxInterval × msgTxHold + 1)`, which is 121 s with the defaults. On exit
the daemon sends a shutdown LLDPDU (9.2.7 mkShutdownLLDPDU), containing only the
mandatory TLVs with TTL 0.

## Decisions and deviations

* **Development environment.** The host is Windows 11, so everything was built and run
  in WSL2 (Ubuntu 24.04, kernel 6.18, gcc 13.3, clang 18, valgrind 3.22, tshark 4.2.2)
  via `wsl -u root`. No source depends on that.
* **Destination address.** Only the nearest-bridge group address `01:80:C2:00:00:0E` is
  used for tx and rx. The nearest-non-TPMR (`…03`) and nearest-customer-bridge (`…00`)
  addresses are not joined, and frames sent to them are discarded.
* **Stricter-than-minimal validation.** The daemon rejects reserved Chassis/Port ID
  subtypes, duplicate single-instance optional TLVs, and inconsistent Management
  Address internal lengths. It is safer to drop such frames than to guess.
* **One interface per process.** You run one instance per port, which keeps the code
  single-threaded and simple.
* **Not implemented.** The following parts of the agent are not implemented: fast-start
  transmission (`txFast`), the transmit credit (`txCredit`/`msgFastTx`), `reinitDelay`,
  transmitting on local-information change, the System Capabilities and Management
  Address TLVs (both are *parsed*, not sent), the MIB/SNMP side, and VLAN-tagged LLDP.
* **Clause references.** Comments cite 802.1AB-2016. Clause 7 (addressing) and clause 8
  (8.4 TLV format, 8.5.x basic TLVs, 8.6 org-specific) are cited by number. Clause 9 is
  cited by procedure and variable name (rxProcessFrame, mkShutdownLLDPDU, rxInfoAge,
  msgTxInterval/msgTxHold, the `stats*` counters). The exact subclause numbers in
  `main.c` should be checked against the text: this was written without the standard
  at hand.

## Testbed (`scripts/testbed.sh`)

```
     lldp-ns1            lldp-ns2            lldp-ns3
  eth0 02:..:01       eth0 02:..:02       eth0 02:..:03
       |                   |                   |
     brp1 ------------- brp2 -------------- brp3
              br0 (Linux bridge, netns lldp-br)
```

The script uses four network namespaces (the bridge gets its own, so the host is
untouched) with `-t 2 -H 3`, giving TTL = 7 s. A capture runs on bridge port `brp1`.

> **Bridge forwarding.** `01:80:C2:00:00:0E` is a reserved link-local group address.
> A standards-compliant bridge consumes it instead of forwarding it, which is the whole
> point of "nearest bridge" LLDP. A Linux bridge therefore needs
> `group_fwd_mask 0x4000` (bit 14 = `…0E`) before namespaces behind it can see each
> other. Phase 0 demonstrates the default behaviour first.

| Phase | What it does | What is checked |
|---|---|---|
| 0 | default bridge | no neighbour is learned (the bridge correctly drops `…0E`) |
| 1 | `group_fwd_mask 0x4000` | all 6 directed adjacencies are learned (~1.1 s), each table shows 2 entries, and Port Description is received |
| 2 | `inject_lldp.py` sends 10 malformed frames and 2 valid edge cases from ns2 | ns1 logs the exact rejection reason for each malformed frame, accepts the valid frame with a reserved TLV type and an org-specific TLV, deletes it again on its TTL-0 frame, and stays up |
| 3 | `kill -9` the ns3 daemon and `ip netns del lldp-ns3` | ns1 and ns2 age ns3 out between TTL−TX and TTL after the kill, **exactly 7000 ms after its last LLDPDU** by the daemon's own monotonic clock, and do not age out each other |
| 4 | `kill -INT` ns2 | ns1 deletes ns2 within ~12 ms via the shutdown LLDPDU, and ns2 exits 0 |
| 5 | `kill -INT` ns1, then decode the capture with `tshark` | all daemon frames decode as LLDP with no malformed/expert warnings, the TTL-0 frames come only from ns1 and ns2, and the decoded chassis MAC, port ID, TTL, system name and port description of all three match |

Artifacts are written to `build/testbed/`: `lldp.pcap`, `dissection.txt` (full
`tshark -V -x` of a normal and a shutdown LLDPDU), `summary.tsv`, `ns{1,2,3}.log`, and
`clock.log`. `BIN=build/asan/lldpnd` runs the daemons under ASan, and `VALGRIND=1` runs
them under valgrind (a leak or error then shows up as a non-zero exit on SIGINT).

To watch or capture by hand while the testbed runs:

```bash
ip netns exec lldp-br tcpdump -i brp1 -nn -e -vv ether proto 0x88cc       # tcpdump decodes LLDP with -v
ip netns exec lldp-br tcpdump -i brp1 -U --immediate-mode -w lldp.pcap ether proto 0x88cc
tshark -r build/testbed/lldp.pcap -Y lldp -V            # Wireshark's LLDP dissector
tshark -r build/testbed/lldp.pcap -Y '_ws.malformed'    # should list only injected frames
wireshark build/testbed/lldp.pcap
```

## Test results

All of the following were run on 2026-10-02 from a clean build.

| Test | Result |
|---|---|
| `test_tlv`: header known values, exhaustive 128×512 encode/decode round trip, overflow, builders vs hand bytes, limits, iterator truncation | **PASS** (65 checks) |
| `test_frame`: **byte-for-byte match of a full frame against a hand-computed 60-octet frame**, shutdown frame, padding, limits, SIOCGIFHWADDR errors | **PASS** (27) |
| `test_lldpdu`: builder → parser round trip, every rejection rule, boundary lengths (255/256, 0, 511), escaping, ID formatting | **PASS** (179) |
| `test_neigh`: keying (subtype-sensitive, prefix-safe), refresh/update, expiry exactly at TTL, TTL 0, table full, escaped printing | **PASS** (79) |
| `test_rawsock` (veth pair in private netns): byte-identical A→B and B→A, multicast membership in `/proc/net/dev_mcast`, IPv4/0x88B5/0x88CD frames filtered, truncation flag, PACKET_OUTGOING | **PASS** (27) |
| All of the above under **valgrind** (`--leak-check=full --errors-for-leak-kinds=all`) | **PASS**, 0 errors, 0 leaks |
| All of the above under **ASan + UBSan** (`-fno-sanitize-recover=all`) | **PASS** |
| Fuzz driver under ASan+UBSan: 2 M iterations (seed default) + 10 M (seed `0xdeadbeef`), split evenly between random, seed-mutation and structure-aware generation; every rejection path hit; accepted frames re-encoded and re-parsed identically | **PASS**: no crashes or sanitizer reports, round-trip invariant held |
| libFuzzer (clang 18) + ASan + UBSan, 121 s | **PASS**: 15.2 M execs (~126 k/s), 176 edges, 249-input corpus, no crashes |
| Testbed, plain build (3 consecutive runs) | **41/41 PASS** each |
| Testbed with daemons under ASan+UBSan | **41/41 PASS**, no sanitizer output |
| Testbed with daemons under valgrind | **41/41 PASS**, 0 valgrind messages, exit 0 |
| `idle_check.sh` (`-t 5`, 20 s) | 4 wakeups, 0 ms CPU, waiting in `do_epoll_wait` |

### Problems found along the way, and what was done

1. **ASan caught three out-of-bounds reads, all in test code, none in the daemon.**
   * Two were in `test_lldpdu.c`: a 400-byte buffer used to build a 511-octet TLV, and a
     5-byte string literal passed with length 8.
   * One was in the fuzz harness's structured generator: a 7-byte literal read up to 8.

   Valgrind did not flag the two stack/global ones, since memcheck doesn't track array
   bounds. That is a good argument for running both tools. All three were fixed.
2. **No defect was found in the daemon/parser code** by unit tests, valgrind, ASan/UBSan,
   ~27 M fuzz executions, or the testbed.
3. **Testbed: the last frame was missing from the capture.** libpcap's TPACKET_V3 ring
   hands packets to tcpdump only when a block retires, so ns1's final shutdown LLDPDU
   was still buffered when tcpdump was stopped. tcpdump itself reported "30 received by
   filter, 29 captured". The fix is `--immediate-mode` plus a short drain delay.
4. **Testbed: `tshark -c 1 -Y …` returned nothing.** `-c` counts packets *read*, not
   matched. The fix is `| head -1`.
5. **Testbed: one run reported ageout at 8.7 s for a 7 s TTL.** The stopwatch was the
   problem, not the daemon. WSL2's realtime clock is stepped by Hyper-V time sync and
   timesyncd: the new `clock.log` recorded steps of 692 ms and 1558 ms relative to
   monotonic during later runs. The testbed now:
   * times itself with `/proc/uptime` (CLOCK_BOOTTIME);
   * uses millisecond log timestamps;
   * has the daemon report the monotonic time between a neighbour's last LLDPDU and its
     removal.

   That self-reported figure was exactly 7000 ms in all 10 measurements across 5 runs,
   so ageing is precise. The assertion was also tightened to [TTL, TTL+250 ms].
6. **A Wireshark 4.2.2 display quirk (not a defect).** For any LLDP frame longer than the
   60-octet minimum, Wireshark shows the final 3 octets (the last value byte plus End
   Of LLDPDU) as an Ethernet "Trailer". Every TLV, End included, still decodes with the
   right length, and no malformed or expert flag is raised. Frames generated
   independently in Python show the same thing, and the byte-for-byte unit test pins
   down the encoding.
