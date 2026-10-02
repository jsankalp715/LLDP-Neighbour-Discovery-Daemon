# lldpnd: an LLDP (IEEE 802.1AB) neighbour discovery daemon in C

`lldpnd` implements the Link Layer Discovery Protocol from the standard, over raw
`AF_PACKET` sockets. Ethernet II frames and TLVs are built and parsed by hand: no
libpcap, no lldpd, no LLDP library. Everything received is treated as untrusted.

* **Protocol.** It advertises Chassis ID, Port ID, TTL, Port Description, System
  Name, System Description, System Capabilities, Management Address and the 802.3
  Maximum Frame Size. It decodes the common 802.1/802.3 extensions neighbours send:
  Port VLAN ID, VLAN Name, MAC/PHY, Link Aggregation and Maximum Frame Size. It runs
  on several interfaces at once with one chassis ID, including VLAN sub-interfaces.
  Local changes (alias, addresses, MTU, link state, hostname) are sent immediately,
  limited by the transmit credit. It also implements fast start, a shutdown LLDPDU on
  exit, link up/down handling with `reinitDelay`, interface hot-plug, loop detection,
  adminStatus (rx/tx-only), and all three LLDP group addresses.
* **Implementation.** C11, Linux only, `-Wall -Wextra -Werror` with GCC and Clang.
  One thread and one `epoll` loop: sockets, `timerfd`s, `signalfd`, rtnetlink and a
  hostname watch. An idle daemon wakes only to transmit.
* **Operation.** `lldpnd-ctl` queries the daemon as text or JSON. `-U user` drops
  to an unprivileged user that keeps only `CAP_NET_RAW`. The project includes a
  hardened systemd unit (`systemd-analyze security` exposure 1.9) and man pages.
* **Verification.** Unit tests run plain, under valgrind and under ASan+UBSan. The
  receive path is fuzzed. A namespace testbed checks captures with Wireshark's
  dissector, and an interoperability test runs against **lldpd**. CI runs all of it.

## Quick start

```bash
make                                   # build/lldpnd, build/lldpnd-ctl, tests
sudo ./build/lldpnd -i eth0            # or -i eno1,eno2 for several ports
sudo ./build/lldpnd-ctl show           # neighbour tables (also: json, stats, local)
```

As a service:

```bash
sudo make install                      # /usr/local/{sbin,bin,share/man}, systemd unit
echo 'LLDPND_OPTS="-i eth0"' | sudo tee /etc/default/lldpnd
sudo systemctl enable --now lldpnd
sudo lldpnd-ctl -S /run/lldpnd/lldpnd.sock json | jq '.ports[].neighbors[].system_name'
```

### `lldpnd` options

| Option | Meaning | Default |
|---|---|---|
| `-i IF[,IF…]` | interfaces to run on (repeatable, up to 32) | required |
| `-c IF` | interface whose MAC is the chassis ID | first `-i` |
| `-m MODE` | adminStatus: `rxtx`, `tx` (transmit only), `rx` (receive only) | `rxtx` |
| `-a ADDR` | destination: `nearest-bridge`, `nearest-nontpmr`, `nearest-customer` | `nearest-bridge` |
| `-t SECS` | msgTxInterval, 1–3600 | 30 |
| `-H N` | msgTxHold, 1–100; TTL = min(65535, SECS×N+1) | 4 (TTL 121) |
| `-f N` | txFastInit: frames sent 1 s apart at start, on link up and for a new neighbour, 0–8 | 4 |
| `-C N` | txCreditMax: back-to-back frames allowed, 1–10 | 5 |
| `-p SECS` | print the tables periodically | print on change |
| `-n` / `-d` | System Name / Description | hostname (followed live) / uname |
| `-P DESC` | Port Description for every port | interface alias, else name |
| `-M` | don't send Management Address TLVs | send them |
| `-S PATH` | control socket, or `none` | `/run/lldpnd.sock` |
| `-U USER` | run as USER after start-up, keeping only CAP_NET_RAW | stay root |

The daemon logs one line per event to stdout:

```
22:48:28.261 [eth0] NEIGHBOUR ADD chassis=02:00:00:00:00:02 port=eth0(st5) name=ns2 ttl=7
22:48:31.386 [eth0] rx: discard from 02:00:00:00:00:99: truncated TLV / length exceeds frame
22:48:37.262 [eth0] NEIGHBOUR AGEOUT chassis=02:00:00:00:00:03 port=eth0(st5) name=ns3 ttl=7 (TTL expired, last rx 7000 ms ago)
22:48:37.328 [eth1] NEIGHBOUR DELETE chassis=02:00:00:00:00:02 port=eth0(st5) name=ns2 ttl=7 (shutdown LLDPDU)
```

SIGINT or SIGTERM sends a shutdown LLDPDU (TTL 0) on every port, prints the tables
and statistics, and exits 0. See `man/lldpnd.8` and `man/lldpnd-ctl.8`.

## Design

```
src/
  tlv.[ch]        TLV header (7-bit type, 9-bit length), builders, bounds-checked iterator   8.4-8.6
  frame.[ch]      Ethernet II build/parse, SIOCGIFHWADDR, 01:80:C2:00:00:0E, 0x88CC        7
  lldpdu.[ch]     LLDPDU builder; validating parser; escaping/formatting of untrusted data  8.2, 8.5
  neigh.[ch]      remote systems table keyed by (Chassis ID, Port ID); TTL expiry; flush   9.2.7, 9.2.9
  txsched.[ch]    txTTR / txFast / txCredit / txNow on an injected clock (pure logic)      9.2.5, 9.2.8, 9.2.10
  rawsock.[ch]    AF_PACKET socket bound to ifindex + 0x88CC, PACKET_ADD_MEMBERSHIP
  netmon.[ch]     rtnetlink link/address events, link dump
  localinfo.[ch]  hostname, uname, capabilities, management-address selection
  agent.[ch]      ports, local-change detection, rx/tx/ageing, the epoll loop               9
  ctl.[ch]        non-blocking control socket;  report.[ch]  text + JSON views
  privdrop.[ch]   setuid + capset(CAP_NET_RAW) + no_new_privs
  main.c          CLI                       lldpnd_ctl.c   the lldpnd-ctl client
```

### Event loop

All work arrives on file descriptors in one `epoll` set:

| fd | fires when | action |
|---|---|---|
| raw socket (per port) | an LLDP frame arrives | validate, update table, maybe fast-transmit |
| tx `timerfd` (per port) | one-shot at `txs_deadline()` | re-check local info, transmit if allowed |
| age `timerfd` (per port) | one-shot at the earliest neighbour expiry | remove expired neighbours |
| rtnetlink | link/address change | portEnabled, re-attach, rebuild LLDPDUs |
| `/proc/sys/kernel/hostname` | hostname changed (`POLLPRI`) | rebuild LLDPDUs |
| `signalfd` | SIGINT / SIGTERM | shutdown LLDPDUs, exit |
| control socket + clients | a query | render and send a reply |

The standard drives `txTTR` and `txCredit` from a one-second `txTick`. `txsched`
instead computes the credit lazily from elapsed time and arms one timer for the next
real deadline, so an idle daemon doesn't wake every second. After start-up settles,
`scripts/idle_check.sh` measured 4 wake-ups in 20 s with `-t 5` (one per frame),
0 ms of CPU, waiting in `do_epoll_wait`.

### Transmit

* **Information LLDPDU** (9.2.7 `mibConstrInfoLLDPDU()`):
  * Chassis ID: subtype 4, the chassis interface's MAC. It is the same on every port.
  * Port ID: subtype 5, the interface name.
  * TTL: `min(65535, msgTxInterval × msgTxHold + 1)` (9.2.5.22).
  * Port Description: the alias, else the name.
  * System Name and System Description.
  * System Capabilities: router and station supported; router enabled when IPv4 or
    IPv6 forwarding is on.
  * Management Address: the first IPv4 address and the first IPv6 address (global
    preferred), numbered by ifIndex, or the MAC if the port has no IP.
  * IEEE 802.3 Maximum Frame Size (8.6, 802.3 Clause 79): MTU + 18, following the
    MTU live, so the peer can spot an MTU mismatch.
  * End.
* **Destination** (7.1): `nearest-bridge` `01:80:C2:00:00:0E` (default; no bridge
  forwards it), `nearest-nontpmr` `…03` (passes two-port MAC relays), or
  `nearest-customer` `…00` (also passes provider bridges), chosen with `-a`. Frames
  sent to another group address belong to another agent and are ignored. For
  several agents on one port, run one `lldpnd` per address.
* **adminStatus** (9.2.5.1, `-m`): `rxtx`, `tx` (received LLDPDUs are drained and
  ignored), or `rx` (never transmits, not even a shutdown LLDPDU).
* **Timing** (9.2.8, 9.2.10):
  * The first frame goes out at once, followed by a fast start of `txFastInit`
    frames 1 s apart, then one frame per `msgTxInterval`.
  * A new neighbour reloads `txFast`, but only if it is 0.
  * Every frame spends one credit. The credit refills by one per second, up to
    `txCreditMax`.
* **Local changes** (`somethingChangedLocal`). The port's LLDPDU is rebuilt on every
  netlink event, hostname change and timer tick, and compared byte for byte with
  the last one. If they differ, a frame goes out as soon as credit allows. In the
  testbed, alias, hostname and address changes reached neighbours in 20–30 ms.
* **Shutdown** (9.2.7 `mibConstrShutdownLLDPDU()`): only the mandatory TLVs, with
  TTL 0.

### Receive validation (8.2, 8.5, 9.2.7 rxProcessFrame)

An LLDPDU is discarded, and counted in `statsFramesDiscardedTotal` /
`statsFramesInErrorsTotal`, if any of these hold:

| Rule | Logged as |
|---|---|
| a TLV header or length runs past the frame | `truncated TLV / length exceeds frame` |
| TLV 1, 2 and 3 are not Chassis ID, Port ID and TTL, in that order | `first/second/third TLV is not …` |
| there is no End Of LLDPDU, or it has a nonzero length | `missing End Of LLDPDU TLV` / `… with nonzero length` |
| Chassis/Port ID length is not 2..256; the subtype is reserved (0, 8..255); a MAC subtype isn't 6 octets; a network-address subtype is under 2 octets | `invalid Chassis ID / Port ID TLV` |
| TTL length ≠ 2 | `invalid TTL TLV length` |
| Chassis ID, Port ID or TTL appears again | `mandatory TLV repeated` |
| Port Desc / Sys Name / Sys Desc / Sys Cap appears twice | `single-instance optional TLV repeated` |
| a string is over 255 octets; Sys Cap ≠ 4; org-specific is under 4; a Management Address's internal lengths don't add up (8.5.9) | `optional TLV has invalid length` |

* **Accepted and skipped.** Reserved TLV types (9..126) are counted as
  `statsTLVsUnrecognizedTotal` and skipped. Octets after End Of LLDPDU are padding.
* **Organizationally specific TLVs** (8.6). These IEEE extensions are decoded,
  stored, shown in `show` and `json`, and included in change detection:
  * 802.1: Port VLAN ID; VLAN Name (the first is kept, the rest counted).
  * 802.3: MAC/PHY Configuration/Status, Link Aggregation, Maximum Frame Size.

  Each has a fixed or self-describing length. An unknown, malformed or repeated
  extension is counted as unrecognized and ignored. Because these are optional
  extensions defined outside 802.1AB, a bad one never discards the LLDPDU.
* **Bounds and storage.** Only `lldp_tlv_next()` walks received TLVs, and it refuses
  any length past the buffer. Values are copied into fixed-size fields, so nothing
  is allocated per frame.
* **Ports.** Frames are ignored until the port is operational (portEnabled).
  Frames carrying this system's own chassis ID are logged once as a loop and are
  not recorded.
* **Output escaping.** Every string from the wire is escaped before display:
  `\xNN` in text, `\u00NN` in JSON. JSON output is pure ASCII and always parses.
  A strict validator checks this in the unit tests and, in the fuzzer, for every
  accepted frame.

### Neighbour table (9.2.7, 9.2.9)

* **Storage.** Each port has a fixed table of 32 entries, keyed by Chassis ID and
  Port ID (subtype, length and bytes). When the table is full, new neighbours are
  dropped (`tooManyNeighbors`) and existing ones keep refreshing.
* **Updates.** A received frame produces an `ADD`, an `UPDATE` (content changed),
  or a `REFRESH` (identical), and the entry's expiry restarts at `now + TTL`.
* **Removal.** TTL 0 deletes the entry at once. Expiry gives an `AGEOUT`, which
  reports the monotonic time since the last frame. Link down flushes the table.

### Ports and links

* **portEnabled** follows `IFF_UP && IFF_RUNNING` from rtnetlink.
* **Down:** the port's neighbours are flushed and transmission stops.
* **Up:** credit and fast start are re-initialised (9.2.7.12 `txInitializeLLDP()`),
  no earlier than `reinitDelay` (2 s, 9.2.5.10) after the port went down.
* **Hot-plug:** an interface that is deleted and recreated with the same name is
  re-attached with a new socket. This also works after a privilege drop, because
  `CAP_NET_RAW` is kept.

### Privilege model

* **`-U user`:** after opening its sockets the daemon calls `setgroups(0)`, `setgid`
  and `setuid`. `capset` then leaves only `CAP_NET_RAW` permitted and effective, and
  `PR_SET_NO_NEW_PRIVS` is set. Before continuing, the daemon checks that it can no
  longer regain root.
* **The systemd unit** reaches the same state declaratively: `DynamicUser=yes` and
  `AmbientCapabilities=CAP_NET_RAW`, plus a read-only system, a syscall filter and
  address-family restrictions.
* **Control socket:** it is created mode 0600 and refuses to replace a live
  daemon's socket or any non-socket file. Clients are non-blocking and limited to 8
  slots; the oldest is evicted.

## Standard references

Comments cite IEEE Std 802.1AB-2016:
* **Clauses 7 and 8** (addressing, TLV formats) are cited by number.
* **Clause 9 numbers** were checked against IEEE 802.1 maintenance requests that
  quote the standard ([0121](https://www.ieee802.org/1/files/public/maint/requests/maint_0121.pdf),
  [0127](https://grouper.ieee.org/groups/802/1/files/public/maint/requests/maint_0127.pdf)):
  msgFastTx 9.2.5.5, msgTxHold 9.2.5.6, msgTxInterval 9.2.5.7, reinitDelay 9.2.5.10,
  txCreditMax 9.2.5.17, txFastInit 9.2.5.19, txTTL 9.2.5.22, txInitializeLLDP
  9.2.7.12, transmit state machine 9.2.8, transmit timer state machine 9.2.10.
* **Editions.** Those requests quote the 2009 edition. Zephyr cites msgTxHold as
  9.2.5.6 against 2016, so the numbering carried over.
* **Without a sub-number.** Procedures and variables that couldn't be confirmed to
  a sub-clause are cited by name only: `rxProcessFrame()`, `rxInitializeLLDP()`,
  `mibDeleteObjects()`, `tooManyNeighbors`, and the statistics counters.

## Decisions and deviations

* **One agent per process.** One agent per process means one destination address.
  The standard's several agents per port (one per address) are run as one
  `lldpnd` per address, each with its own control socket. The modes test verifies
  this.
* **Strictness.** Validation is stricter than the minimum: reserved ID subtypes,
  duplicate single-instance TLVs and inconsistent Management Address lengths are
  rejected.
* **Fast start.** Fast start runs at start-up and on link up as well as for new
  neighbours. `-f 0` disables fast transmission.
* **Ports and interfaces.** Ports are identified by interface name, and interfaces
  must exist at start-up (a missing name is more likely a typo than hot-plug).
* **Chassis ID.** The chassis ID follows the chassis interface's MAC if that
  changes.
* **Capabilities.** Router and station are reported as supported, with router
  enabled only while forwarding is on. This matches what lldpd reports for a Linux
  host. Bridge membership is not detected.
* **Management Address.** At most one IPv4 and one IPv6 address are sent, with no
  OID. On receive the first 4 are stored, and all of them are validated.
* **VLANs.** LLDPDUs are untagged, as 802.1AB specifies. On a VLAN, run `lldpnd`
  on the VLAN sub-interface (`-i eth0.100`): its frames are tagged on the wire, and
  the modes test verifies this.
* **Out of scope, deliberately:**
  * **The LLDP MIB over SNMP, and notifications.** This needs an SNMP agent
    (AgentX). `lldpnd-ctl json` exposes the same information.
  * **LLDP-MED** (ANSI/TIA-1057). It is a separate standard for VoIP endpoints.
  * **Transmitting 802.3 MAC/PHY status.** Mapping a Linux link to an IANA MAU type
    is ambiguous for virtual, bonded and multi-rate links, and a wrong value is
    worse than none. MAC/PHY is decoded when received.
  * **Transmitting 802.1 VLAN TLVs.** A host's port VLAN is not well defined; a
    bridge's belongs to bridge software.
  * **Per-port timers.** One process uses one set; run separate processes if needed.

## Testing

| Layer | What | Where |
|---|---|---|
| Unit | TLV header (exhaustive round trip), builders vs hand-computed bytes, **byte-for-byte frame**, every parser rule and boundary, 802.1/802.3 extension decoding incl. malformed and duplicate ones, neighbour keying/ageing/flush, tx scheduling on a simulated clock, netlink parsing incl. malformed buffers, mgmt-address selection, JSON validity and escaping | `tests/test_*.c` |
| Memory | all unit tests under valgrind (leaks are errors) and ASan+UBSan (`-fno-sanitize-recover`) | `make valgrind`, `make asan` |
| Fuzz | random, mutated and structure-aware frames → Ethernet parse → LLDPDU validation → table → text/JSON, plus the netlink parser; invariants: re-encode round trip, valid JSON | `make fuzz`, `make libfuzzer` |
| Raw socket | veth pair in a private netns: byte-exact delivery, multicast membership for each group address, EtherType filter, truncation, outgoing detection | `make rawsock-test` |
| Testbed | 3 namespaces on a Linux bridge, 10 phases, tshark-decoded capture | `make testbed` |
| Interop | lldpnd ↔ **lldpd 1.0.18**, both directions | `make interop` |
| Modes | adminStatus tx/rx-only, all three group addresses with two agents on one port, VLAN sub-interfaces, MFS following a live MTU change, extension decoding | `make modes-test` |
| Service | the shipped systemd unit under real systemd | `scripts/service_check.sh` |
| CI | all of the above on every push | `.github/workflows/ci.yml` |

### Testbed (`scripts/testbed.sh`)

```
            lldp-ns1                 lldp-ns2            lldp-ns3
     eth0 02:..:01  eth1 02:..:11   eth0 02:..:02       eth0 02:..:03
          |             |               |                   |
        brp1          brp1b           brp2                brp3
                   br0 (Linux bridge, in netns lldp-br)
```

* **ns1** runs one daemon on two ports.
* **ns2** runs as `nobody` in its own UTS namespace, so it advertises its hostname
  live.
* **ns3** is a plain instance.

`01:80:C2:00:00:0E` is a reserved link-local address that a standards-compliant
bridge consumes. Phase 0 checks that nothing is learned through the default bridge;
after that the bridge is configured with `group_fwd_mask 0x4000`.

| Phase | Checked |
|---|---|
| 0 | the default bridge forwards nothing |
| 1 | all 10 adjacencies are learned (ns1 is seen on both ports with one chassis ID); ns1 reports a loop on both ports |
| 2 | `lldpnd-ctl json` from each daemon parses and shows names, alias-derived port descriptions, capabilities and management addresses; `show`, `stats`, `local` and unknown commands behave correctly |
| 3 | 10 malformed frames are each rejected with the right reason; a valid frame with a reserved and an org-specific TLV is accepted, then deleted by its TTL 0 |
| 4 | an alias change, a hostname change (via `nsenter`) and a new IPv6 address each reach ns1 in 20–30 ms (a periodic frame would take up to 2000 ms); turning on IP forwarding switches the advertised capability to router at the next periodic check |
| 5 | ns2 runs as uid 65534 with `CapEff` = `0x2000` (CAP_NET_RAW) |
| 6 | link flap: flush on down, re-learn about 1 s after up |
| 7 | ns2's interface is deleted and recreated; the unprivileged daemon re-attaches and re-learns |
| 8 | ns3 is killed and its namespace deleted; three ports age it out, each reporting **exactly 7000 ms** since its last frame (TTL 7 s) |
| 9 | ns2 is stopped with SIGINT; ns1 deletes it on both ports within 10 ms |
| 10 | tshark decodes every daemon frame with 0 malformed/expert flags; shutdown frames come from exactly ns1/eth0, ns1/eth1 and ns2; chassis, port, TTL, names, port description, capabilities `0x0090/0x0080` and IPv4/IPv6 management addresses all decode to the expected values |

The testbed times itself with `/proc/uptime`, not the wall clock, which WSL2 steps
by up to 1.5 s through Hyper-V time sync. `clock.log` records the drift for each
run. Artifacts (`lldp.pcap`, `dissection.txt`, logs, JSON) go to `build/testbed/`.

### Interoperability with lldpd (`scripts/interop_lldpd.sh`)

* **lldpd decodes lldpnd:** chassis MAC, system name and description, port ifname,
  alias-based port description, TTL, IPv4 and IPv6 management addresses, Router off
  and Station on, and the 802.3 Maximum Frame Size (1518).
* **lldpnd decodes lldpd:** chassis MAC, port ID as a MAC, name, capabilities,
  IPv4 and IPv6 management addresses, and lldpd's 802.3 MAC/PHY and Link
  Aggregation TLVs. None of lldpd's frames are rejected.

### Modes (`scripts/modes_test.sh`)

The modes test runs on a veth pair between two namespaces, with a capture checked
by tshark:
* **adminStatus.**
  * A transmit-only agent is learned by a receive-only one, but ignores a valid
    injected LLDPDU itself.
  * The receive-only agent sends nothing, not even a shutdown LLDPDU.
  * The transmit-only agent's shutdown LLDPDU removes it from its neighbour.
* **Group addresses.** Two agents share one port (`nearest-bridge` and
  `nearest-customer`):
  * Each pairs only with the peer agent on the same address and logs the other
    address's frames as "wrong destination".
  * The capture shows both destinations.
* **VLAN.** Agents on `eth0.100` learn each other, and their frames carry VLAN tag
  100 on the wire.
* **Maximum Frame Size.** Setting MTU 9000 reaches the neighbour as MFS 9018
  within about 30 ms.
* **Extensions.** An injected frame's Port VLAN ID, VLAN Name, MAC/PHY, Link
  Aggregation and MFS are decoded and appear in the JSON.
* **Live changes:** an alias change reaches lldpd at once.
* **Shutdowns:** each side's shutdown LLDPDU removes it from the other's table
  within 50 ms.

### Results

Final run on 2026-10-03, from `make clean`, in WSL2 (CI runs the same suites on GitHub's Ubuntu 24.04 runners):

| Test | Result |
|---|---|
| Build, gcc 13.3 and clang 18, `-Werror` | clean |
| Unit tests: 7 suites, gcc and clang | **652/652** |
| Unit tests under valgrind (`--errors-for-leak-kinds=all`) | **652/652**, 0 errors, 0 leaks |
| Unit tests under ASan+UBSan | **652/652** |
| Fuzz driver under ASan+UBSan, 3M (default seed) + 10M (seed `0xdeadbeef`) | no crashes or sanitizer reports; round-trip (including extensions) and JSON-validity invariants held for every accepted frame |
| libFuzzer + ASan+UBSan, 120 s | 12.7M executions (~105k/s), 403 edges, 505-input corpus, no crashes |
| Raw-socket test, plain and ASan | **36/36** each |
| Testbed, plain | **77/77** |
| Testbed, daemons under ASan+UBSan | **77/77**, no sanitizer output |
| Testbed, daemons under valgrind | **77/77**, no valgrind output |
| Interop with lldpd 1.0.18 | **32/32** |
| Modes: adminStatus, group addresses, VLAN, MFS, extensions | **26/26** |
| systemd unit under real systemd | **14/14**; `systemd-analyze security` exposure 1.9 (OK) |
| Idle steady state, `-t 5`, 20 s | 4 wake-ups (one per frame), 0 ms CPU, in `do_epoll_wait` |
| CLI and control-socket edge cases (bad ranges, unknown interface or user, `-U root`, live or stale or regular file at the socket path) | 19/19 correct exit codes; never replaces a live socket or a regular file |

### Bugs found by the tests, and fixes

1. **Netlink over-read.** The fuzzer found an over-read in the netlink parser.
   `NLMSG_NEXT` subtracts the *aligned* message length, so with an `unsigned`
   remaining count a final unaligned message wrapped the counter, and `NLMSG_OK`
   then walked past the buffer. The macros were replaced by an explicitly
   bounds-checked iterator, which also fixes a Clang `-Wsign-compare` error from the
   macros. A regression test feeds the exact input in an exactly-sized heap buffer.
2. **Bugs in test code.** ASan found three out-of-bounds reads in test and harness
   code (literals shorter than the length passed). GCC's `-Warray-bounds` found an
   out-of-bounds index in a new test. Valgrind missed the stack and global cases.
3. **Behaviour fixes from the testbed and smoke tests:**
   * Frames were processed in the up-to-1 s window before the kernel reported the
     link running. They are now dropped until portEnabled.
   * `ENETDOWN` from a packet socket was logged as an error.
   * A spurious "local change" was logged when IPv6 link-local addresses appeared
     right after link up.
4. **Test-harness bugs:**
   * libpcap's ring buffer held the last frame when tcpdump was stopped (fixed with
     `--immediate-mode`).
   * `tshark -c` counts packets read, not packets matched.
   * The wall-clock stopwatch was replaced with a monotonic one.
   * `/proc` status fields are separated by tabs.
   * lldpd's privilege-separated child needs its socket directory to be traversable.
   * valgrind's gdbserver FIFOs can't be removed after the daemon drops privileges
     (fixed with `--vgdb=no`).
   * Found by the first CI run: a new network namespace inherits IPv4 forwarding
     from the host, and GitHub runners have it on (Docker). The daemons correctly
     advertised router, but the tests assumed station. The tests now pin forwarding
     off per namespace, and a new check confirms that turning it on switches the
     advertised capability to router.
   * Also found by CI: LeakSanitizer's exit-time leak check failed ("does not work
     under ptrace") for the ASan daemon that drops privileges. The check must ptrace
     the process, which is non-dumpable after `setuid`, and the runner refused the
     attach. Making the daemon dumpable again would let any process running as the
     target user ptrace a process holding `CAP_NET_RAW`, so the daemon is unchanged.
     That one ASan daemon runs with `detect_leaks=0`, and CI now also runs the
     valgrind testbed, which checks leaks in-process on every daemon, including
     that one.
   * In the modes test, an injected frame was sent from the receiving agent's own
     namespace, so it left the interface rather than arriving at it.
5. **Wireshark 4.2.2 display quirk, not a defect.** On LLDP frames longer than 60
   octets, Wireshark shows the last 3 octets as an Ethernet "trailer". Frames built
   independently in Python show the same thing, and every TLV still decodes with no
   malformed or expert flag.

## Development environment

This was developed on Windows 11 in WSL2 (Ubuntu 24.04, kernel 6.18, gcc 13.3,
clang 18, valgrind 3.22, tshark 4.2.2, lldpd 1.0.18), with root via `wsl -u root`.
Nothing in the code depends on WSL. From Windows:

```bash
wsl -d Ubuntu-24.04 -u root --cd /mnt/d/lldp -- make check
```

## License

MIT; see [LICENSE](LICENSE).
