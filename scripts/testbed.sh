#!/usr/bin/env bash
#
# testbed.sh - multi-namespace Linux bridge testbed for lldpnd
#
#        lldp-ns1            lldp-ns2            lldp-ns3
#     eth0 02:..:01       eth0 02:..:02       eth0 02:..:03
#          |                   |                   |
#        brp1 ------------- brp2 -------------- brp3
#                 br0 (Linux bridge, in netns lldp-br)
#
# Phases
#   0  bridge with default group_fwd_mask: 01:80:C2:00:00:0E is a reserved
#      link-local group address (802.1Q 8.6.3, 802.1AB 7.1) that a bridge
#      must NOT forward, so no neighbours may appear.
#   1  group_fwd_mask 0x4000 (forward ...0E): every daemon learns the other two.
#   2  inject malformed frames: the daemon rejects each for the right reason.
#   3  SIGKILL the ns3 daemon and delete lldp-ns3: ns1/ns2 age it out after TTL.
#   4  SIGINT ns2: it sends a shutdown LLDPDU, ns1 deletes it immediately.
#   5  SIGINT ns1, then decode the capture with tshark (Wireshark's dissector).
#
# Usage (root):  scripts/testbed.sh
#   BIN=build/asan/lldpnd scripts/testbed.sh     # run daemons under ASan
#   VALGRIND=1 scripts/testbed.sh                # run daemons under valgrind
#
set -u

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
BIN=${BIN:-$root/build/lldpnd}
OUT=${OUT:-$root/build/testbed}
TX=2                       # msgTxInterval (s)
HOLD=3                     # msgTxHold
TTL=$((TX * HOLD + 1))     # 7 s
BRNS=lldp-br
INJ_MAC=02:00:00:00:00:99

pass=0; fail=0
declare -A PID

ok()   { echo "  PASS: $*"; pass=$((pass + 1)); }
bad()  { echo "  FAIL: $*"; fail=$((fail + 1)); }
mac()  { printf '02:00:00:00:00:%02x' "$1"; }
log()  { echo "$WORK/ns$1.log"; }

# Stopwatch in ms from /proc/uptime (CLOCK_BOOTTIME). Not `date`: the wall
# clock can be stepped by NTP / Hyper-V time sync mid-test (seen on WSL2).
mono_ms() { local up; read -r up _ </proc/uptime; echo $(( 10#${up/./} * 10 )); }

# wait_for <timeout-s> <file> <fixed-string>
wait_for() {
	local deadline=$(( $(mono_ms) + $1 * 1000 ))
	while (( $(mono_ms) < deadline )); do
		grep -qF -- "$3" "$2" 2>/dev/null && return 0
		sleep 0.05
	done
	return 1
}

cleanup() {
	for k in "${!PID[@]}"; do kill -KILL "${PID[$k]}" 2>/dev/null; done
	wait 2>/dev/null
	for ns in lldp-ns1 lldp-ns2 lldp-ns3 $BRNS; do
		ip netns del "$ns" 2>/dev/null
	done
	if [[ -n ${WORK:-} && -d $WORK ]]; then
		cp -a "$WORK"/. "$OUT"/ && rm -rf "$WORK"
	fi
}

if [[ $EUID -ne 0 ]]; then echo "testbed.sh: must run as root" >&2; exit 2; fi
[[ -x $BIN ]] || { echo "testbed.sh: $BIN not built (make)" >&2; exit 2; }
for t in ip tcpdump tshark python3; do
	command -v $t >/dev/null || { echo "testbed.sh: needs $t" >&2; exit 2; }
done

trap cleanup EXIT
cleanup
rm -rf "$OUT"; mkdir -p "$OUT"
# work on the Linux filesystem (fast, coherent); artifacts are copied to $OUT on exit
WORK=$(mktemp -d /tmp/lldp-testbed.XXXXXX)

RUN=("$BIN")
if [[ ${VALGRIND:-0} == 1 ]]; then
	RUN=(valgrind -q --leak-check=full --show-leak-kinds=all
	     --errors-for-leak-kinds=all --error-exitcode=99 "$BIN")
fi
echo "== lldpnd testbed: ${RUN[*]}  (tx=${TX}s hold=$HOLD ttl=${TTL}s)"

# ---------------------------------------------------------------- topology
ip netns add $BRNS
ip -n $BRNS link set lo up
ip -n $BRNS link add br0 type bridge stp_state 0
ip -n $BRNS link set br0 up
for i in 1 2 3; do
	ns=lldp-ns$i
	ip netns add $ns
	ip -n $ns link set lo up
	# create the veth inside the namespace; the peer goes straight to lldp-br
	ip -n $ns link add eth0 address "$(mac $i)" type veth \
		peer name brp$i netns $BRNS
	ip -n $BRNS link set brp$i master br0
	ip -n $BRNS link set brp$i up
	ip -n $ns link set eth0 up
done
echo "   bridge group_fwd_mask = $(ip netns exec $BRNS cat /sys/class/net/br0/bridge/group_fwd_mask)"

# capture on bridge port brp1: sees ns1's frames and everything forwarded to it
ip netns exec $BRNS tcpdump -Z root --immediate-mode -i brp1 -U -nn -w "$WORK/lldp.pcap" ether proto 0x88cc \
	2>"$WORK/tcpdump.err" &
PID[tcpdump]=$!
sleep 1

for i in 1 2 3; do
	ip netns exec lldp-ns$i "${RUN[@]}" -i eth0 -t $TX -H $HOLD -p $TX \
		-n "ns$i" -P "ns$i uplink to br0" >"$(log $i)" 2>&1 &
	PID[ns$i]=$!
done

# record (wall clock - monotonic) so any wall-clock step during the run is visible
while :; do echo $(( $(date +%s%3N) - $(mono_ms) )); sleep 0.5; done >"$WORK/clock.log" &
PID[clock]=$!

# ---------------------------------------------------------------- phase 0
echo "-- phase 0: default bridge drops the nearest-bridge group address"
sleep $((TX * 2 + 1))
n=$(cat "$(log 1)" "$(log 2)" "$(log 3)" | grep -c "NEIGHBOUR ADD")
if [[ $n -eq 0 ]]; then ok "no neighbours learned through a standard bridge"
else bad "$n neighbours learned with group_fwd_mask=0"; fi

# ---------------------------------------------------------------- phase 1
echo "-- phase 1: group_fwd_mask 0x4000 -> discovery"
ip -n $BRNS link set br0 type bridge group_fwd_mask 0x4000
t0=$(mono_ms)
for i in 1 2 3; do
	for j in 1 2 3; do
		[[ $i == "$j" ]] && continue
		if wait_for $((TX + 3)) "$(log $i)" "NEIGHBOUR ADD chassis=$(mac $j) port=eth0(st5) name=ns$j"
		then ok "ns$i learned ns$j"
		else bad "ns$i did not learn ns$j"; fi
	done
done
echo "   all neighbours learned in $(( $(mono_ms) - t0 )) ms"
sleep $((TX + 1))   # let a periodic table print happen
for i in 1 2 3; do
	last=$(grep "neighbour table:" "$(log $i)" | tail -1)
	[[ $last == *"2 entries"* ]] && ok "ns$i table holds 2 entries" \
		|| bad "ns$i table: $last"
	grep -qF "port desc    ns$((i % 3 + 1)) uplink to br0" "$(log $i)" \
		&& ok "ns$i shows Port Description of its neighbour" \
		|| bad "ns$i missing neighbour Port Description"
done

# ---------------------------------------------------------------- phase 2
echo "-- phase 2: malformed frames injected from ns2 are rejected by ns1"
mapfile -t expects < <(ip netns exec lldp-ns2 python3 "$here/inject_lldp.py" eth0 $INJ_MAC)
for e in "${expects[@]}"; do
	if [[ $e == NEIGHBOUR* ]]; then pat="$e"; else pat="discard from $INJ_MAC: $e"; fi
	if wait_for 2 "$(log 1)" "$pat"; then ok "ns1: $pat"
	else bad "ns1 log lacks: $pat"; fi
done
kill -0 "${PID[ns1]}" 2>/dev/null && ok "ns1 daemon survived the malformed frames" \
	|| bad "ns1 daemon died"

# ---------------------------------------------------------------- phase 3
echo "-- phase 3: ns3 goes down hard (SIGKILL + netns deleted) -> TTL ageout"
t0=$(mono_ms)
kill -KILL "${PID[ns3]}"; wait "${PID[ns3]}" 2>/dev/null; unset 'PID[ns3]'
ip netns del lldp-ns3
for i in 1 2; do
	if wait_for $((TTL + 3)) "$(log $i)" "NEIGHBOUR AGEOUT chassis=$(mac 3)"; then
		ms=$(( $(mono_ms) - t0 ))
		# last frame from ns3 was 0..TX s before the kill, so expiry is TTL-TX..TTL s later
		if (( ms >= (TTL - TX) * 1000 - 300 && ms <= TTL * 1000 + 300 )); then
			ok "ns$i aged out ns3 ${ms} ms after the kill (expected $((TTL - TX))-${TTL}s)"
		else
			bad "ns$i aged out ns3 ${ms} ms after the kill, outside $((TTL - TX))-${TTL}s"
		fi
		# the daemon's own monotonic measurement: time from last rx to removal
		age=$(grep -F "NEIGHBOUR AGEOUT chassis=$(mac 3)" "$(log $i)" |
		      sed -n 's/.*last rx \([0-9]*\) ms ago.*/\1/p' | head -1)
		if [[ -n $age ]] && (( age >= TTL * 1000 && age <= TTL * 1000 + 250 )); then
			ok "ns$i removed ns3 ${age} ms after its last LLDPDU (TTL ${TTL}000 ms)"
		else
			bad "ns$i removed ns3 '${age}' ms after its last LLDPDU, want ${TTL}000-$((TTL * 1000 + 250))"
		fi
	else
		bad "ns$i never aged out ns3"
	fi
done
for i in 1 2; do
	j=$((3 - i))
	grep -qF "NEIGHBOUR AGEOUT chassis=$(mac $j)" "$(log $i)" \
		&& bad "ns$i wrongly aged out live ns$j" || ok "ns$i kept live neighbour ns$j"
done

# ---------------------------------------------------------------- phase 4
echo "-- phase 4: ns2 shuts down gracefully -> shutdown LLDPDU (TTL 0)"
kill -INT "${PID[ns2]}"
t0=$(mono_ms)
if wait_for 2 "$(log 1)" "NEIGHBOUR DELETE chassis=$(mac 2) port=eth0(st5) name=ns2"; then
	ok "ns1 deleted ns2 after $(( $(mono_ms) - t0 )) ms (no ageout wait)"
else
	bad "ns1 did not process ns2's shutdown LLDPDU"
fi
wait "${PID[ns2]}"; rc=$?; unset 'PID[ns2]'
[[ $rc -eq 0 ]] && ok "ns2 exited 0 on SIGINT" || bad "ns2 exit status $rc"

# ---------------------------------------------------------------- phase 5
echo "-- phase 5: stop ns1, decode capture with tshark"
sleep 1
kill -INT "${PID[ns1]}"
wait "${PID[ns1]}"; rc=$?; unset 'PID[ns1]'
[[ $rc -eq 0 ]] && ok "ns1 exited 0 on SIGINT" || bad "ns1 exit status $rc"
grep -q "stats:" "$(log 1)" && echo "   $(grep stats: "$(log 1)" | sed 's/^.*stats/ns1 stats/')"
sleep 1    # let tcpdump read the final shutdown frame
kill -INT "${PID[tcpdump]}"; wait "${PID[tcpdump]}" 2>/dev/null; unset 'PID[tcpdump]'

ours='lldp && eth.src != '$INJ_MAC
total=$(tshark -r "$WORK/lldp.pcap" -Y "$ours" 2>/dev/null | wc -l)
malformed=$(tshark -r "$WORK/lldp.pcap" -Y "($ours) && (_ws.malformed || _ws.expert.severity >= warning)" 2>/dev/null | wc -l)
inj_bad=$(tshark -r "$WORK/lldp.pcap" -Y "eth.src == $INJ_MAC && _ws.malformed" 2>/dev/null | wc -l)
shutdowns=$(tshark -r "$WORK/lldp.pcap" -Y "($ours) && lldp.time_to_live == 0" -T fields -e eth.src 2>/dev/null | sort | tr '\n' ' ')
echo "   capture: $(tshark -r "$WORK/lldp.pcap" 2>/dev/null | wc -l) frames, $total from the daemons"
(( total > 0 )) && ok "tshark decodes $total daemon frames as LLDP" || bad "no LLDP frames decoded"
(( malformed == 0 )) && ok "0 daemon frames flagged malformed/warning by Wireshark's dissector" \
	|| bad "$malformed daemon frames flagged malformed by Wireshark"
echo "   (Wireshark also flags $inj_bad of the deliberately malformed injected frames)"
[[ $shutdowns == "$(mac 1) $(mac 2) " ]] && ok "shutdown LLDPDUs (TTL 0) seen from ns1 and ns2 only" \
	|| bad "unexpected TTL-0 senders: '$shutdowns'"
for i in 1 2 3; do
	# (tshark's -c counts packets read, not matched, so take the first match with head)
	f=$(tshark -r "$WORK/lldp.pcap" -Y "eth.src == $(mac $i) && lldp.time_to_live != 0" \
	    -T fields -E separator='|' -e lldp.chassis.id.mac -e lldp.port.id \
	    -e lldp.time_to_live -e lldp.tlv.system.name -e lldp.port.desc 2>/dev/null | head -1)
	want="$(mac $i)|eth0|$TTL|ns$i|ns$i uplink to br0"
	[[ $f == "$want" ]] && ok "ns$i frame fields: $f" || bad "ns$i fields '$f' != '$want'"
done

# full dissection of ns1's first frame, plus one shutdown LLDPDU
tshark -r "$WORK/lldp.pcap" -Y "eth.src == $(mac 1)" -V -x 2>/dev/null \
	| awk '/^Frame / && n++ {exit} {print}' >"$WORK/dissection.txt"
tshark -r "$WORK/lldp.pcap" -Y "($ours) && lldp.time_to_live == 0" -V -x 2>/dev/null \
	| awk '/^Frame / && n++ {exit} {print}' >>"$WORK/dissection.txt"
tshark -r "$WORK/lldp.pcap" -Y "lldp" -T fields -e frame.number -e frame.time_relative \
	-e eth.src -e lldp.time_to_live -e lldp.tlv.system.name -e _ws.malformed 2>/dev/null \
	>"$WORK/summary.tsv"

kill "${PID[clock]}" 2>/dev/null; wait "${PID[clock]}" 2>/dev/null; unset 'PID[clock]'
step=$(sort -n "$WORK/clock.log" | sed -n '1p;$p' | paste -sd' ' | awk '{print $2 - $1}')
echo "   wall clock vs monotonic drift during run: ${step} ms (informational)"

echo
echo "== artifacts (copied to $OUT on exit): lldp.pcap, dissection.txt, summary.tsv, ns{1,2,3}.log"
echo "== result: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
