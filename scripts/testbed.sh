#!/usr/bin/env bash
#
# testbed.sh - multi-namespace Linux bridge testbed for lldpnd
#
#            lldp-ns1                 lldp-ns2            lldp-ns3
#     eth0 02:..:01  eth1 02:..:11   eth0 02:..:02       eth0 02:..:03
#     192.0.2.1          |          192.0.2.2           192.0.2.3
#          |             |               |                   |
#        brp1          brp1b           brp2                brp3
#                   br0 (Linux bridge, in netns lldp-br)
#
# lldp-ns1 runs ONE daemon on two ports (same chassis ID on both); lldp-ns2
# runs as user nobody (keeping only CAP_NET_RAW) in its own UTS namespace so
# its System Name follows the hostname; lldp-ns3 is a plain instance.
#
# Phases
#   0  default bridge: 01:80:C2:00:00:0E is a reserved link-local group
#      address that a bridge must not forward -> no neighbours.
#   1  group_fwd_mask 0x4000: discovery; ns1 sees its own LLDPDUs on the
#      other port and reports a loop.
#   2  control socket: JSON from every daemon parses and has the expected
#      neighbours, capabilities, management addresses, port descriptions.
#   3  malformed frames injected: rejected for the right reason.
#   4  local changes (alias, hostname, IPv6 address) reach the neighbours
#      at once, not at the next periodic transmission.
#   5  privilege drop: ns2 runs as uid 65534 with CapEff = CAP_NET_RAW.
#   6  link flap on ns1/eth1: flush on down, fast re-learn on up.
#   7  ns2's interface deleted and re-created: the unprivileged daemon
#      re-attaches (needs the retained CAP_NET_RAW).
#   8  ns3 goes down hard (SIGKILL + netns deleted): TTL ageout.
#   9  ns2 shuts down gracefully: shutdown LLDPDU, immediate delete.
#  10  ns1 stops; the capture is decoded with tshark (Wireshark's dissector).
#
# Usage (root):  scripts/testbed.sh
#   BIN=build/asan/lldpnd scripts/testbed.sh     # daemons under ASan
#   VALGRIND=1 scripts/testbed.sh                # daemons under valgrind
#
set -u

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
BIN=${BIN:-$root/build/lldpnd}
CTL=${CTL:-$root/build/lldpnd-ctl}
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
sock() { echo "$WORK/ns$1.sock"; }

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

# check <description> <command...>: PASS if the command succeeds
check() { local d=$1; shift; if "$@"; then ok "$d"; else bad "$d"; fi; }

# Flatten a daemon's JSON (via lldpnd-ctl) into greppable lines; prints
# JSONERR if it does not parse.
facts() {
	"$CTL" -S "$(sock "$1")" json >"$WORK/ns$1.json" 2>&1
	python3 - "$WORK/ns$1.json" <<'EOF'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception as e:
    print("JSONERR", e); sys.exit(0)
for p in d["ports"]:
    print(f"port {p['name']} n={len(p['neighbors'])} own={p['stats']['own_frames']}")
    for n in p["neighbors"]:
        caps = ",".join(n["capabilities"]["enabled"]) if n["capabilities"] else "-"
        mg = ",".join(m["address"] for m in n["management_addresses"])
        print(f"nb {p['name']} {n['chassis_id']['value']} {n['port_id']['value']} "
              f"name={n['system_name']} pdesc={n['port_description']} caps={caps} mgmt={mg}")
EOF
}

# wait until facts for ns $1 contain fixed string $3 (timeout $2 s)
wait_fact() {
	local deadline=$(( $(mono_ms) + $2 * 1000 ))
	while (( $(mono_ms) < deadline )); do
		facts "$1" | grep -qF -- "$3" && return 0
		sleep 0.1
	done
	return 1
}

mkveth() {   # mkveth <ns> <ifname> <mac> <bridge-port> <alias>
	ip -n "$1" link add "$2" address "$3" type veth peer name "$4" netns $BRNS
	ip -n $BRNS link set "$4" master br0
	ip -n $BRNS link set "$4" up
	ip -n "$1" link set "$2" alias "$5"
	ip -n "$1" link set "$2" up
}

cleanup() {
	for k in "${!PID[@]}"; do kill -KILL "${PID[$k]}" 2>/dev/null; done
	wait 2>/dev/null
	for ns in lldp-ns1 lldp-ns2 lldp-ns3 $BRNS; do
		ip netns del "$ns" 2>/dev/null
	done
	if [[ -n ${WORK:-} && -d $WORK ]]; then
		find "$WORK" -type s -delete    # control sockets cannot be copied
		cp -a "$WORK"/. "$OUT"/ && rm -rf "$WORK"
	fi
}

if [[ $EUID -ne 0 ]]; then echo "testbed.sh: must run as root" >&2; exit 2; fi
[[ -x $BIN && -x $CTL ]] || { echo "testbed.sh: build lldpnd and lldpnd-ctl first (make)" >&2; exit 2; }
for t in ip tcpdump tshark python3 nsenter unshare; do
	command -v $t >/dev/null || { echo "testbed.sh: needs $t" >&2; exit 2; }
done

trap cleanup EXIT
cleanup
rm -rf "$OUT"; mkdir -p "$OUT"
# work on the Linux filesystem (fast, coherent); artifacts are copied to $OUT on exit
WORK=$(mktemp -d /tmp/lldp-testbed.XXXXXX)
chmod 755 "$WORK"

RUN="$BIN"
if [[ ${VALGRIND:-0} == 1 ]]; then
	RUN="valgrind -q --vgdb=no --leak-check=full --show-leak-kinds=all --errors-for-leak-kinds=all --error-exitcode=99 $BIN"
fi
COMMON="-t $TX -H $HOLD"
echo "== lldpnd testbed: $RUN  (tx=${TX}s hold=$HOLD ttl=${TTL}s)"

# ---------------------------------------------------------------- topology
ip netns add $BRNS
ip -n $BRNS link set lo up
ip -n $BRNS link add br0 type bridge stp_state 0
ip -n $BRNS link set br0 up
for i in 1 2 3; do
	ip netns add lldp-ns$i
	ip -n lldp-ns$i link set lo up
	mkveth lldp-ns$i eth0 "$(mac $i)" brp$i "ns$i uplink to br0"
	ip -n lldp-ns$i addr add 192.0.2.$i/24 dev eth0
done
mkveth lldp-ns1 eth1 "$(mac 17)" brp1b "ns1 second port"
echo "   bridge group_fwd_mask = $(ip netns exec $BRNS cat /sys/class/net/br0/bridge/group_fwd_mask)"

# capture on bridge port brp1: sees ns1/eth0's frames and everything forwarded to it
ip netns exec $BRNS tcpdump -Z root --immediate-mode -i brp1 -U -nn -w "$WORK/lldp.pcap" \
	ether proto 0x88cc 2>"$WORK/tcpdump.err" &
PID[tcpdump]=$!
# record (wall clock - monotonic) so any wall-clock step during the run is visible
while :; do echo $(( $(date +%s%3N) - $(mono_ms) )); sleep 0.5; done >"$WORK/clock.log" &
PID[clock]=$!
sleep 1

ip netns exec lldp-ns1 $RUN -i eth0,eth1 $COMMON -n ns1 -S "$(sock 1)" >"$(log 1)" 2>&1 &
PID[ns1]=$!
# ns2: own UTS namespace, System Name from the hostname, unprivileged after start-up
ip netns exec lldp-ns2 unshare --uts sh -c \
	"hostname ns2 && exec $RUN -i eth0 $COMMON -S $(sock 2) -U nobody" >"$(log 2)" 2>&1 &
PID[ns2]=$!
ip netns exec lldp-ns3 $RUN -i eth0 $COMMON -n ns3 -S "$(sock 3)" >"$(log 3)" 2>&1 &
PID[ns3]=$!

# ---------------------------------------------------------------- phase 0
echo "-- phase 0: default bridge drops the nearest-bridge group address"
sleep $((TX * 2 + 1))
n=$(cat "$(log 1)" "$(log 2)" "$(log 3)" | grep -c "NEIGHBOUR ADD")
check "no neighbours learned through a standard bridge ($n)" test "$n" -eq 0
for i in 1 2 3; do
	check "ns$i daemon running" kill -0 "${PID[ns$i]}"
done

# ---------------------------------------------------------------- phase 1
echo "-- phase 1: group_fwd_mask 0x4000 -> discovery"
ip -n $BRNS link set br0 type bridge group_fwd_mask 0x4000
t0=$(mono_ms)
learn() {   # learn <ns> <port-tag> <chassis-n> <remote-port> <name>
	if wait_for $((TX + 3)) "$(log "$1")" "[$2] NEIGHBOUR ADD chassis=$(mac "$3") port=$4(st5) name=$5"
	then ok "ns$1/$2 learned $5/$4"
	else bad "ns$1/$2 did not learn $5/$4"; fi
}
learn 1 eth0 2 eth0 ns2; learn 1 eth0 3 eth0 ns3
learn 1 eth1 2 eth0 ns2; learn 1 eth1 3 eth0 ns3
learn 2 eth0 1 eth0 ns1; learn 2 eth0 1 eth1 ns1; learn 2 eth0 3 eth0 ns3
learn 3 eth0 1 eth0 ns1; learn 3 eth0 1 eth1 ns1; learn 3 eth0 2 eth0 ns2
echo "   all neighbours learned in $(( $(mono_ms) - t0 )) ms"
for p in eth0 eth1; do
	check "ns1/$p reports its own LLDPDU from the other port (loop)" \
		wait_for 3 "$(log 1)" "[$p] LOOP: received our own LLDPDU"
done

# ---------------------------------------------------------------- phase 2
echo "-- phase 2: control socket (lldpnd-ctl json) on every daemon"
for i in 1 2 3; do facts $i >"$WORK/facts$i.txt"; done
for i in 1 2 3; do
	check "ns$i JSON parses" bash -c "! grep -q JSONERR '$WORK/facts$i.txt'"
done
check "ns1 port eth0 has 2 neighbours and saw its own frames" grep -qE "^port eth0 n=2 own=[1-9]" "$WORK/facts1.txt"
check "ns1 port eth1 has 2 neighbours and saw its own frames" grep -qE "^port eth1 n=2 own=[1-9]" "$WORK/facts1.txt"
check "ns2 has 3 neighbours (ns1 twice, ns3)" grep -qF "port eth0 n=3" "$WORK/facts2.txt"
check "ns2 sees ns3: name, port desc from alias, station, mgmt 192.0.2.3" \
	grep -qF "nb eth0 $(mac 3) eth0 name=ns3 pdesc=ns3 uplink to br0 caps=station mgmt=192.0.2.3," "$WORK/facts2.txt"
check "ns2 sees ns1/eth1 with the same chassis ID as ns1/eth0" \
	grep -qF "nb eth0 $(mac 1) eth1 name=ns1 pdesc=ns1 second port" "$WORK/facts2.txt"
check "ns3 sees ns2 named by its hostname, mgmt 192.0.2.2" \
	grep -qF "nb eth0 $(mac 2) eth0 name=ns2 pdesc=ns2 uplink to br0 caps=station mgmt=192.0.2.2," "$WORK/facts3.txt"
check "lldpnd-ctl show"  bash -c "'$CTL' -S '$(sock 1)' show | grep -q 'eth1 neighbour table: 2 entries'"
check "lldpnd-ctl stats" bash -c "'$CTL' -S '$(sock 1)' stats | grep -qE '^eth1 '"
check "lldpnd-ctl local" bash -c "'$CTL' -S '$(sock 1)' local | grep -q 'mgmt addr 192.0.2.1'"
check "lldpnd-ctl rejects unknown commands" bash -c "'$CTL' -S '$(sock 1)' bogus | grep -q '^error:'"

# ---------------------------------------------------------------- phase 3
echo "-- phase 3: malformed frames injected from ns3 are rejected by ns1"
mapfile -t expects < <(ip netns exec lldp-ns3 python3 "$here/inject_lldp.py" eth0 $INJ_MAC)
for e in "${expects[@]}"; do
	if [[ $e == NEIGHBOUR* ]]; then pat="$e"; else pat="discard from $INJ_MAC: $e"; fi
	check "ns1: $pat" wait_for 2 "$(log 1)" "$pat"
done
check "ns1 daemon survived the malformed frames" kill -0 "${PID[ns1]}"

# ---------------------------------------------------------------- phase 4
echo "-- phase 4: local changes are advertised immediately"
change() {   # change <description> <expected-fact-in-ns1> <command...>
	local d=$1 want=$2; shift 2
	local t=$(mono_ms)
	"$@"
	if wait_fact 1 3 "$want"; then
		ok "$d reached ns1 in $(( $(mono_ms) - t )) ms (periodic would take up to ${TX}000)"
	else
		bad "$d did not reach ns1"
	fi
}
change "ns3 alias change" "nb eth0 $(mac 3) eth0 name=ns3 pdesc=ns3 renamed uplink" \
	ip -n lldp-ns3 link set eth0 alias "ns3 renamed uplink"
change "ns2 hostname change" "nb eth0 $(mac 2) eth0 name=ns2-renamed" \
	nsenter -t "${PID[ns2]}" -u hostname ns2-renamed
change "ns3 new IPv6 address" "mgmt=192.0.2.3,2001:db8::3" \
	ip -n lldp-ns3 addr add 2001:db8::3/64 dev eth0 nodad
check "ns3 logged somethingChangedLocal" grep -qF "local information changed" "$(log 3)"
check "ns2 logged its new system name" grep -qF "system name changed: ns2 -> ns2-renamed" "$(log 2)"

# ---------------------------------------------------------------- phase 5
echo "-- phase 5: privilege drop (ns2 runs with -U nobody)"
st=$(grep -E '^(Uid|CapEff):' /proc/"${PID[ns2]}"/status | tr -s '\t ' ' ' | tr '\n' ';')
check "ns2 runs as uid 65534 ($st)" test "$(awk '/^Uid:/ {print $2,$3,$4,$5}' /proc/"${PID[ns2]}"/status)" = "65534 65534 65534 65534"
check "ns2 effective capabilities are CAP_NET_RAW only" \
	grep -qE '^CapEff:\s+0000000000002000$' /proc/"${PID[ns2]}"/status

# ---------------------------------------------------------------- phase 6
echo "-- phase 6: link flap on ns1/eth1"
ip -n lldp-ns1 link set eth1 down
check "ns1/eth1 link down detected" wait_for 3 "$(log 1)" "[eth1] link down"
check "ns1/eth1 flushed its neighbours" wait_for 2 "$(log 1)" "[eth1] NEIGHBOUR FLUSH chassis=$(mac 3)"
sleep 1
n0=$(grep -c "\[eth1\] NEIGHBOUR ADD chassis=$(mac 2)" "$(log 1)")
t0=$(mono_ms)
ip -n lldp-ns1 link set eth1 up
if wait_fact 1 $((TX + 5)) "port eth1 n=2"; then
	ok "ns1/eth1 re-learned both neighbours $(( $(mono_ms) - t0 )) ms after link up"
else
	bad "ns1/eth1 did not re-learn its neighbours"
fi
check "ns1/eth1 logged a new ADD after the flap" \
	test "$(grep -c "\[eth1\] NEIGHBOUR ADD chassis=$(mac 2)" "$(log 1)")" -gt "$n0"

# ---------------------------------------------------------------- phase 7
echo "-- phase 7: ns2's interface deleted and re-created (daemon is unprivileged)"
ip -n lldp-ns2 link del eth0
check "ns2 detached the vanished interface" wait_for 3 "$(log 2)" "[eth0] detached: interface removed"
mkveth lldp-ns2 eth0 "$(mac 2)" brp2 "ns2 uplink to br0"
ip -n lldp-ns2 addr add 192.0.2.2/24 dev eth0
check "ns2 re-attached (new AF_PACKET socket with retained CAP_NET_RAW)" \
	wait_for 5 "$(log 2)" "[eth0] attached: ifindex="
check "ns2 re-learned ns3 after re-creation" wait_fact 2 $((TX + 5)) "nb eth0 $(mac 3) eth0 name=ns3"
check "ns2 still unprivileged" test "$(awk '/^Uid:/ {print $2}' /proc/"${PID[ns2]}"/status)" = 65534

# ---------------------------------------------------------------- phase 8
echo "-- phase 8: ns3 goes down hard (SIGKILL + netns deleted) -> TTL ageout"
t0=$(mono_ms)
kill -KILL "${PID[ns3]}"; wait "${PID[ns3]}" 2>/dev/null; unset 'PID[ns3]'
ip netns del lldp-ns3
ageout() {   # ageout <ns> <port-tag>
	local f; f=$(log "$1")
	if wait_for $((TTL + 3)) "$f" "[$2] NEIGHBOUR AGEOUT chassis=$(mac 3)"; then
		local ms=$(( $(mono_ms) - t0 ))
		# last frame from ns3 was 0..TX s before the kill: expiry TTL-TX..TTL s later
		if (( ms >= (TTL - TX) * 1000 - 300 && ms <= TTL * 1000 + 300 )); then
			ok "ns$1/$2 aged out ns3 ${ms} ms after the kill (expected $((TTL - TX))-${TTL}s)"
		else
			bad "ns$1/$2 aged out ns3 ${ms} ms after the kill, outside $((TTL - TX))-${TTL}s"
		fi
		# the daemon's own monotonic measurement: last rx -> removal
		local age
		age=$(grep -F "[$2] NEIGHBOUR AGEOUT chassis=$(mac 3)" "$f" |
		      sed -n 's/.*last rx \([0-9]*\) ms ago.*/\1/p' | head -1)
		if [[ -n $age ]] && (( age >= TTL * 1000 && age <= TTL * 1000 + 250 )); then
			ok "ns$1/$2 removed ns3 ${age} ms after its last LLDPDU (TTL ${TTL}000 ms)"
		else
			bad "ns$1/$2 removed ns3 '${age}' ms after its last LLDPDU"
		fi
	else
		bad "ns$1/$2 never aged out ns3"
	fi
}
ageout 1 eth0; ageout 1 eth1; ageout 2 eth0
check "ns1 kept live neighbour ns2" bash -c "! grep -qF 'NEIGHBOUR AGEOUT chassis=$(mac 2)' '$(log 1)'"
check "ns2 kept live neighbour ns1" bash -c "! grep -qF 'NEIGHBOUR AGEOUT chassis=$(mac 1)' '$(log 2)'"

# ---------------------------------------------------------------- phase 9
echo "-- phase 9: ns2 shuts down gracefully -> shutdown LLDPDU (TTL 0)"
t0=$(mono_ms)
kill -INT "${PID[ns2]}"
for p in eth0 eth1; do
	if wait_for 2 "$(log 1)" "[$p] NEIGHBOUR DELETE chassis=$(mac 2) port=eth0(st5)"; then
		ok "ns1/$p deleted ns2 after $(( $(mono_ms) - t0 )) ms (no ageout wait)"
	else
		bad "ns1/$p did not process ns2's shutdown LLDPDU"
	fi
done
wait "${PID[ns2]}"; rc=$?; unset 'PID[ns2]'
check "ns2 exited 0 on SIGINT (status $rc)" test "$rc" -eq 0

# ---------------------------------------------------------------- phase 10
echo "-- phase 10: stop ns1, decode capture with tshark"
sleep 1
kill -INT "${PID[ns1]}"
wait "${PID[ns1]}"; rc=$?; unset 'PID[ns1]'
check "ns1 exited 0 on SIGINT (status $rc)" test "$rc" -eq 0
grep "stats:" "$(log 1)" | sed 's/^/   /'
sleep 1    # let tcpdump read the final shutdown frames
kill -INT "${PID[tcpdump]}"; wait "${PID[tcpdump]}" 2>/dev/null; unset 'PID[tcpdump]'

P="$WORK/lldp.pcap"
ours='lldp && eth.src != '$INJ_MAC
total=$(tshark -r "$P" -Y "$ours" 2>/dev/null | wc -l)
malformed=$(tshark -r "$P" -Y "($ours) && (_ws.malformed || _ws.expert.severity >= warning)" 2>/dev/null | wc -l)
inj_bad=$(tshark -r "$P" -Y "eth.src == $INJ_MAC && _ws.malformed" 2>/dev/null | wc -l)
shutdowns=$(tshark -r "$P" -Y "($ours) && lldp.time_to_live == 0" -T fields -e eth.src 2>/dev/null | sort -u | tr '\n' ' ')
echo "   capture: $(tshark -r "$P" 2>/dev/null | wc -l) frames, $total from the daemons"
check "tshark decodes $total daemon frames as LLDP" test "$total" -gt 0
check "0 daemon frames flagged malformed/warning by Wireshark's dissector ($malformed)" test "$malformed" -eq 0
echo "   (Wireshark also flags $inj_bad of the deliberately malformed injected frames)"
check "shutdown LLDPDUs from ns1/eth0, ns1/eth1, ns2 only ('$shutdowns')" \
	test "$shutdowns" = "$(mac 1) $(mac 2) $(mac 17) "

fields() {   # first frame from a source MAC with TTL != 0, matching an optional filter
	tshark -r "$P" -Y "eth.src == $1 && lldp.time_to_live != 0 ${2:-}" \
		-T fields -E separator='|' -e lldp.chassis.id.mac -e lldp.port.id \
		-e lldp.time_to_live -e lldp.tlv.system.name -e lldp.port.desc \
		-e lldp.tlv.system_cap -e lldp.tlv.enable_system_cap -e lldp.mgn.addr.ip4 \
		2>/dev/null | head -1
}
want1="$(mac 1)|eth0|$TTL|ns1|ns1 uplink to br0|0x0090|0x0080|192.0.2.1"
want17="$(mac 1)|eth1|$TTL|ns1|ns1 second port|0x0090|0x0080|"
want3="$(mac 3)|eth0|$TTL|ns3|ns3 renamed uplink|0x0090|0x0080|192.0.2.3"
f=$(fields "$(mac 1)");  check "ns1/eth0 decoded: $f" test "$f" = "$want1"
f=$(fields "$(mac 17)"); check "ns1/eth1 decoded (same chassis): $f" test "$f" = "$want17"
f=$(fields "$(mac 3)" '&& lldp.port.desc == "ns3 renamed uplink"')
check "ns3 decoded after alias change: $f" test "$f" = "$want3"
v6=$(tshark -r "$P" -Y "eth.src == $(mac 3) && lldp.mgn.addr.ip6 == 2001:db8::3" 2>/dev/null | wc -l)
check "ns3's IPv6 management address decoded ($v6 frames)" test "$v6" -gt 0

# full dissection of ns1's first frame, plus one shutdown LLDPDU
tshark -r "$P" -Y "eth.src == $(mac 1) && lldp.time_to_live != 0" -V -x 2>/dev/null \
	| awk '/^Frame / && n++ {exit} {print}' >"$WORK/dissection.txt"
tshark -r "$P" -Y "($ours) && lldp.time_to_live == 0" -V -x 2>/dev/null \
	| awk '/^Frame / && n++ {exit} {print}' >>"$WORK/dissection.txt"
tshark -r "$P" -Y "lldp" -T fields -e frame.number -e frame.time_relative \
	-e eth.src -e lldp.port.id -e lldp.time_to_live -e lldp.tlv.system.name \
	-e _ws.malformed 2>/dev/null >"$WORK/summary.tsv"

kill "${PID[clock]}" 2>/dev/null; wait "${PID[clock]}" 2>/dev/null; unset 'PID[clock]'
step=$(sort -n "$WORK/clock.log" | sed -n '1p;$p' | paste -sd' ' | awk '{print $2 - $1}')
echo "   wall clock vs monotonic drift during run: ${step} ms (informational)"

echo
echo "== artifacts (copied to $OUT on exit): lldp.pcap, dissection.txt, summary.tsv, ns*.log, ns*.json"
echo "== result: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
