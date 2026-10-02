#!/usr/bin/env bash
#
# modes_test.sh - adminStatus modes, destination group addresses, several
# agents on one port, LLDP over VLAN sub-interfaces, the 802.3 Maximum Frame
# Size following the MTU, and decoding of 802.1/802.3 extensions.
#
#     lldp-ma: eth0 02:00:00:00:a0:01  <-- veth -->  lldp-mb: eth0 02:00:00:00:b0:01
#
# Usage (root):  scripts/modes_test.sh
#
set -u
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
BIN=${BIN:-$root/build/lldpnd}
CTL=${CTL:-$root/build/lldpnd-ctl}
OUT=${OUT:-$root/build/modes}
A=lldp-ma; B=lldp-mb
MAC_A=02:00:00:00:a0:01; MAC_B=02:00:00:00:b0:01; INJ=02:00:00:00:e0:01
pass=0; fail=0
declare -A PID

ok()   { echo "  PASS: $*"; pass=$((pass + 1)); }
bad()  { echo "  FAIL: $*"; fail=$((fail + 1)); }
check() { local d=$1; shift; if "$@"; then ok "$d"; else bad "$d"; fi; }
mono_ms() { local up; read -r up _ </proc/uptime; echo $(( 10#${up/./} * 10 )); }

# start <name> <netns> <args...>: daemon with its own log and control socket
start() {
	local name=$1 ns=$2; shift 2
	ip netns exec "$ns" "$BIN" -t 2 -H 3 -S "$WORK/$name.sock" "$@" >"$WORK/$name.log" 2>&1 &
	PID[$name]=$!
}
stop() {   # stop <name>: SIGINT, returns the exit status
	kill -INT "${PID[$1]}"; wait "${PID[$1]}"; local rc=$?; unset "PID[$1]"; return $rc
}
# flattened JSON view of daemon <name>
view() {
	"$CTL" -S "$WORK/$1.sock" json >"$WORK/$1.json" 2>&1
	python3 - "$WORK/$1.json" <<'EOF'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception as e:
    print("JSONERR", e); sys.exit(0)
print("mode=%s dest=%s" % (d["admin_status"], d["destination"]["name"]))
for p in d["ports"]:
    s = p["stats"]
    print("port=%s mtu=%d out=%d in=%d n=%d" % (p["name"], p["mtu"], s["frames_out"],
                                                s["frames_in"], len(p["neighbors"])))
    for n in p["neighbors"]:
        e1, e3 = n["ieee8021"], n["ieee8023"]
        print("nb=%s name=%s" % (n["chassis_id"]["value"], n["system_name"]))
        print("pvid=%s vlan=%s" % (e1["port_vlan_id"],
              "%d:%s" % (e1["vlan_name"]["vlan_id"], e1["vlan_name"]["name"]) if e1["vlan_name"] else None))
        mp = e3["mac_phy"]
        print("macphy=%s" % ("%s/%s/%d" % (mp["autoneg_supported"], mp["autoneg_enabled"], mp["mau_type"]) if mp else None))
        la = e3["link_aggregation"]
        print("lag=%s mfs=%s" % ("%s/%s/%d" % (la["capable"], la["enabled"], la["port_id"]) if la else None,
                                 e3["max_frame_size"]))
EOF
}
vgrep() {       # vgrep <name> <extended-regex>: match against the current view
	view "$1" | grep -qE -- "$2"
}
wait_view() {   # wait_view <timeout-s> <name> <fixed-string>
	local deadline=$(( $(mono_ms) + $1 * 1000 ))
	while (( $(mono_ms) < deadline )); do
		view "$2" | grep -qF -- "$3" && return 0
		sleep 0.1
	done
	return 1
}
wait_log() {    # wait_log <timeout-s> <name> <fixed-string>
	local deadline=$(( $(mono_ms) + $1 * 1000 ))
	while (( $(mono_ms) < deadline )); do
		grep -qF -- "$3" "$WORK/$2.log" 2>/dev/null && return 0
		sleep 0.05
	done
	return 1
}

cleanup() {
	for k in "${!PID[@]}"; do kill -KILL "${PID[$k]}" 2>/dev/null; done
	wait 2>/dev/null
	ip netns del $A 2>/dev/null; ip netns del $B 2>/dev/null
	if [[ -n ${WORK:-} && -d $WORK ]]; then
		find "$WORK" -type s -delete
		cp -a "$WORK"/. "$OUT"/ && rm -rf "$WORK"
	fi
}
[[ $EUID -eq 0 ]] || { echo "modes_test.sh: must run as root" >&2; exit 2; }
[[ -x $BIN && -x $CTL ]] || { echo "modes_test.sh: build first (make)" >&2; exit 2; }
trap cleanup EXIT
cleanup
rm -rf "$OUT"; mkdir -p "$OUT"
WORK=$(mktemp -d /tmp/lldp-modes.XXXXXX)

ip netns add $A; ip netns add $B
ip -n $A link add eth0 address $MAC_A type veth peer name eth0 netns $B address $MAC_B
for n in $A $B; do
	ip netns exec $n sysctl -qw net.ipv4.conf.all.forwarding=0 net.ipv6.conf.all.forwarding=0
	ip -n $n link set lo up; ip -n $n link set eth0 up
done
ip netns exec $A tcpdump -Z root --immediate-mode -i eth0 -U -nn -w "$WORK/modes.pcap" \
	2>"$WORK/tcpdump.err" &
PID[tcpdump]=$!
sleep 0.5

# ------------------------------------------------------------------ adminStatus
echo "-- adminStatus (9.2.5.1): A transmit-only, B receive-only"
start atx $A -i eth0 -m tx -n a-txonly
start brx $B -i eth0 -m rx -n b-rxonly
check "receive-only B learned transmit-only A" wait_log 4 brx "NEIGHBOUR ADD chassis=$MAC_A"
# a valid LLDPDU injected towards each side: only the receive-capable agent
# may take it (an injected frame leaves the namespace it is sent from)
ip netns exec $B python3 "$here/inject_lldp.py" eth0 $INJ extensions >/dev/null
ip netns exec $A python3 "$here/inject_lldp.py" eth0 $INJ extensions >/dev/null
sleep 1
check "transmit-only A sent frames, received none, has no neighbours" \
	vgrep atx '^port=eth0 mtu=1500 out=[1-9][0-9]* in=0 n=0$'
check "receive-only B transmitted nothing" vgrep brx '^port=eth0 mtu=1500 out=0 in=[1-9]'
check "control socket reports mode=tx / mode=rx" \
	bash -c "'$CTL' -S '$WORK/atx.sock' json | grep -q '\"admin_status\":\"tx\"' &&
	         '$CTL' -S '$WORK/brx.sock' json | grep -q '\"admin_status\":\"rx\"'"
check "B decoded the injected 802.1/802.3 extensions" \
	wait_view 2 brx "pvid=100 vlan=100:voice"
v=$(view brx)
check "  MAC/PHY: autoneg supported/enabled, MAU 16" grep -qF "macphy=True/True/16" <<<"$v"
check "  link aggregation capable/enabled, port 7; MFS 1522" grep -qF "lag=True/True/7 mfs=1522" <<<"$v"
t0=$(mono_ms)
stop atx; rc=$?
check "transmit-only A exited 0 ($rc)" test $rc -eq 0
check "A's shutdown LLDPDU removed it from B" wait_log 2 brx "NEIGHBOUR DELETE chassis=$MAC_A"
stop brx; rc=$?
check "receive-only B exited 0 ($rc)" test $rc -eq 0
check "receive-only B sent no shutdown LLDPDU" bash -c "! grep -q 'sent shutdown' '$WORK/brx.log'"

# ------------------------------------------------- destination addresses
echo "-- destination group addresses (7.1); two agents on one port"
start a_nb $A -i eth0 -n a-nearest-bridge
start a_nc $A -i eth0 -n a-nearest-customer -a nearest-customer
start b_nc $B -i eth0 -n b-nearest-customer -a nearest-customer
check "B (nearest-customer) learned A's nearest-customer agent" \
	wait_log 4 b_nc "NEIGHBOUR ADD chassis=$MAC_A port=eth0(st5) name=a-nearest-customer"
check "A's nearest-customer agent learned B" \
	wait_log 4 a_nc "NEIGHBOUR ADD chassis=$MAC_B port=eth0(st5) name=b-nearest-customer"
check "B ignored A's nearest-bridge LLDPDUs (wrong destination)" \
	wait_log 4 b_nc "rx: discard from $MAC_A: not LLDP / wrong destination"
check "A's nearest-bridge agent ignored B's nearest-customer LLDPDUs" \
	wait_log 4 a_nb "rx: discard from $MAC_B: not LLDP / wrong destination"
check "A's nearest-bridge agent has no neighbours" wait_view 2 a_nb "n=0"
check "control socket reports dest=nearest-customer" bash -c "'$CTL' -S '$WORK/a_nc.sock' local | grep -q 'destination nearest-customer (01:80:c2:00:00:00)'"
for d in a_nb a_nc b_nc; do stop $d; done

# ------------------------------------------------------ VLAN sub-interfaces
echo "-- LLDP over VLAN sub-interfaces (eth0.100)"
for n in $A $B; do
	ip -n $n link add link eth0 name eth0.100 type vlan id 100
	ip -n $n link set eth0.100 up
done
start a_v $A -i eth0.100 -n a-vlan100
start b_v $B -i eth0.100 -n b-vlan100
check "A learned B over VLAN 100" wait_log 5 a_v "NEIGHBOUR ADD chassis=$MAC_B port=eth0.100(st5) name=b-vlan100"
check "B learned A over VLAN 100" wait_log 5 b_v "NEIGHBOUR ADD chassis=$MAC_A port=eth0.100(st5) name=a-vlan100"

# ---------------------------------------------- Maximum Frame Size follows MTU
echo "-- 802.3 Maximum Frame Size tracks the MTU live"
check "B sees A's MFS 1518 (MTU 1500)" wait_view 3 b_v "lag=None mfs=1518"
t0=$(mono_ms)
ip -n $A link set eth0 mtu 9000
ip -n $A link set eth0.100 mtu 9000
if wait_view 3 b_v "lag=None mfs=9018"; then
	ok "MTU 9000 on A reached B as MFS 9018 in $(( $(mono_ms) - t0 )) ms"
else
	bad "B did not see A's new MFS"
fi
for d in a_v b_v; do stop $d; done
sleep 0.5
kill -INT "${PID[tcpdump]}"; wait "${PID[tcpdump]}" 2>/dev/null; unset 'PID[tcpdump]'

# ------------------------------------------------------------------ capture
echo "-- capture decoded by tshark"
P="$WORK/modes.pcap"
c00=$(tshark -r "$P" -Y "lldp && eth.dst == 01:80:c2:00:00:00" 2>/dev/null | wc -l)
c0e=$(tshark -r "$P" -Y "lldp && eth.dst == 01:80:c2:00:00:0e" 2>/dev/null | wc -l)
cv=$(tshark -r "$P" -Y "lldp && vlan.id == 100" 2>/dev/null | wc -l)
cm=$(tshark -r "$P" -Y "lldp && eth.src == $MAC_A && lldp.ieee.802_3.max_frame_size == 9018" 2>/dev/null | wc -l)
bad_frames=$(tshark -r "$P" -Y "lldp && eth.src != $INJ && (_ws.malformed || _ws.expert.severity >= warning)" 2>/dev/null | wc -l)
check "LLDPDUs to nearest-customer 01:80:c2:00:00:00 on the wire ($c00)" test "$c00" -gt 0
check "LLDPDUs to nearest-bridge 01:80:c2:00:00:0e on the wire ($c0e)" test "$c0e" -gt 0
check "LLDPDUs tagged with VLAN 100 on the wire ($cv)" test "$cv" -gt 0
check "Wireshark decodes the 802.3 MFS 9018 ($cm)" test "$cm" -gt 0
check "no daemon frame flagged malformed by Wireshark ($bad_frames)" test "$bad_frames" -eq 0

echo
echo "== result: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
