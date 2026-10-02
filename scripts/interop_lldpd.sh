#!/usr/bin/env bash
#
# interop_lldpd.sh - interoperability test against lldpd, the widely used
# open-source LLDP implementation (https://lldpd.github.io).
#
#     lldp-ia: lldpnd                      lldp-ib: lldpd
#     eth0 02:00:00:00:0a:01  <-- veth -->  eth0 02:00:00:00:0b:01
#     192.0.2.1, 2001:db8::1                192.0.2.2, 2001:db8::2
#
# Checks, in both directions, that each implementation decodes the other:
# chassis/port IDs, TTL, names, descriptions, capabilities, management
# addresses; that local changes propagate immediately; and that each
# side's shutdown LLDPDU removes it from the other's table at once.
#
# Usage (root):  scripts/interop_lldpd.sh      (needs lldpd + lldpcli)
#
set -u

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
BIN=${BIN:-$root/build/lldpnd}
CTL=${CTL:-$root/build/lldpnd-ctl}
OUT=${OUT:-$root/build/interop}
TX=2; HOLD=3; TTL=$((TX * HOLD + 1))
A=lldp-ia; B=lldp-ib
MAC_A=02:00:00:00:0a:01; MAC_B=02:00:00:00:0b:01

pass=0; fail=0
declare -A PID

ok()   { echo "  PASS: $*"; pass=$((pass + 1)); }
bad()  { echo "  FAIL: $*"; fail=$((fail + 1)); }
check() { local d=$1; shift; if "$@"; then ok "$d"; else bad "$d"; fi; }
mono_ms() { local up; read -r up _ </proc/uptime; echo $(( 10#${up/./} * 10 )); }

# lldpd's view of its neighbours, one key=value per line
lldpd_view() {
	ip netns exec $B lldpcli -u "$WORK/lldpd.sock" -f keyvalue show neighbors details 2>/dev/null
}
# lldpnd's view, flattened from its JSON
lldpnd_view() {
	"$CTL" -S "$WORK/lldpnd.sock" json >"$WORK/lldpnd.json" 2>&1
	python3 - "$WORK/lldpnd.json" <<'EOF'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception as e:
    print("JSONERR", e); sys.exit(0)
for p in d["ports"]:
    for n in p["neighbors"]:
        c = n["capabilities"] or {"supported": [], "enabled": []}
        print("chassis=%s/%s" % (n["chassis_id"]["subtype"], n["chassis_id"]["value"]))
        print("port=%s/%s" % (n["port_id"]["subtype"], n["port_id"]["value"]))
        print("ttl=%d" % n["ttl"])
        print("name=%s" % n["system_name"])
        print("descr=%s" % n["system_description"])
        print("pdesc=%s" % n["port_description"])
        print("caps=%s enabled=%s" % (",".join(c["supported"]), ",".join(c["enabled"])))
        for m in n["management_addresses"]:
            print("mgmt=%s/%s/if%d" % (m["family"], m["address"], m["if_number"]))
        print("org_tlvs=%d" % n["org_specific_tlvs"])
EOF
}
# wait_view <timeout-s> <lldpd|lldpnd> <fixed-string>
wait_view() {
	local deadline=$(( $(mono_ms) + $1 * 1000 ))
	while (( $(mono_ms) < deadline )); do
		"${2}_view" | grep -qF -- "$3" && return 0
		sleep 0.1
	done
	return 1
}
wait_log() {   # wait_log <timeout-s> <file> <fixed-string>
	local deadline=$(( $(mono_ms) + $1 * 1000 ))
	while (( $(mono_ms) < deadline )); do
		grep -qF -- "$3" "$2" 2>/dev/null && return 0
		sleep 0.05
	done
	return 1
}

start_lldpnd() {
	ip netns exec $A "$BIN" -i eth0 -t $TX -H $HOLD -n lldpnd-host -S "$WORK/lldpnd.sock" \
		>>"$WORK/lldpnd.log" 2>&1 &
	PID[lldpnd]=$!
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

if [[ $EUID -ne 0 ]]; then echo "interop_lldpd.sh: must run as root" >&2; exit 2; fi
for t in lldpd lldpcli tshark tcpdump python3; do
	command -v $t >/dev/null || { echo "interop_lldpd.sh: needs $t" >&2; exit 2; }
done
[[ -x $BIN && -x $CTL ]] || { echo "interop_lldpd.sh: build first (make)" >&2; exit 2; }

trap cleanup EXIT
cleanup
rm -rf "$OUT"; mkdir -p "$OUT"
WORK=$(mktemp -d /tmp/lldp-interop.XXXXXX)
chmod 755 "$WORK"    # lldpd's privilege-separated child (_lldpd) must reach its socket
echo "== interop: lldpnd vs $(lldpd -v 2>&1 | head -1 | sed 's/^/lldpd /')"

ip netns add $A; ip netns add $B
ip -n $A link add eth0 address $MAC_A type veth peer name eth0 netns $B address $MAC_B
ip -n $A addr add 192.0.2.1/24 dev eth0; ip -n $A addr add 2001:db8::1/64 dev eth0 nodad
ip -n $B addr add 192.0.2.2/24 dev eth0; ip -n $B addr add 2001:db8::2/64 dev eth0 nodad
ip -n $A link set eth0 alias "lldpnd port"
for n in $A $B; do ip -n $n link set lo up; ip -n $n link set eth0 up; done

ip netns exec $A tcpdump -Z root --immediate-mode -i eth0 -U -nn -w "$WORK/interop.pcap" \
	ether proto 0x88cc 2>"$WORK/tcpdump.err" &
PID[tcpdump]=$!
sleep 0.5
# lldpd: foreground, private control socket, only eth0, 1 s transmit interval
ip netns exec $B lldpd -d -u "$WORK/lldpd.sock" -p "$WORK/lldpd.pid" -I eth0 \
	>"$WORK/lldpd.log" 2>&1 &
PID[lldpd]=$!
wait_log 5 "$WORK/lldpd.log" "lldpd should resume operations" || sleep 1
ip netns exec $B lldpcli -u "$WORK/lldpd.sock" configure lldp tx-interval 1 >/dev/null
ip netns exec $B lldpcli -u "$WORK/lldpd.sock" configure system hostname lldpd-peer >/dev/null
start_lldpnd

# ------------------------------------------------------------ lldpd sees us
echo "-- lldpd decodes lldpnd"
check "lldpd learned lldpnd" wait_view 6 lldpd "chassis.mac=$MAC_A"
lldpd_view >"$WORK/lldpd_view.txt"
v() { grep -qF -- "$1" "$WORK/lldpd_view.txt"; }
check "chassis ID (MAC subtype)"     v "chassis.mac=$MAC_A"
check "system name"                  v "chassis.name=lldpnd-host"
check "system description"           v "chassis.descr=Linux "
check "port ID (ifname subtype)"     v "port.ifname=eth0"
check "port description from alias"  v "port.descr=lldpnd port"
check "TTL"                          v "port.ttl=$TTL"
check "management address IPv4"      v "chassis.mgmt-ip=192.0.2.1"
check "management address IPv6"      v "chassis.mgmt-ip=2001:db8::1"
check "capability Router supported, disabled" v "chassis.Router.enabled=off"
check "capability Station supported, enabled" v "chassis.Station.enabled=on"

# ------------------------------------------------------------ we see lldpd
echo "-- lldpnd decodes lldpd"
check "lldpnd learned lldpd" wait_view 6 lldpnd "chassis=mac/$MAC_B"
lldpnd_view >"$WORK/lldpnd_view.txt"
w() { grep -qF -- "$1" "$WORK/lldpnd_view.txt"; }
check "lldpnd JSON parses"              bash -c "! grep -q JSONERR '$WORK/lldpnd_view.txt'"
check "chassis ID (MAC subtype)"        w "chassis=mac/$MAC_B"
check "port ID (MAC subtype)"           w "port=mac/$MAC_B"
check "system name"                     w "name=lldpd-peer"
check "port description"                w "pdesc=eth0"
check "capabilities incl. station enabled" grep -qE "^caps=.*station.* enabled=station$" "$WORK/lldpnd_view.txt"
check "management address IPv4"         w "mgmt=ipv4/192.0.2.2/if"
check "management address IPv6"         w "mgmt=ipv6/2001:db8::2/if"
check "802.3 org-specific TLVs accepted and counted" grep -qE "^org_tlvs=[1-9]" "$WORK/lldpnd_view.txt"
check "no frames from lldpd rejected" bash -c "! grep -q 'rx: discard' '$WORK/lldpnd.log'"

# ------------------------------------------------------------ live changes
echo "-- local changes propagate immediately"
t0=$(mono_ms)
ip -n $A link set eth0 alias "lldpnd renamed port"
if wait_view 2 lldpd "port.descr=lldpnd renamed port"; then
	ok "lldpd saw lldpnd's new port description after $(( $(mono_ms) - t0 )) ms (periodic: ${TX}000)"
else
	bad "lldpd did not see the new port description"
fi
t0=$(mono_ms)
ip netns exec $B lldpcli -u "$WORK/lldpd.sock" configure system hostname lldpd-renamed >/dev/null
if wait_view 3 lldpnd "name=lldpd-renamed"; then
	ok "lldpnd saw lldpd's new system name after $(( $(mono_ms) - t0 )) ms"
else
	bad "lldpnd did not see lldpd's new system name"
fi

# ------------------------------------------------------------ shutdowns
echo "-- shutdown LLDPDUs"
t0=$(mono_ms)
kill -INT "${PID[lldpnd]}"; wait "${PID[lldpnd]}"; rc=$?; unset 'PID[lldpnd]'
check "lldpnd exited 0" test "$rc" -eq 0
gone=0
for _ in $(seq 1 30); do
	# only a successful query that lacks us counts (not an lldpcli error)
	if out=$(lldpd_view) && ! grep -qF "chassis.mac=$MAC_A" <<<"$out"; then
		gone=1
		break
	fi
	sleep 0.1
done
if [[ $gone == 1 ]]; then
	ok "lldpd removed lldpnd $(( $(mono_ms) - t0 )) ms after its shutdown LLDPDU (TTL ${TTL}s)"
else
	bad "lldpd still lists lldpnd after its shutdown LLDPDU"
fi

start_lldpnd
check "lldpnd re-learned lldpd after restart" wait_view 6 lldpnd "chassis=mac/$MAC_B"
t0=$(mono_ms)
kill -TERM "${PID[lldpd]}"; wait "${PID[lldpd]}" 2>/dev/null; unset 'PID[lldpd]'
if wait_log 3 "$WORK/lldpnd.log" "NEIGHBOUR DELETE chassis=$MAC_B"; then
	ok "lldpnd deleted lldpd $(( $(mono_ms) - t0 )) ms after lldpd's shutdown LLDPDU"
else
	bad "lldpnd did not process lldpd's shutdown LLDPDU"
fi
kill -INT "${PID[lldpnd]}"; wait "${PID[lldpnd]}"; unset 'PID[lldpnd]'
sleep 0.5
kill -INT "${PID[tcpdump]}"; wait "${PID[tcpdump]}" 2>/dev/null; unset 'PID[tcpdump]'

# ------------------------------------------------------------ capture
echo "-- capture decoded by tshark"
ours=$(tshark -r "$WORK/interop.pcap" -Y "eth.src == $MAC_A" 2>/dev/null | wc -l)
theirs=$(tshark -r "$WORK/interop.pcap" -Y "eth.src == $MAC_B" 2>/dev/null | wc -l)
bad_ours=$(tshark -r "$WORK/interop.pcap" -Y "eth.src == $MAC_A && (_ws.malformed || _ws.expert.severity >= warning)" 2>/dev/null | wc -l)
echo "   $ours frames from lldpnd, $theirs from lldpd"
check "lldpnd frames decode cleanly ($bad_ours flagged)" test "$ours" -gt 0 -a "$bad_ours" -eq 0
tshark -r "$WORK/interop.pcap" -Y "eth.src == $MAC_B" -V 2>/dev/null \
	| awk '/^Frame / && n++ {exit} {print}' >"$WORK/lldpd_frame.txt"

echo
echo "== artifacts (copied to $OUT): interop.pcap, lldpd_view.txt, lldpnd_view.txt, *.log"
echo "== result: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
