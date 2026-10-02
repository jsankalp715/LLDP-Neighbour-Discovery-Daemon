#!/usr/bin/env bash
#
# service_check.sh - run contrib/lldpnd.service under real systemd, with all
# its sandboxing, inside a throwaway network namespace, and check that it
# works: neighbour learned, unprivileged dynamic user holding only
# CAP_NET_RAW, control socket reachable, shutdown LLDPDU on stop.
#
# Temporary changes, all undone on exit: binaries under /opt/lldpnd-svc,
# a runtime unit in /run/systemd/system (tmpfs), network namespaces.
#
# Usage (root, systemd as PID 1):  scripts/service_check.sh
#
set -u
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
PFX=/opt/lldpnd-svc
UNIT=lldpnd-svc-test
NS=lldp-svc; PEER=lldp-svc-peer
pass=0; fail=0
ok()  { echo "  PASS: $*"; pass=$((pass + 1)); }
bad() { echo "  FAIL: $*"; fail=$((fail + 1)); }
check() { local d=$1; shift; if "$@"; then ok "$d"; else bad "$d"; fi; }

cleanup() {
	systemctl stop $UNIT 2>/dev/null
	rm -f /run/systemd/system/$UNIT.service
	systemctl daemon-reload
	[[ -n ${PEERPID:-} ]] && kill -KILL "$PEERPID" 2>/dev/null
	wait 2>/dev/null
	ip netns del $NS 2>/dev/null; ip netns del $PEER 2>/dev/null
	rm -rf "$PFX" /tmp/lldp-svc-peer.log
}
[[ $EUID -eq 0 && -d /run/systemd/system ]] || { echo "needs root and systemd" >&2; exit 2; }
trap cleanup EXIT
cleanup

echo "== install to $PFX"
make -C "$root" -s install DESTDIR= PREFIX=$PFX UNITDIR=$PFX/unit >/dev/null
check "binaries installed" test -x $PFX/sbin/lldpnd -a -x $PFX/bin/lldpnd-ctl
check "man pages installed" test -f $PFX/share/man/man8/lldpnd.8 -a -f $PFX/share/man/man8/lldpnd-ctl.8
check "unit has the install path" grep -q "^ExecStart=$PFX/sbin/lldpnd " $PFX/unit/lldpnd.service
w=$(groff -man -ww -z "$root"/man/*.8 2>&1 | wc -l)
check "man pages render without groff warnings ($w)" test "$w" -eq 0

echo "== systemd-analyze verify"
cp $PFX/unit/lldpnd.service /run/systemd/system/$UNIT.service
# man: references are resolved via man(1); point it at the test prefix
out=$(MANPATH="$PFX/share/man:" systemd-analyze verify /run/systemd/system/$UNIT.service 2>&1)
check "unit verifies cleanly${out:+: $out}" test -z "$out"

echo "== run the unit in a network namespace"
ip netns add $NS; ip netns add $PEER
ip -n $NS link add eth0 address 02:00:00:00:5e:01 type veth peer name eth0 netns $PEER address 02:00:00:00:5e:02
for n in $NS $PEER; do ip -n $n link set lo up; ip -n $n link set eth0 up; done
ip -n $NS addr add 192.0.2.10/24 dev eth0
ip netns exec $PEER "$root/build/lldpnd" -i eth0 -t 2 -n svc-peer -S none >/tmp/lldp-svc-peer.log 2>&1 &
PEERPID=$!
# the shipped unit, plus: run inside the test namespace, our options
cat >>/run/systemd/system/$UNIT.service <<EOF

[Service]
NetworkNamespacePath=/run/netns/$NS
Environment=LLDPND_OPTS="-i eth0 -t 2 -n svc-host"
EOF
systemctl daemon-reload
systemctl start $UNIT
sleep 4
check "service is active" systemctl is-active --quiet $UNIT
pid=$(systemctl show -p MainPID --value $UNIT)
uid=$(awk '/^Uid:/ {print $2}' /proc/"$pid"/status 2>/dev/null)
cap=$(awk '/^CapEff:/ {print $2}' /proc/"$pid"/status 2>/dev/null)
check "runs as a dynamic, unprivileged user (uid $uid)" test -n "$uid" -a "${uid:-0}" -ne 0
check "effective capabilities are CAP_NET_RAW only ($cap)" test "$cap" = 0000000000002000
check "peer learned the service" grep -q "NEIGHBOUR ADD chassis=02:00:00:00:5e:01 port=eth0(st5) name=svc-host" /tmp/lldp-svc-peer.log
check "service learned the peer (journal)" bash -c "journalctl -u $UNIT --no-pager | grep -q 'NEIGHBOUR ADD chassis=02:00:00:00:5e:02'"
check "control socket answers" bash -c "$PFX/bin/lldpnd-ctl -S /run/lldpnd/lldpnd.sock show | grep -q svc-peer"
check "advertises its management address" grep -q "mgmt addr    192.0.2.10" /tmp/lldp-svc-peer.log
sec=$(systemd-analyze security $UNIT 2>/dev/null | tail -1)
echo "   systemd-analyze security: $sec"
systemctl stop $UNIT
sleep 1
check "stop sent a shutdown LLDPDU" grep -q "NEIGHBOUR DELETE chassis=02:00:00:00:5e:01" /tmp/lldp-svc-peer.log
check "service stopped cleanly" bash -c "! systemctl is-failed --quiet $UNIT"

echo "== result: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
