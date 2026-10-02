#!/usr/bin/env bash
# idle_check.sh - show that an idle lldpnd sleeps in epoll_wait (no busy-wait):
# count its wakeups (voluntary context switches) and CPU time over a window.
# Runs in a private network namespace. Root required.
#   scripts/idle_check.sh [tx-interval=5] [window-seconds=20]
set -eu
here=$(cd "$(dirname "$0")" && pwd)
BIN=${BIN:-$here/../build/lldpnd}
TX=${1:-5}
WIN=${2:-20}

exec unshare --net bash -s "$BIN" "$TX" "$WIN" <<'EOF'
BIN=$1 TX=$2 WIN=$3
ip link add idA type veth peer name idB
ip link set idA up; ip link set idB up
"$BIN" -i idA -t "$TX" >/dev/null &
P=$!
sleep 0.5
ctx() { awk '/^voluntary_ctxt_switches/ {print $2}' /proc/$P/status; }
cpu() { awk '{print $14 + $15}' /proc/$P/stat; }   # utime + stime, clock ticks
c0=$(ctx); t0=$(cpu)
sleep "$WIN"
c1=$(ctx); t1=$(cpu)
echo "idle window ${WIN}s, tx interval ${TX}s (expected ~$((WIN / TX)) tx wakeups)"
echo "  wakeups (voluntary context switches): $((c1 - c0))"
echo "  CPU time used: $(( (t1 - t0) * 1000 / $(getconf CLK_TCK) )) ms"
echo "  kernel wait channel: $(cat /proc/$P/wchan)"
kill -INT $P; wait $P; echo "  exit status after SIGINT: $?"
EOF
