#!/usr/bin/env bash
# Sustained-load benchmark for meshping (Linux). Requires /usr/bin/time.
# ICMP runs need passwordless sudo (raw socket) or ping_group_range permission; they are skipped otherwise.
# Usage: scripts/bench-meshping.sh [seconds=30] [runs=3]
set -euo pipefail
SECS=${1:-30}
cd "$(dirname "$0")/.."
cargo build --release -q -p meshping
BIN=$PWD/target/release/meshping
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
# 100 distinct loopback addresses (127.0.0.0/8 is all loopback on Linux).
for i in $(seq 1 100); do echo "127.0.0.$i"; done > "$WORK/hosts.txt"
# TCP targets: a closed port on each address -> immediate RST, i.e. a timed reply.
sed 's/$/:9/' "$WORK/hosts.txt" > "$WORK/tcp.txt"

echo "## environment"
echo "cpu: $(lscpu | sed -n 's/^Model name:[[:space:]]*//p') ($(nproc) logical)"
echo "kernel: $(uname -sr)"; rustc --version
echo "binary size: $(stat -c %s "$BIN") bytes"

measure() { # label, cmd...
  local label=$1; shift
  /usr/bin/time -f "%e %U %S %M" -o "$WORK/t" "$@" > /dev/null 2>&1 || true
  read -r wall user sys rss < "$WORK/t"
  awk -v l="$label" -v w="$wall" -v u="$user" -v s="$sys" -v r="$rss" \
    'BEGIN{printf "%s: wall %.1f s, CPU %.2f s (%.2f%% of one core), peak RSS %.1f MiB\n", l, w, u+s, (u+s)*100/w, r/1024}'
}

RUNS=${2:-3}
echo "## 100 hosts at 1 Hz for ${SECS}s, $RUNS runs each (table output, no per-sample I/O)"
for r in $(seq "$RUNS"); do
  measure "tcp  run $r" "$BIN" -f "$WORK/tcp.txt" -m tcp -c "$SECS" -i 1s -r 1h
done
if sudo -n true 2>/dev/null; then
  for r in $(seq "$RUNS"); do
    measure "icmp run $r (raw socket, sudo)" sudo -n "$BIN" -f "$WORK/hosts.txt" -m icmp -c "$SECS" -i 1s -r 1h
  done
fi
echo "## 100 hosts at 10 Hz for ${SECS}s (tcp, JSON per sample)"
measure "tcp 10 Hz" "$BIN" -f "$WORK/tcp.txt" -m tcp -c $((SECS * 10)) -i 100ms -t 100ms -o json -q
