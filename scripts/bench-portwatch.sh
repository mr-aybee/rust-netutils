#!/usr/bin/env bash
# Benchmark harness for portwatch (Linux). Requires: hyperfine, /usr/bin/time, ss.
# Usage: scripts/bench-portwatch.sh [connections=5000]
set -euo pipefail
N=${1:-5000}
cd "$(dirname "$0")/.."
ulimit -n $((N * 2 + 1000))
cargo build --release -q -p portwatch --bin portwatch --example socket_load
BIN=$PWD/target/release/portwatch
WORK=$(mktemp -d); trap 'kill $LOAD 2>/dev/null || true; rm -rf "$WORK"' EXIT
target/release/examples/socket_load "$N" > "$WORK/ready" & LOAD=$!
until grep -q ready "$WORK/ready" 2>/dev/null; do sleep 0.2; done
PORT=$(awk '{print $NF}' "$WORK/ready")

echo "## environment"
echo "cpu: $(lscpu | sed -n 's/^Model name:[[:space:]]*//p') ($(nproc) logical)"
echo "kernel: $(uname -sr)"; rustc --version; ss --version 2>&1 | head -1
echo "binary size: $(stat -c %s "$BIN") bytes"
echo "fixture: $(cat "$WORK/ready"); total TCP sockets on host: $(ss -tanH | wc -l)"
echo "correctness: ss=$(ss -tanH "( sport = :$PORT or dport = :$PORT )" | wc -l) portwatch=$("$BIN" -t -p "$PORT" -q | wc -l)"

echo "## full TCP snapshot (all sockets on host)"
hyperfine -N --warmup 3 --runs 20 "ss -tanp" "$BIN -t -q" "$BIN -t --json" 2>/dev/null | grep -E "Benchmark|Time" | sed "s#$BIN#portwatch#"
echo "## filtered by port"
hyperfine -N --warmup 3 --runs 20 "ss -tanp sport = :$PORT" "$BIN -t -L $PORT -q" 2>/dev/null | grep -E "Benchmark|Time" | sed "s#$BIN#portwatch#"

echo "## peak RSS"
/usr/bin/time -f "%M" -o "$WORK/rss" "$BIN" -t -q > /dev/null; echo "snapshot: $(awk '{printf "%.1f MiB", $1/1024}' "$WORK/rss")"
/usr/bin/time -f "%M %U %S %e" -o "$WORK/w" timeout -s INT 30 "$BIN" --watch -i 1s -t -q > /dev/null 2>&1 || true
read -r rss u s e < <(tail -n 1 "$WORK/w")
awk -v r="$rss" -v u="$u" -v s="$s" -v e="$e" 'BEGIN{printf "watch (10k sockets held), 1s interval, 30s: peak RSS %.1f MiB, CPU %.1f%% of one core\n", r/1024, (u+s)*100/e}'
echo "## kernel cost reference: 20 consecutive full dumps"
/usr/bin/time -f "ss -tan x20: %U+%S s CPU" bash -c 'for i in $(seq 20); do ss -tanH > /dev/null; done' 2>&1
/usr/bin/time -f "portwatch -t x20: %U+%S s CPU" bash -c "for i in \$(seq 20); do $BIN -t -q > /dev/null; done" 2>&1
