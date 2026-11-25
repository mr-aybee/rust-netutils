#!/usr/bin/env bash
# End-to-end benchmark harness for dnswatch (Linux). Requires: hyperfine, /usr/bin/time, dig.
# Usage: scripts/bench-dnswatch.sh [runs=5]
set -euo pipefail
RUNS=${1:-5}
cd "$(dirname "$0")/.."
cargo build --release -q -p dnswatch --bin dnswatch --example dns_stub
BIN=$PWD/target/release/dnswatch
PORT=15353
WORK=$(mktemp -d); trap 'kill $STUB 2>/dev/null || true; rm -rf "$WORK"' EXIT
target/release/examples/dns_stub 127.0.0.1:$PORT 2>/dev/null & STUB=$!
sleep 0.3
NAMES=$(for i in $(seq 0 999); do printf "n%03d.test " "$i"; done)
for i in $(seq 0 999); do printf "n%03d.test A\n" "$i"; done > "$WORK/dig.txt"

echo "## environment"
echo "cpu: $(lscpu | sed -n 's/^Model name:[[:space:]]*//p') ($(nproc) logical)"
echo "kernel: $(uname -sr)"; rustc --version; dig -v 2>&1 | head -1
echo "binary size: $(stat -c %s "$BIN") bytes"

echo "## startup"
hyperfine -N --warmup 20 --runs 200 "$BIN --version" 2>/dev/null | grep -E "Time"

echo "## 1,000 A queries against local stub"
for c in 1 64; do
  for i in $(seq "$RUNS"); do
    # shellcheck disable=SC2086
    /usr/bin/time -f "%e %M" -o "$WORK/t" "$BIN" compare $NAMES -s 127.0.0.1:$PORT -j $c > /dev/null
    read -r secs rss < "$WORK/t"
    awk -v s="$secs" -v r="$rss" -v c="$c" -v i="$i" 'BEGIN{printf "dnswatch -j %d run %d: %.3f s, %.0f queries/s, peak RSS %.1f MiB\n", c, i, s, 1000/s, r/1024}'
  done
done
for i in $(seq "$RUNS"); do
  s=$(date +%s.%N); dig @127.0.0.1 -p $PORT -f "$WORK/dig.txt" +short +tries=1 > /dev/null; e=$(date +%s.%N)
  echo "dig -f (sequential batch) run $i: $(echo "$e - $s" | bc) s"
done
