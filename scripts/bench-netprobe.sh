#!/usr/bin/env bash
# End-to-end benchmark harness for netprobe (Linux). Requires: hyperfine, /usr/bin/time.
# Usage: scripts/bench-netprobe.sh [jobs=10000] [concurrency=64] [runs=5]
set -euo pipefail
JOBS=${1:-10000}; CONC=${2:-64}; RUNS=${3:-5}
cd "$(dirname "$0")/.."
cargo build --release -q -p netprobe --bin netprobe --example sink
BIN=target/release/netprobe
SINK=target/release/examples/sink
PORT=17000
WORK=$(mktemp -d); trap 'kill $SINK_PID 2>/dev/null || true; rm -rf "$WORK"' EXIT
$SINK 127.0.0.1:$PORT 2>/dev/null & SINK_PID=$!
sleep 0.3
for _ in $(seq "$JOBS"); do echo "tcp 127.0.0.1:$PORT"; done > "$WORK/jobs.txt"

echo "## environment"
echo "cpu: $(lscpu | sed -n 's/^Model name:[[:space:]]*//p') ($(nproc) logical)"
echo "kernel: $(uname -sr)"; rustc --version
echo "binary size: $(stat -c %s $BIN) bytes"

echo "## startup (--version)"
hyperfine -N --warmup 20 --runs 200 "$BIN --version" --export-json "$WORK/startup.json" >/dev/null
python3 -c "import json,sys;r=json.load(open(sys.argv[1]))['results'][0];print(f\"mean {r['mean']*1e3:.3f} ms, median {r['median']*1e3:.3f} ms, stddev {r['stddev']*1e3:.3f} ms\")" "$WORK/startup.json"

echo "## loopback tcp batch: $JOBS probes, concurrency $CONC, $RUNS runs"
for i in $(seq "$RUNS"); do
  /usr/bin/time -f "%e %M %P" -o "$WORK/time.$i" $BIN batch "$WORK/jobs.txt" -j "$CONC" -q >/dev/null
  read -r secs rss cpu < "$WORK/time.$i"
  awk -v s="$secs" -v r="$rss" -v c="$cpu" -v n="$JOBS" -v i="$i" 'BEGIN{printf "run %d: %.2f s, %.0f probes/s, peak RSS %.1f MiB, CPU %s\n", i, s, n/s, r/1024, c}'
done

echo "## single probe latency distribution (loopback, 1000 sequential, 1ms interval)"
$BIN tcp 127.0.0.1:$PORT -c 1000 -i 1ms -q | tail -1
