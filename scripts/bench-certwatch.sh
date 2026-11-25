#!/usr/bin/env bash
# End-to-end benchmark harness for certwatch (Linux). Requires: hyperfine, /usr/bin/time, openssl.
# Usage: scripts/bench-certwatch.sh [runs=5]
set -euo pipefail
RUNS=${1:-5}
cd "$(dirname "$0")/.."
cargo build --release -q -p certwatch --bin certwatch --example tls_server
BIN=target/release/certwatch
PORT=17443
WORK=$(mktemp -d); trap 'kill $SRV 2>/dev/null || true; rm -rf "$WORK"' EXIT
target/release/examples/tls_server 127.0.0.1:$PORT "$WORK" 2>/dev/null & SRV=$!
sleep 0.5
for n in 100 1000; do for _ in $(seq $n); do echo "localhost:$PORT"; done > "$WORK/t$n.txt"; done
CA=(--ca-file "$WORK/root.pem" --no-system-roots)

echo "## environment"
echo "cpu: $(lscpu | sed -n 's/^Model name:[[:space:]]*//p') ($(nproc) logical)"
echo "kernel: $(uname -sr)"; rustc --version; openssl version
echo "binary size: $(stat -c %s $BIN) bytes"

echo "## startup (--version)"
hyperfine -N --warmup 20 --runs 200 "$BIN --version" --export-json "$WORK/s.json" >/dev/null 2>&1
python3 -c "import json,sys;r=json.load(open(sys.argv[1]))['results'][0];print(f\"mean {r['mean']*1e3:.3f} ms, median {r['median']*1e3:.3f} ms\")" "$WORK/s.json"

for spec in "100 20" "1000 20" "1000 100"; do
  set -- $spec; n=$1; c=$2
  echo "## $n endpoints, concurrency $c, $RUNS runs"
  for i in $(seq "$RUNS"); do
    /usr/bin/time -f "%e %M %P" -o "$WORK/time" $BIN check -f "$WORK/t$n.txt" -j $c "${CA[@]}" -q >/dev/null
    read -r secs rss cpu < "$WORK/time"
    awk -v s="$secs" -v r="$rss" -v c="$cpu" -v n="$n" -v i="$i" 'BEGIN{printf "run %d: %.2f s, %.0f checks/s, peak RSS %.1f MiB, CPU %s\n", i, s, n/s, r/1024, c}'
  done
done

echo "## comparison: 100 sequential checks"
s=$(date +%s.%N); for _ in $(seq 100); do echo | openssl s_client -connect 127.0.0.1:$PORT -servername localhost -CAfile "$WORK/root.pem" -verify_return_error >/dev/null 2>&1 || echo "openssl check failed" >&2; done; e=$(date +%s.%N)
echo "openssl s_client x100: $(echo "$e - $s" | bc) s"
s=$(date +%s.%N); $BIN check -f "$WORK/t100.txt" -j 1 "${CA[@]}" -q >/dev/null; e=$(date +%s.%N)
echo "certwatch -j 1 (100 targets): $(echo "$e - $s" | bc) s"
