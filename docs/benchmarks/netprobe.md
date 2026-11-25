# netprobe benchmark report

> These results come from a single host. They are not guarantees, and other hardware, kernels or network conditions will give different numbers.

## Environment

| Item | Value |
|---|---|
| CPU | Intel Xeon E5-2620 v2 @ 2.10 GHz, 16 logical CPUs, 1 thread per core |
| Memory | 62 GiB |
| OS | Linux 6.8.0-147-generic, x86_64 |
| Rust | rustc 1.100.0 (0ef1bc386 2026-11-09) |
| Build profile | `release`: `lto = "thin"`, `codegen-units = 1`, `opt-level = 3`, `strip = true` |
| Date | 2026-11-25 |
| System state | Shared development host, not isolated (hyperfine reported statistical outliers) |

## Results against the engineering targets

| Target (from project plan) | Measured | Status |
|---|---|---|
| ≥ 1,000 loopback TCP probes/s at concurrency 64 | 4,386 – 6,410 probes/s (median 5,051), 5 runs × 10,000 probes | Met |
| p95 scheduling overhead < 5 ms excluding network time | p95 full probe latency 0.50 ms on loopback (1,000 sequential probes, includes resolve + connect + close) | Met (upper bound) |

## 1. Throughput: loopback TCP batch

10,000 `tcp 127.0.0.1:17000` jobs, `-j 64`, against `examples/sink` (accepts and immediately closes).

| Run | Wall time | Probes/s | Peak RSS | CPU |
|---|---|---|---|---|
| 1 | 2.03 s | 4,926 | 17.0 MiB | 99% |
| 2 | 1.56 s | 6,410 | 17.0 MiB | 99% |
| 3 | 1.98 s | 5,051 | 17.1 MiB | 99% |
| 4 | 1.81 s | 5,525 | 17.0 MiB | 99% |
| 5 | 2.28 s | 4,386 | 17.0 MiB | 99% |

CPU is 99% of one core because the runtime is single-threaded; the sink and the kernel's loopback path account for part of that time. The spread between runs reflects the shared host.

### Optimization recorded during development

The first version of batch mode spawned a task for every job up front and limited concurrency with a semaphore. With 10,000 jobs, peak RSS was **130.6 MiB**. Changing it to keep only `concurrency` tasks alive, spawning the next job as each one finishes, brought peak RSS down to **16.2 MiB** with the same throughput. The remaining memory grows with the number of retained results, which are needed for the final summary and JSON output.

## 2. Latency: sequential loopback probes

`netprobe tcp 127.0.0.1:17000 -c 1000 -i 1ms -q`

| min | avg | p50 | p95 | max | stddev |
|---|---|---|---|---|---|
| 0.29 ms | 0.38 ms | 0.36 ms | 0.50 ms | 0.67 ms | 0.06 ms |

## 3. Startup and binary size

| Metric | Value | Method |
|---|---|---|
| `netprobe --version` | mean 4.615 ms, median 4.562 ms, σ 0.254 ms | `hyperfine -N --warmup 20 --runs 200` |
| Binary size (x86_64 Linux, stripped) | 4,134,000 bytes (3.9 MiB) | `stat` |

## 4. Comparison with `nc`

Single connect check per process invocation, same loopback listener, `hyperfine -N --warmup 20 --runs 300`:

| Command | Mean ± σ |
|---|---|
| `nc -z 127.0.0.1 17001` (OpenBSD netcat 1.226) | 4.9 ms ± 0.4 ms |
| `netprobe tcp 127.0.0.1:17001 -q` | 5.2 ms ± 0.4 ms |

The difference is within about one standard deviation. Per-invocation cost is dominated by process startup.

## 5. Microbenchmarks (Criterion)

`cargo bench -p netprobe --bench core -- --warm-up-time 1 --measurement-time 3`

| Benchmark | Time (median estimate) |
|---|---|
| `parse_endpoint/hostname` | 234 ns |
| `parse_endpoint/ipv6` | 234 ns |
| `parse_url` | 490 ns |
| `http/parse_status_line` | 109 ns |
| `icmp/build_echo` | 47 ns |
| `stats/summarize_10k` (10,000 samples) | 370 µs |

## Reproducing

```sh
scripts/bench-netprobe.sh 10000 64 5     # requires hyperfine and /usr/bin/time (Linux)
cargo bench -p netprobe --bench core
```

## Known limitations of this report

- Linux x86_64 only; Windows and macOS have not been benchmarked.
- Loopback only; real-network results are dominated by RTT and are not representative of tool overhead.
- DNS, HTTP, UDP and ICMP throughput have not been benchmarked yet.

## Optimization opportunities

- A multi-threaded runtime for very large batches (the current ceiling is one core).
- Optionally stream results (JSON Lines) instead of keeping them all in memory, for very large batches.
