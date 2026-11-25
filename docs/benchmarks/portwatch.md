# portwatch benchmark report

> These results come from a single, shared host. They are not guarantees.

## Environment

| Item | Value |
|---|---|
| CPU | Intel Xeon E5-2620 v2 @ 2.10 GHz, 16 logical CPUs |
| Memory | 62 GiB (relevant: kernel TCP hash table size scales with RAM) |
| OS | Linux 6.8.0-147-generic, x86_64 |
| Rust | rustc 1.100.0 (0ef1bc386 2026-11-09) |
| Build profile | `release` (thin LTO, `codegen-units = 1`, stripped) |
| Reference | `ss` (iproute2 6.1.0) |
| Date | 2026-11-25 |

## Workload

`examples/socket_load 5000` holds 5,000 loopback TCP connections, which is 10,000 sockets plus one listener (10,060 TCP sockets on the host in total). Timings use `hyperfine -N`, with 3 warm-up runs and 20 measured runs.

## Correctness

| Check | ss | portwatch |
|---|---|---|
| Sockets on the fixture port | 10,001 | 10,001 |
| TCP / UDP sockets on the host (repeated 3×) | 147 / 12 | 147 / 12 |
| Listening TCP with an owner PID (root) | 27 | 27 |

## Results against the engineering targets

| Target (from project plan) | Measured | Status |
|---|---|---|
| 10,000-socket snapshot in < 500 ms | 251.7 ms ± 86.2 (with PID mapping) | Met |
| Idle watch RSS < 30 MiB at a 1 s interval | 2.8 MiB (idle host), 14.6 MiB (10k sockets) | Met |

## Snapshot timings (10,060 TCP sockets)

| Command | Time |
|---|---|
| `ss -tanp` (with PIDs) | 421.5 ms ± 122.4 |
| `portwatch -t -q` (with PIDs) | 251.7 ms ± 86.2 |
| `portwatch -t --json` | 494.2 ms ± 116.4 |
| `ss -tanp sport = :PORT` | 428.9 ms ± 99.7 |
| `portwatch -t -L PORT -q` | 293.9 ms ± 76.6 |

Pretty-printing 10,000 JSON objects adds about 240 ms.

## Watch mode CPU

| Scenario | CPU (one core = 100%) | Peak RSS |
|---|---|---|
| Idle host (~120 sockets), `-i 1s`, 3 runs | 6.00%, 6.25%, 6.40% | 2.8 MiB |
| 10k sockets held, `-i 1s` | 16.6% | 14.6 MiB |

**Where the time goes.** A `strace -c` of an idle watch shows two netlink `sendto` calls per poll (IPv4 and IPv6) at about 19 ms each. That's kernel time spent walking the TCP hash table, which scales with RAM rather than with socket count. As a reference, 20 runs of `ss -tan` (no PIDs) on the idle host cost 1.30 s of CPU, about 65 ms each. portwatch's idle watch costs about the same as running `ss -tan` once per second.

## Optimization recorded during development

The first version mapped PIDs on every poll by scanning every process's `/proc/<pid>/fd`. Idle watch used **10.0%** of a core and 10.5 MiB. Caching owners by socket inode, and scanning only when unknown inodes appear (unresolvable ones are cached too), brought this to **~6.2%** and **2.8 MiB**. The remainder is the kernel dump.

## Startup and binary size

| Metric | Value |
|---|---|
| Binary (x86_64 Linux, stripped) | 1,023,288 bytes (1.0 MiB) |

## Reproducing

```sh
scripts/bench-portwatch.sh 5000
```

## Known limitations

- Linux only, on one host with a large TCP hash table. Smaller machines will show lower kernel dump costs.
- Windows (IP Helper) and macOS (libproc) have not been benchmarked.
