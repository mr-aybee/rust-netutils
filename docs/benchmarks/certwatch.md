# certwatch benchmark report

> These results come from a single host. They are not guarantees.

## Environment

| Item | Value |
|---|---|
| CPU | Intel Xeon E5-2620 v2 @ 2.10 GHz, 16 logical CPUs |
| Memory | 62 GiB |
| OS | Linux 6.8.0-147-generic, x86_64 |
| Rust | rustc 1.100.0 (0ef1bc386 2026-11-09) |
| Build profile | `release`: `lto = "thin"`, `codegen-units = 1`, `opt-level = 3`, `strip = true` |
| Comparison | OpenSSL 3.0.13 |
| Date | 2026-11-25 |
| System state | Shared development host, not isolated |

## Workload

The `examples/tls_server` fixture runs on loopback. It serves a root → leaf chain for `localhost` with an ECDSA P-256 key, TLS 1.3, and one thread per connection. Each target in the list is a separate TCP connection and full handshake. Every check validates against the fixture root (`--ca-file`, `--no-system-roots`).

## Results against the engineering targets

| Target (from project plan) | Measured | Status |
|---|---|---|
| 100 local TLS endpoints within 5 s at concurrency 20 | 0.20–0.22 s (5 runs) | Met |
| Under 40 MiB RSS on that fixture | 5.1–5.4 MiB peak RSS | Met |

## Throughput and memory

| Workload | Runs (wall time) | Checks/s | Peak RSS | CPU |
|---|---|---|---|---|
| 100 endpoints, `-j 20` | 0.21, 0.21, 0.20, 0.22, 0.22 s | 455–500 | 5.1–5.4 MiB | 127–131% |
| 1,000 endpoints, `-j 20` | 1.47, 1.16, 1.01, 0.98, 1.33 s | 680–1,020 | 6.9–7.1 MiB | 124–134% |
| 1,000 endpoints, `-j 100` | 1.39, 1.06, 1.62, 0.94, 1.58 s | 617–1,064 | 9.1–9.6 MiB | 128–142% |

Raising concurrency from 20 to 100 did not raise throughput. On loopback the limits are the single-threaded client's handshake cryptography and the thread-per-connection fixture, not network wait. CPU use above 100% comes from DNS resolution on Tokio's blocking pool. Against real endpoints, where most time is spent waiting on the network, higher concurrency helps.

## Comparison with `openssl s_client`

100 sequential checks of the same endpoint, each with full verification against the fixture root:

| Command | Wall time |
|---|---|
| `openssl s_client -verify_return_error` × 100 (one process each) | 2.35 s |
| `certwatch check -f t100.txt -j 1` (one process, sequential) | 0.37 s |

This is the practical comparison for "check N endpoints": the openssl loop pays process startup and configuration loading 100 times. It is not a comparison of TLS implementation speed.

## Startup and binary size

| Metric | Value |
|---|---|
| `certwatch --version` | mean 3.83 ms, median 3.78 ms (`hyperfine -N`, 200 runs) |
| Binary size (x86_64 Linux, stripped) | 2,784,096 bytes (2.7 MiB) |

## Reproducing

```sh
scripts/bench-certwatch.sh 5     # requires hyperfine, /usr/bin/time, openssl (Linux)
```

## Known limitations

- Loopback only; no real-network latency.
- One fixture key type (ECDSA P-256). RSA-4096 handshakes cost more CPU.
- Linux x86_64 only.

## Optimization opportunities

- A multi-threaded runtime would raise CPU-bound handshake throughput for very large inventories on loopback or LAN.
