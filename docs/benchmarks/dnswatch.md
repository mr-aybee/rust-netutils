# dnswatch benchmark report

> These results come from a single host. They are not guarantees.

## Environment

| Item | Value |
|---|---|
| CPU | Intel Xeon E5-2620 v2 @ 2.10 GHz, 16 logical CPUs |
| OS | Linux 6.8.0-147-generic, x86_64 |
| Rust | rustc 1.100.0 (0ef1bc386 2026-11-09) |
| Build profile | `release` (thin LTO, `codegen-units = 1`, stripped) |
| Reference | `dig` 9.18.39 |
| Date | 2026-11-25 |

## Workload

1,000 distinct names (`n000.test` … `n999.test`), A queries, against `examples/dns_stub` on loopback (UDP; it answers `A 192.0.2.1` immediately). Measured with `dnswatch compare <1,000 names> -s 127.0.0.1:15353`, 5 runs each.

## Results against the engineering targets

| Target (from project plan) | Measured | Status |
|---|---|---|
| 1,000 queries in < 10 s against a local resolver at concurrency 64 | 0.12–0.13 s | Met |
| < 40 MiB RSS | 5.8–5.9 MiB | Met |

## Detail

| Tool | Runs (s) | Queries/s | Peak RSS |
|---|---|---|---|
| dnswatch `-j 64` | 0.12, 0.13, 0.13, 0.13, 0.12 | 7,692–8,333 | 5.8–5.9 MiB |
| dnswatch `-j 1` | 0.44, 0.50, 0.28, 0.49, 0.24 | 2,000–4,167 | 4.9–5.1 MiB |
| `dig -f` (sequential batch file) | 0.27, 0.43, 0.34, 0.31, 0.27 | 2,300–3,700 | — |

Sequentially, dnswatch and `dig` are comparable. The concurrency is what makes large inventories cheap to poll.

## Startup and binary size

| Metric | Value |
|---|---|
| `dnswatch --version` | 3.7 ms ± 1.1 |
| Binary (x86_64 Linux, stripped) | 2,548,688 bytes (2.4 MiB) |

## Reproducing

```sh
scripts/bench-dnswatch.sh 5     # requires hyperfine, /usr/bin/time, dig
```

## Known limitations

- The loopback stub answers instantly. With real recursive resolvers, time is dominated by upstream latency and caching.
- Long-running `watch` (days) memory behaviour has not been measured. By design it is constant per combination.
