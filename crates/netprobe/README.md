# netprobe

Multi-protocol network diagnostics in a single small binary: **TCP connect, DNS, HTTP(S), UDP and ICMP** probes, each with per-phase timing, latency percentiles, JSON output and exit codes suited to CI.

```console
$ netprobe http https://example.com -v
http https://example.com/ seq=1 ok 209.93 ms addr=172.66.147.243:443 HTTP 200 OK tls=1.3 [dns=80.84ms connect=20.15ms tls=38.20ms first_byte=70.48ms]

$ netprobe tcp db.internal:5432 -c 5 -i 500ms -q
--- db.internal:5432: 5 sent, 5 ok, 0 failed, 0 inconclusive, 0.0% failed
latency min/avg/p50/p95/max/stddev = 0.41/0.52/0.49/0.70/0.70/0.10 ms
```

## Install

Download a binary for your platform from [Releases](https://github.com/mr-aybee/rust-netutils/releases) (see `SHA256SUMS`), or build from source:

```sh
cargo install --git https://github.com/mr-aybee/rust-netutils netprobe
```

## Commands

| Command | Purpose |
|---|---|
| `netprobe tcp HOST:PORT` | Resolve and connect |
| `netprobe dns NAME [-T TYPE] [-s SERVER]` | Query records, measure resolver latency |
| `netprobe http URL [--expect CODES]` | HTTP(S) status and DNS/connect/TLS/first-byte timings |
| `netprobe udp HOST:PORT [-p TEXT]` | Datagram request/response (silence is *inconclusive*) |
| `netprobe icmp HOST` | Ping (unprivileged where the OS allows) |
| `netprobe batch FILE` | Many probes from a file with bounded concurrency |

Exit codes: `0` ok, `1` failure, `2` usage error, `3` inconclusive.

Full documentation: [docs/utilities/netprobe.md](../../docs/utilities/netprobe.md). Benchmarks: [docs/benchmarks/netprobe.md](../../docs/benchmarks/netprobe.md).

## License

MIT OR Apache-2.0.
