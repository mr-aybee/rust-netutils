# Changelog — netprobe

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the crate uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-11-25

### Added
- `tcp`: resolve + connect probe with DNS/connect timing; tries each resolved address in order.
- `dns`: A, AAAA, CNAME, MX, TXT, NS, SOA, PTR, SRV and CAA queries via the system resolver or `--server`; cache disabled so every attempt is a real query; NXDOMAIN is distinguished from empty answers.
- `http`: HTTP/1.1 GET/HEAD over plain TCP or TLS (rustls), with DNS/connect/TLS/first-byte timings, `--expect` status codes, `--ca-file` and an explicit, warned `--insecure`.
- `udp`: request/response probe with text (escaped) or hex payloads; silence is reported as *inconclusive* (exit 3), ICMP port unreachable as failure.
- `icmp`: echo probe using unprivileged datagram ICMP sockets where permitted, falling back to raw sockets when privileged; clear error otherwise.
- `batch`: run a target file (or stdin) with bounded concurrency; results in input order.
- `--count`, `--interval`, `--timeout`; latency summary (min/avg/p50/p95/max/stddev); `--json`, `--quiet`, `--verbose`; graceful Ctrl+C with partial summary.
