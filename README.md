<div align="center">

# rust-netutils

**Small, fast, cross-platform network utilities written in Rust.**

[![CI](https://github.com/mr-aybee/rust-netutils/actions/workflows/ci.yml/badge.svg)](https://github.com/mr-aybee/rust-netutils/actions/workflows/ci.yml)
![MSRV](https://img.shields.io/badge/MSRV-1.88-blue)
![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)

</div>

rust-netutils is a collection of single-purpose command-line tools for developers, system administrators, DevOps and network engineers. Each tool is one static binary with no runtime to install. Each has predictable resource use, human and JSON output, and exit codes you can rely on in scripts and CI.

## Utilities

| Utility | Status | Purpose |
|---|---|---|
| [**netprobe**](docs/utilities/netprobe.md) | ✅ 0.2.0 | TCP, DNS, HTTP(S), UDP and ICMP diagnostics with timing breakdowns |
| [**certwatch**](docs/utilities/certwatch.md) | ✅ 0.1.0 | TLS certificate inspection and expiry monitoring for many endpoints |
| [**dnswatch**](docs/utilities/dnswatch.md) | ✅ 0.1.0 | DNS change monitoring, propagation waiting and resolver comparison |
| [**meshping**](docs/utilities/meshping.md) | ✅ 0.1.0 | Continuous latency and loss monitoring for many hosts (ICMP or TCP) |
| [**portwatch**](docs/utilities/portwatch.md) | ✅ 0.1.0 | Sockets, listening ports and owning processes, with change watching |

More utilities (port forwarding, throughput testing, subnet discovery) will be added here only once they are implemented and tested.

## Key features

- **One binary per tool**, no runtime dependencies: about 4 MiB for netprobe and 2.7 MiB for certwatch.
- **Honest results**: three outcomes (`ok`, `failed`, `inconclusive`). For example, UDP silence is never reported as "closed".
- **Secure defaults**: TLS verification is always on; `--insecure` is explicit and prints a warning; inputs are validated and bounded.
- **Automation-friendly**: `--json`, stable exit codes, diagnostics on stderr.
- **Bounded resources**: per-attempt deadlines, concurrency limits, streaming batch execution.

## Supported platforms

| OS | x86_64 | ARM64 |
|---|---|---|
| Linux | ✅ tested in CI | ✅ tested in CI |
| Windows | ✅ tested in CI | ✅ tested in CI |
| macOS | 🔨 built in CI (cross-compiled, not tested) | ✅ tested in CI |

Platform-specific behaviour (for example, ICMP permissions) is documented per utility.

## Installation

Prebuilt binaries with SHA-256 checksums are attached to each [release](https://github.com/mr-aybee/rust-netutils/releases).

From source (Rust 1.88 or newer):

```sh
cargo install --git https://github.com/mr-aybee/rust-netutils netprobe
```

## Quick start

```sh
netprobe tcp example.com:443                        # can I connect?
netprobe http https://example.com -v                # where does the time go?
netprobe dns example.com -T MX -s 1.1.1.1           # what does this resolver say?
netprobe tcp db.internal:5432 -c 10 -i 200ms -q     # latency percentiles
netprobe batch smoke.txt -j 32 --json > report.json # many checks at once
certwatch check -f endpoints.txt --crit-days 14     # fail CI before certificates expire
certwatch check vault.internal:8200 --ca-file root.pem -v   # inspect a private-PKI chain
```

## Use cases

- **CI/CD smoke tests**: check that a deployment answers on the right port with the right status code. The exit code fails the pipeline.
- **Port conflicts and unexpected listeners**: `portwatch -l` shows what is listening and who owns it; `--watch` catches listeners that come and go.
- **Firewall and security-group debugging**: distinguish *refused*, *timed out* and *unreachable*.
- **DNS migrations**: compare old and new resolvers with `dnswatch compare`, and block a cut-over script until a change has propagated with `dnswatch wait`.
- **Certificate hygiene**: find certificates that are expiring, expired, untrusted, hostname-mismatched or served with an incomplete chain across an inventory of endpoints, before users notice.

## Performance

Measured on an Intel Xeon E5-2620 v2 running Linux. Full methodology: [netprobe](docs/benchmarks/netprobe.md), [certwatch](docs/benchmarks/certwatch.md), [dnswatch](docs/benchmarks/dnswatch.md), [meshping](docs/benchmarks/meshping.md), [portwatch](docs/benchmarks/portwatch.md).

| Utility | Workload | Result | Peak RSS | Startup | Binary |
|---|---|---|---|---|---|
| netprobe | 10,000 loopback TCP probes, concurrency 64 | 4,386–6,410 probes/s | 17 MiB | 4.6 ms | 3.9 MiB |
| certwatch | 100 loopback TLS endpoints, concurrency 20 | 0.20–0.22 s total | 5.4 MiB | 3.8 ms | 2.7 MiB |
| dnswatch | 1,000 DNS queries to a local stub, concurrency 64 | 0.12–0.13 s total | 5.9 MiB | 3.7 ms | 2.4 MiB |
| meshping | 100 hosts at 1 Hz (ICMP), sustained | 2.5% of one core (median) | 6.8 MiB | — | 1.1 MiB |
| portwatch | 10,000-socket snapshot with PIDs | 252 ms (`ss -tanp`: 422 ms) | 7.4 MiB | — | 1.0 MiB |

## Architecture

The repository is a Cargo workspace: each utility is an independent crate with its own version and release, and a small private `net-common` crate holds shared conventions. See [docs/architecture/overview.md](docs/architecture/overview.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Please run `cargo fmt`, `cargo clippy -- -D warnings` and `cargo test` before opening a pull request.

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md). These tools are intended for networks you own or are authorized to test.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
