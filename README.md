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

More utilities (TLS certificate monitoring, multi-host latency, socket inspection and others) will be added here only once they are implemented and tested.

## Key features

- **One binary per tool**, no runtime dependencies; about 4 MiB for netprobe.
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
```

## Use cases

- **CI/CD smoke tests**: check that a deployment answers on the right port with the right status code. The exit code fails the pipeline.
- **Firewall and security-group debugging**: distinguish *refused*, *timed out* and *unreachable*.
- **DNS migrations**: query the old and new resolvers directly and compare the answers.
- **TLS problems**: certificate failures are reported with the exact reason (expired, wrong host, untrusted).

## Performance

Measured on an Intel Xeon E5-2620 v2 running Linux (full methodology in [docs/benchmarks/netprobe.md](docs/benchmarks/netprobe.md)):

| Metric | Result |
|---|---|
| Loopback TCP probes/s (concurrency 64, 10,000 jobs) | 4,386 – 6,410 (median 5,051) |
| Peak RSS for that batch | 17 MiB |
| Startup (`--version`) | 4.6 ms |
| Binary size | 3.9 MiB |

## Architecture

The repository is a Cargo workspace: each utility is an independent crate with its own version and release, and a small private `net-common` crate holds shared conventions. See [docs/architecture/overview.md](docs/architecture/overview.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Please run `cargo fmt`, `cargo clippy -- -D warnings` and `cargo test` before opening a pull request.

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md). These tools are intended for networks you own or are authorized to test.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
