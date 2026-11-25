# Changelog — meshping

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the crate uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-11-25

### Added
- Continuous probing of many hosts with one task per host, start times staggered across the interval.
- Modes: `icmp` (unprivileged datagram socket, raw socket, or the Windows IP Helper API), `tcp` (connect timing; a refusal counts as a reply), and `auto` (ICMP if permitted, else TCP, labelled per host).
- One shared ICMP socket per address family with a reply dispatcher, so the per-packet cost does not grow with the number of hosts.
- Rolling-window statistics (`--window`): loss, last, min, avg, p95, max, jitter; lifetime sent and loss.
- Output: periodic table (`--report`), CSV or JSON Lines per probe; final summary.
- `--count`, `--interval`, `--timeout` (≤ interval), host files; exit 1 if any host never replied.
