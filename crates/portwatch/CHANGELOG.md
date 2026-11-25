# Changelog — portwatch

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the crate uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-11-25

### Added
- List TCP and UDP sockets (IPv4/IPv6) with local/remote endpoints, TCP state, owning PIDs and, on Linux, process names.
- Filters: `--port` (local or remote), `--local-port`, `--pid`, `--process`, `--address`, `--state`, `--listening`, `-t/-u`, `-4/-6`.
- Exit status 1 when nothing matches (grep-like), so `portwatch -p 8080` can be used as a check.
- `--watch`: report sockets opening, closing and changing state, as text or JSON Lines.
- Linux: socket owners are cached by inode, and `/proc` is rescanned only when unknown sockets appear.
- `--json` output.
