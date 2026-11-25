# Changelog — dnswatch

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the crate uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-11-25

### Added
- `watch`: poll names × record types × resolvers and report `initial`, `changed` (with added/removed records), `error` and `recovered` events; `--until-change`, `--quiet`, JSON Lines output.
- `wait`: block until every resolver returns exactly the `--expect`ed values (propagation check), with `--max-wait`.
- `compare`: one-shot comparison across resolvers; exit 1 if answers differ, 3 if only errors prevented a verdict.
- Canonical, TTL-independent record sets; NXDOMAIN, NODATA and records are distinct states; transient failures are never reported as changes.
- Record types A, AAAA, CNAME, MX, TXT, NS, SOA, PTR, SRV, CAA; system resolver or explicit `--server IP[:PORT]` (repeatable); resolver cache disabled.
