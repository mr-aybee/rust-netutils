# Changelog — certwatch

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the crate uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-11-25

### Added
- `check`: connect to `HOST[:PORT]` targets (arguments, `--file` or stdin), perform a TLS handshake and validate the chain (trust, hostname, validity period) against the platform trust store and/or `--ca-file`.
- The presented chain is recorded even when validation fails, so expired, untrusted, hostname-mismatched and incomplete chains are all inspectable.
- Verdicts `ok`, `warning`, `critical`, `error` with `--warn-days` (default 30) and `--crit-days` (default 7); intermediate certificates count toward expiry.
- `inspect`: local PEM bundles or DER certificates.
- Certificate details: subject, issuer, SANs, validity, days left, key type/size, signature algorithm, SHA-256 fingerprint; flags SHA-1 signatures and RSA keys under 2048 bits.
- `--sni`, `--no-system-roots`, bounded concurrency (`-j`, default 20), per-target `--timeout`, `--json`, `--quiet`, `--verbose`.
- Exit codes: 0 ok, 1 critical/error, 2 usage, 4 warning.
