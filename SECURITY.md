# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Report them privately via
GitHub's [private vulnerability reporting](https://github.com/mr-aybee/rust-netutils/security/advisories/new).

Include the affected utility and version, platform, reproduction steps and impact.
You should receive an acknowledgement within 7 days.

## Supported versions

Only the latest release of each utility receives security fixes.

## Scope and intended use

These utilities are for diagnostics and administration of networks you own or are
authorized to test. Security-relevant defaults:

- TLS certificates and hostnames are verified by default. `--insecure` must be given
  explicitly and prints a warning.
- No shell commands are executed and no credentials are stored.
- Inputs (targets, URLs, record types, batch files) are validated; batch files are
  limited to 100,000 jobs and 4 KiB per line; HTTP response heads to 16 KiB.
- Dependencies are audited in CI with `cargo-deny` (RustSec advisories and licenses).
