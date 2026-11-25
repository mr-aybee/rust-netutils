# certwatch

TLS certificate inspection and expiry monitoring in one small binary. Check many endpoints concurrently, see exactly *why* a certificate fails (expired, untrusted, hostname mismatch, incomplete chain), and fail CI before a certificate expires.

```console
$ certwatch check github.com example.com expired.badssl.com
OK       example.com:443  expires in 89 day(s) (2027-02-22)  subject: CN=example.com  TLS 1.3
OK       github.com:443  expires in 63 day(s) (2027-01-27)  subject: CN=github.com  TLS 1.3
CRITICAL expired.badssl.com:443  expired 4245 day(s) ago (2015-04-12)  subject: OU=Domain Control Validated, OU=PositiveSSL Wildcard, CN=*.badssl.com  TLS 1.2
         ! invalid peer certificate: certificate expired: ...
--- 3 checked: 2 ok, 0 warning, 1 critical, 0 error
```

## Install

Download a binary from [Releases](https://github.com/mr-aybee/rust-netutils/releases) (see `SHA256SUMS`), or:

```sh
cargo install --git https://github.com/mr-aybee/rust-netutils certwatch
```

## Usage

| Command | Purpose |
|---|---|
| `certwatch check HOST[:PORT]... [-f FILE]` | Validate remote certificates |
| `certwatch inspect FILE...` | Inspect local PEM/DER certificates |

Exit codes: `0` ok, `1` critical or error, `2` usage error, `4` warning.

Full documentation: [docs/utilities/certwatch.md](../../docs/utilities/certwatch.md). Benchmarks: [docs/benchmarks/certwatch.md](../../docs/benchmarks/certwatch.md).

## License

MIT OR Apache-2.0.
