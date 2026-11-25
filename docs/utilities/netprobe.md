# netprobe

Multi-protocol network diagnostics in one small binary: TCP connect, DNS, HTTP(S), UDP request/response and ICMP echo, each with per-phase timing, latency statistics, JSON output and CI-friendly exit codes.

<details>
<summary><strong>Contents</strong></summary>

- [Commands](#commands)
- [Common options](#common-options)
- [Exit codes](#exit-codes)
- [Output](#output)
- [Batch files](#batch-files)
- [Platform behavior and permissions](#platform-behavior-and-permissions)
- [Limitations](#limitations)
- [Implementation notes](#implementation-notes)

</details>

## Commands

### `tcp HOST:PORT`

Resolves the host with the system resolver, then connects to each address in order until one succeeds. Reports DNS and connect time.

```console
$ netprobe tcp github.com:443 -v
tcp github.com:443 seq=1 ok 86.35 ms addr=140.82.121.4:443 [dns=64.21ms connect=22.04ms]
$ netprobe tcp 127.0.0.1:1
tcp 127.0.0.1:1 seq=1 FAILED: connection refused
```

IPv6 literals use brackets: `netprobe tcp [2001:db8::1]:22`.

### `dns NAME [-T TYPE] [-s SERVER]`

Queries one record type (default `A`). Supported: `A AAAA CNAME MX TXT NS SOA PTR SRV CAA`. `--server` takes an IP address with optional port (`1.1.1.1`, `[2606:4700:4700::1111]:53`). The resolver cache is disabled, so with `--count` every attempt is a real query. Answers are sorted so that output is stable; `-v` prints them.

```console
$ netprobe dns example.com -T AAAA -v
dns example.com AAAA seq=1 ok 22.91 ms 2 answer(s)
    AAAA 9 2606:4700:10::6814:179a
    AAAA 9 2606:4700:10::ac42:93f3 [dns=22.91ms]
$ netprobe dns nonexistent-zzzq.invalid
dns nonexistent-zzzq.invalid A seq=1 FAILED: NXDOMAIN (name does not exist)
```

An empty answer for an existing name is reported as `no records of the requested type`, distinct from NXDOMAIN.

### `http URL`

Sends one HTTP/1.1 request (`GET`, or `HEAD` with `--head`) and reads the response head only. Redirects are reported (`location=...`) but not followed.

| Option | Meaning |
|---|---|
| `--expect 200,204` | Accepted status codes. Default: any 2xx or 3xx. |
| `--ca-file ca.pem` | Additional trusted CA certificates (PEM), on top of the platform trust store. |
| `--insecure` | Skip certificate chain and hostname verification. Prints a warning. Handshake signatures are still checked. |

```console
$ netprobe http https://example.com -v
http https://example.com/ seq=1 ok 209.93 ms addr=172.66.147.243:443 HTTP 200 OK tls=1.3 [dns=80.84ms connect=20.15ms tls=38.20ms first_byte=70.48ms]
$ netprobe http https://expired.badssl.com
http https://expired.badssl.com/ seq=1 FAILED addr=104.154.89.105:443: TLS handshake failed: invalid peer certificate: certificate expired: ...
```

### `udp HOST:PORT [-p TEXT | --payload-hex HEX]`

Sends one datagram and waits up to `--timeout` for a reply.

| Observation | Result | Exit |
|---|---|---|
| Reply received | `ok`, with size and printable preview | 0 |
| ICMP port unreachable reported by the OS | `FAILED: port unreachable (ICMP)` | 1 |
| Nothing before the deadline | `INCONCLUSIVE` | 3 |

Silence does **not** mean the port is closed: the service may ignore the payload, or a firewall may drop packets. Text payloads accept `\n \r \t \0 \\ \xHH`.

```console
$ netprobe udp 1.1.1.1:53 --payload-hex "abcd 0100 0001 0000 0000 0000 07 6578616d706c65 03 636f6d 00 0001 0001"
udp 1.1.1.1:53 seq=1 ok 17.80 ms addr=1.1.1.1:53 61 byte reply ".............example.com........…"
```

### `icmp HOST`

ICMP echo (ping) over IPv4 or IPv6. See [permissions](#platform-behavior-and-permissions).

```console
$ netprobe icmp 1.1.1.1 -c 3 -i 200ms
icmp 1.1.1.1 seq=1 ok 21.04 ms addr=1.1.1.1 40 bytes
...
--- 1.1.1.1: 3 sent, 3 ok, 0 failed, 0 inconclusive, 0.0% failed
latency min/avg/p50/p95/max/stddev = 16.45/18.34/17.54/21.04/21.04/1.95 ms
```

### `batch FILE`

Runs every job in `FILE` (`-` for stdin) with at most `-j/--concurrency` jobs in flight (default 16, maximum 1024). See [batch files](#batch-files).

## Common options

| Option | Default | Meaning |
|---|---|---|
| `-t, --timeout` | `3s` | Deadline for each attempt (`250ms`, `3s`, `1.5s`, `2m`). |
| `-c, --count` | `1` | Attempts per target. |
| `-i, --interval` | `1s` | Pause between attempts. |
| `--json` | off | Print one JSON document on stdout. |
| `-q, --quiet` | off | Print only the summary. |
| `-v, --verbose` | off | Print the timing breakdown (and DNS answers). |

When `--count` is greater than 1, a summary line follows the attempts. Latency statistics cover successful attempts only. Ctrl+C stops the run and prints the summary for the attempts that completed.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Every attempt succeeded. |
| 1 | At least one attempt failed, or a probe could not be set up (for example, ICMP not permitted). |
| 2 | Invalid usage: bad arguments, target, URL or batch file. |
| 3 | No failures, but at least one result was inconclusive (UDP silence). |

Diagnostics go to stderr; results go to stdout.

## Output

`--json` prints one document after the run:

```json
{
  "version": 1,
  "results": [
    {
      "probe": "tcp",
      "target": "127.0.0.1:8080",
      "seq": 1,
      "outcome": "ok",
      "elapsed_ms": 0.31,
      "address": "127.0.0.1:8080",
      "timings": { "dns_ms": 0.02, "connect_ms": 0.28 }
    }
  ],
  "summary": {
    "sent": 1, "ok": 1, "failed": 0, "inconclusive": 0, "loss_pct": 0.0,
    "latency": { "min_ms": 0.31, "avg_ms": 0.31, "p50_ms": 0.31, "p95_ms": 0.31, "max_ms": 0.31, "stddev_ms": 0.0 },
    "interrupted": false
  }
}
```

`outcome` is one of `ok`, `failed`, `inconclusive`. Optional fields (`address`, `timings.*`, `detail`, `error`, `answers`) are omitted when they don't apply. Batch mode prints `{"version":1,"jobs":[{"label","results","summary"}],"summary":{"jobs","ok","failed","inconclusive","interrupted"}}`. The `version` field changes only if the schema changes incompatibly.

## Batch files

```text
# one job per line: <probe> <target> [dns record type]
tcp  db.internal:5432
http https://api.internal/health
dns  example.com AAAA
udp  10.0.0.5:53
icmp 10.0.0.1
```

- `#` starts a comment; blank lines are ignored.
- Batch jobs use defaults: HTTP is `GET` with 2xx/3xx accepted, and UDP sends an empty datagram. `--timeout`, `--count`, `--interval` and `--ca-file` apply to every job.
- Errors name the line (`line 7: unknown probe 'ftp'`) and exit with code 2 before any probe runs.
- Limits: 100,000 jobs, 4 KiB per line.
- Results come back in input order in JSON. Human output prints each job as it finishes.

## Platform behavior and permissions

| Feature | Linux | macOS | Windows |
|---|---|---|---|
| tcp, dns, http, batch | ✅ | ✅ | ✅ |
| udp: reply / silence | ✅ | ✅ | ✅ |
| udp: ICMP port-unreachable detection | ✅ | ✅ (OS-dependent) | ✅ (reported as connection reset) |
| icmp, unprivileged | ✅ if the group is within `net.ipv4.ping_group_range` | ✅ | ❌ |
| icmp, privileged | ✅ root or `CAP_NET_RAW` | ✅ root | ✅ Administrator (raw socket) |

On Linux, unprivileged ping is enabled with:

```sh
sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"
```

**Validation status.** Every feature has been run by hand on Linux x86_64. CI builds and runs the automated test suite on Linux (x86_64, ARM64), Windows (x86_64, ARM64) and macOS (Apple Silicon). macOS x86_64 is cross-compiled in CI but not tested there. ICMP on Windows and macOS has not been verified at runtime.

## Limitations

- HTTP: HTTP/1.1 only (no HTTP/2 or HTTP/3), no proxy support, no redirect following, response body not read.
- TCP and HTTP try resolved addresses one after another, not with Happy Eyeballs racing.
- DNS: one record type per run; DNSSEC is not validated; DNS-over-TLS/HTTPS is not supported.
- ICMP: fixed 32-byte payload; no TTL or packet-size options; no traceroute.
- UDP: fixed 64 KiB receive buffer; only the first reply is read.

## Implementation notes

- Tokio current-thread runtime: every probe is I/O-bound, so one thread is enough and keeps startup and memory low.
- Batch mode keeps at most `--concurrency` tasks alive at once and spawns the next job when one finishes, so memory stays flat as the job count grows.
- TLS is rustls with the *ring* provider. Trust anchors come from the platform store (`rustls-native-certs`) plus `--ca-file`.
- DNS uses hickory-resolver with caching disabled and one attempt per query.
- ICMP sockets are created with `socket2` and driven by Tokio. Echo replies are matched by sequence number (and by identifier on raw sockets), and error messages are matched against the embedded original packet.
- `unsafe` code is denied across the workspace.
