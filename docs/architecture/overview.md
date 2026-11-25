# Architecture overview

## Workspace layout

```text
rust-netutils/
├── crates/
│   ├── net-common/   private (publish = false): exit statuses, duration and endpoint parsing
│   ├── netprobe/     library + binary
│   └── certwatch/    library + binary
├── docs/             architecture, utility docs, benchmark reports
└── scripts/          reproducible benchmark harnesses
```

Each utility is its own crate with its own version, changelog, tests and release tag (`<crate>-vX.Y.Z`). Shared code goes into `net-common` only when more than one utility uses it; there are no dependencies between utilities.

## netprobe

```mermaid
flowchart LR
    CLI[cli.rs<br/>clap parsing + validation] --> MAIN[main.rs<br/>runtime, Ctrl+C, exit status]
    MAIN --> RUN[runner.rs<br/>count, interval, deadline, cancellation]
    MAIN --> BATCH[batch.rs<br/>job file, bounded concurrency]
    BATCH --> RUN
    RUN --> P{probe}
    P --> TCP[tcp]
    P --> DNS[dns<br/>hickory-resolver]
    P --> HTTP[http<br/>HTTP/1.1 + rustls]
    P --> UDP[udp]
    P --> ICMP[icmp<br/>socket2 dgram/raw<br/>Windows: IcmpSendEcho]
    RUN --> STATS[stats.rs<br/>min/avg/p50/p95/max]
    MAIN --> OUT[output.rs<br/>human / JSON]
```

### Design decisions

| Decision | Reason |
|---|---|
| Logic lives in the library; `main.rs` is a thin wrapper | Integration tests and benchmarks call the same code paths as the CLI. |
| Tokio current-thread runtime | Probes are I/O-bound. One thread keeps startup at about 4.6 ms and memory low. |
| Hand-written HTTP/1.1 client instead of hyper/reqwest | The probe needs one request and the response head. A small client gives exact per-phase timing and a smaller dependency tree. |
| Deadline enforced in the runner; UDP and ICMP enforce their own | A generic deadline turns a hang into "timed out". UDP needs silence to mean *inconclusive*, so it handles its own timeout and the runner allows a grace period. |
| Three outcomes (`ok` / `failed` / `inconclusive`) and exit code 3 | Prevents reporting UDP silence as either open or closed. |
| `unsafe_code = "deny"`, one documented exception | Socket setup goes through `socket2`'s safe API. The only `unsafe` is Windows ICMP FFI (`icmp_windows.rs`), which is the only way to ping on Windows without Administrator rights. |

## certwatch

```mermaid
flowchart LR
    CLI[cli.rs] --> MAIN[main.rs<br/>targets, bounded concurrency, Ctrl+C]
    MAIN --> CHECK[check.rs<br/>connect, handshake, policy]
    MAIN --> INSPECT[inspect.rs<br/>local PEM/DER]
    CHECK --> TLS[tls.rs<br/>RecordingVerifier around WebPKI]
    CHECK --> CERT[cert.rs<br/>x509-parser summary]
    INSPECT --> CERT
    MAIN --> OUT[output.rs<br/>human / JSON]
```

| Decision | Reason |
|---|---|
| `RecordingVerifier` wraps the real WebPKI verifier and records its verdict | One handshake gives both the chain and the exact validation error, so expired or untrusted chains can still be inspected. No data is sent, and failures are always reported. |
| `x509-parser` for certificate details; `ring` for fingerprints | Mature parser; `ring` is already in the tree through rustls. |
| Separate `Warning` exit code (4) | CI can treat "expiring soon" differently from "broken". |
| Dates formatted with an internal civil-calendar routine | Avoids a date/time dependency for a single conversion. |
