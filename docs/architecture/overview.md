# Architecture overview

## Workspace layout

```text
rust-netutils/
├── crates/
│   ├── net-common/   private (publish = false): exit statuses, duration parsing
│   └── netprobe/     library + binary
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
    P --> ICMP[icmp<br/>socket2 dgram/raw]
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
| `unsafe_code = "deny"` | Socket setup goes through `socket2`'s safe API. |
