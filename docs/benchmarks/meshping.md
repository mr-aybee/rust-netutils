# meshping benchmark report

> These results come from a single, shared host. They are not guarantees.

## Environment

| Item | Value |
|---|---|
| CPU | Intel Xeon E5-2620 v2 @ 2.10 GHz, 16 logical CPUs |
| OS | Linux 6.8.0-147-generic, x86_64 |
| Rust | rustc 1.100.0 (0ef1bc386 2026-11-09) |
| Build profile | `release` (thin LTO, `codegen-units = 1`, stripped) |
| Date | 2026-11-25 |
| System state | Shared development host; CPU time varies between identical runs. All runs are listed. |

## Workload

- 100 distinct loopback addresses, `127.0.0.1` to `127.0.0.100`, each probed once per second for 30 s (3,000 probes).
- **ICMP**: raw socket via `sudo` (unprivileged ICMP is disabled on this host).
- **TCP**: connect to port 9 on each address, refused immediately, which counts as a timed reply.
- Table output with the report interval set past the end of the run, so output I/O is excluded.
- CPU = user + system time from `/usr/bin/time`, divided by wall time (100% = one logical core).

## Results against the engineering targets

| Target (from project plan) | Measured (median of 5 runs) | Status |
|---|---|---|
| 100 hosts at 1 Hz using < 5% of one core | ICMP 2.47%, TCP 4.00% | Met (median). One outlier run per mode exceeded 5%; see below. |
| < 40 MiB RSS | ICMP 6.8 MiB, TCP 3.0 MiB | Met |

## All runs

| Run | TCP CPU | ICMP CPU |
|---|---|---|
| 1 | 4.00% | 2.79% |
| 2 | 2.20% | 2.10% |
| 3 | 4.00% | 6.93% |
| 4 | 2.53% | 1.97% |
| 5 | 5.87% | 2.47% |

A `strace -c` profile of 1,000 ICMP probes showed 1,000 `sendto`, 3,000 `recvfrom` (on loopback the raw socket also sees its own outgoing requests; one of each three returns EAGAIN) and about 4,300 `epoll_wait`. That means no busy looping, so the variance comes from the host, not the program.

## Higher rate

100 hosts at 10 Hz (TCP, JSON line per sample to `/dev/null`): 16.9% of one core, 3.0 MiB RSS.

## Optimization recorded during development

The first ICMP version opened one raw socket per host. With raw sockets the kernel copies every ICMP packet to every raw socket, so 100 hosts meant about 20,000 deliveries per second. That run used **9.49%** of a core, missing the target. Moving to a shared socket per address family with a demultiplexing receive task brought the median down to **2.47%**.

## Startup and binary size

| Metric | Value |
|---|---|
| Binary (x86_64 Linux, stripped) | 1,192,064 bytes (1.1 MiB) |

## Reproducing

```sh
scripts/bench-meshping.sh 30 5    # ICMP runs need passwordless sudo
```

## Known limitations

- Loopback only, so no real network latency or loss.
- No comparison with `fping` (not installed on the reference host).
- Unprivileged datagram ICMP (Linux `ping_group_range`, macOS) has not been benchmarked. It needs no receive-side filtering, so it should cost no more than raw sockets.
