# meshping

Continuously measure latency and loss to many hosts at once, over ICMP or TCP, with rolling statistics and CSV/JSON export.

```console
$ meshping 1.1.1.1 8.8.8.8 ::1 10.255.255.1 -c 3 -i 300ms
2026-11-25T13:33:22Z
HOST          MODE    SENT   LOSS%      LAST       MIN       AVG       P95       MAX    JITTER
1.1.1.1       icmp       3     0.0     15.97     11.51     14.69     16.58     16.58      4.77
8.8.8.8       icmp       3     0.0     13.39     13.39     14.80     16.59     16.59      1.60
::1           icmp       3     0.0      0.40      0.40      0.50      0.61      0.61      0.11
10.255.255.1  icmp       3   100.0         -         -         -         -         -         -
```

## Install

Download a binary from [Releases](https://github.com/mr-aybee/rust-netutils/releases), or:

```sh
cargo install --git https://github.com/mr-aybee/rust-netutils meshping
```

## Usage

```sh
meshping HOST[:PORT]... [-f hosts.txt] [-m auto|icmp|tcp] [-i 1s] [-c N] [-o table|csv|json]
```

Exit codes: `0` every host answered at least once, `1` some host never answered (or a setup failure), `2` usage error.

Full documentation: [docs/utilities/meshping.md](../../docs/utilities/meshping.md). Benchmarks: [docs/benchmarks/meshping.md](../../docs/benchmarks/meshping.md).

## License

MIT OR Apache-2.0.
