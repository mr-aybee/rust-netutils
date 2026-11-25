# dnswatch

Watch DNS records for changes, wait for a change to propagate, and compare what different resolvers return.

```console
$ dnswatch compare github.com -s 1.1.1.1 -s 8.8.8.8 -s 9.9.9.9
github.com A  DIFFERENT
  @1.1.1.1              A 140.82.121.4
  @8.8.8.8              A 140.82.121.4
  @9.9.9.9              A 140.82.121.3

$ dnswatch wait app.example.com -e 203.0.113.10 -s 1.1.1.1 -s 8.8.8.8 --max-wait 30m
2026-11-25T13:14:39Z  1/2 matching; waiting on: app.example.com A @8.8.8.8: A 198.51.100.4
2026-11-25T13:14:49Z  2/2 matching

$ dnswatch watch example.com -T A,MX -i 60s --json >> dns-events.jsonl
```

## Install

Download a binary from [Releases](https://github.com/mr-aybee/rust-netutils/releases), or:

```sh
cargo install --git https://github.com/mr-aybee/rust-netutils dnswatch
```

## Commands

| Command | Purpose | Exit |
|---|---|---|
| `dnswatch watch NAME...` | Report record changes until interrupted (or `--until-change`) | 0 |
| `dnswatch wait NAME... -e VALUE` | Wait until all resolvers return the expected values | 0 matched, 1 timed out |
| `dnswatch compare NAME...` | Compare answers across resolvers once | 0 same, 1 different, 3 errors only |

Full documentation: [docs/utilities/dnswatch.md](../../docs/utilities/dnswatch.md). Benchmarks: [docs/benchmarks/dnswatch.md](../../docs/benchmarks/dnswatch.md).

## License

MIT OR Apache-2.0.
