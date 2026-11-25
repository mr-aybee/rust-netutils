# portwatch

See which sockets are open, who owns them, and what changes, on Linux, Windows and macOS.

```console
$ portwatch -l -t
PROTO LOCAL                    REMOTE   STATE       PID/PROCESS
tcp   0.0.0.0:22               *        LISTEN      -
tcp   127.0.0.1:4226           *        LISTEN      87145/sccache
2 socket(s)

$ portwatch -p 8080 -q || echo "nothing on 8080"
nothing on 8080

$ portwatch --watch -p 5432
2026-11-25T14:02:11Z  OPENED  tcp  10.0.0.5:51544   10.0.0.9:5432   ESTABLISHED 4121/api
2026-11-25T14:02:15Z  STATE   tcp  10.0.0.5:51544   10.0.0.9:5432   TIME_WAIT   -  (was ESTABLISHED)
```

## Install

Download a binary from [Releases](https://github.com/mr-aybee/rust-netutils/releases), or:

```sh
cargo install --git https://github.com/mr-aybee/rust-netutils portwatch
```

Exit codes: `0` matching sockets found, `1` no match (or the socket table could not be read), `2` usage error.

Full documentation: [docs/utilities/portwatch.md](../../docs/utilities/portwatch.md). Benchmarks: [docs/benchmarks/portwatch.md](../../docs/benchmarks/portwatch.md).

## License

MIT OR Apache-2.0.
