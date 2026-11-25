# dnswatch

DNS record change monitoring, propagation waiting and multi-resolver comparison.

<details>
<summary><strong>Contents</strong></summary>

- [Why](#why)
- [Commands](#commands)
- [Common options](#common-options)
- [What counts as a change](#what-counts-as-a-change)
- [Output](#output)
- [Exit codes](#exit-codes)
- [Recipes](#recipes)
- [Limitations](#limitations)
- [How it works](#how-it-works)

</details>

## Why

DNS problems usually come down to one of three questions:
- *Did a record change?*
- *Has my change reached the resolvers that matter yet?*
- *Do these resolvers agree?*

`dig` in a shell loop can answer them, but it has no notion of state: it can't tell a real change from a TTL countdown, record reordering or a transient SERVFAIL. dnswatch keeps that state for you.

## Commands

### `watch`

```sh
dnswatch watch example.com api.example.com -T A,AAAA -i 60s
dnswatch watch example.com -s 1.1.1.1 -s 8.8.8.8 --until-change   # exit 0 on first change
dnswatch watch example.com -q --json >> /var/log/dns-events.jsonl  # changes and errors only
```

```console
2026-11-25T13:14:34Z  INITIAL   example.com A @system  A 104.20.23.154, A 172.66.147.243
2026-11-25T13:20:34Z  CHANGED   example.com A @system  + A 104.20.23.160  - A 104.20.23.154
2026-11-25T13:25:34Z  ERROR     example.com A @system  error: request timed out
2026-11-25T13:26:34Z  RECOVERED example.com A @system  A 104.20.23.160, A 172.66.147.243
```

### `wait`

```sh
dnswatch wait app.example.com -e 203.0.113.10 -s 1.1.1.1 -s 8.8.8.8 -s 9.9.9.9 --max-wait 30m
dnswatch wait example.com -T MX -e "10 mail.example.com" -i 30s
```

`wait` polls every `--interval` (default 10s) until **every** server returns **exactly** the expected set of values for **every** name and type. Values are compared case-insensitively, ignoring a trailing dot. CNAMEs followed on the way are ignored. Each poll prints which resolvers are still pending.

### `compare`

```sh
dnswatch compare example.com -T A,AAAA,MX -s 1.1.1.1 -s 8.8.8.8 -s 192.0.2.53
```

Queries each name and type once on every server and reports `CONSISTENT` or `DIFFERENT`. Order and TTL differences are ignored. Some differences are legitimate, for example GeoDNS and load-balanced records.

## Common options

| Option | Default | Meaning |
|---|---|---|
| `-T, --type` | `A` | Comma-separated record types: A, AAAA, CNAME, MX, TXT, NS, SOA, PTR, SRV, CAA. |
| `-s, --server` | system resolver | Resolver `IP[:PORT]`; repeatable. |
| `-t, --timeout` | `3s` | Per-query timeout (one attempt; the cache is disabled). |
| `-j, --concurrency` | 64 | Queries in flight. |
| `-i, --interval` | `60s` watch / `10s` wait | Poll interval. |
| `--json` | off | `watch`/`wait`: one JSON object per line. `compare`: one document. |

At most 10,000 name × type × server combinations per run.

## What counts as a change

Every answer is put into one of four states:

| State | Example |
|---|---|
| Records | `A 192.0.2.1, A 192.0.2.2`, sorted, TTL removed |
| NXDOMAIN | The name does not exist. |
| NODATA | The name exists but has no records of this type. |
| Error | Timeout, SERVFAIL, REFUSED, network error. |

A **change** is a transition between different definitive states (the first three). **Errors never count as changes**: a failure streak is reported once as `ERROR`. If the next good answer equals the previous one, `RECOVERED` is reported; otherwise `CHANGED`. TTL countdowns and record reordering are not changes.

## Output

`watch --json` event:

```json
{"time":"2026-11-25T13:20:34Z","event":"changed","name":"example.com","type":"A","server":"1.1.1.1",
 "answer":{"status":"records","records":["A 104.20.23.160","A 172.66.147.243"]},
 "previous":{"status":"records","records":["A 104.20.23.154","A 172.66.147.243"]},
 "added":["A 104.20.23.160"],"removed":["A 104.20.23.154"]}
```

`event` is one of `initial`, `changed`, `error`, `recovered`. `answer.status` is one of `records`, `nxdomain`, `nodata`, `error`.

## Exit codes

| Command | 0 | 1 | 2 | 3 |
|---|---|---|---|---|
| `watch` | stopped (Ctrl+C or `--until-change`) | resolver setup failed | usage | — |
| `wait` | all servers matched | `--max-wait` exceeded or interrupted | usage | — |
| `compare` | all answers identical | answers differ | usage | no differences, but some queries failed |

## Recipes

```sh
# Cut-over script: switch DNS, wait until the big public resolvers see it, then proceed.
dnswatch wait app.example.com -e 203.0.113.10 -s 1.1.1.1 -s 8.8.8.8 -s 9.9.9.9 --max-wait 1h && ./switch-traffic.sh

# Detect unexpected changes to MX/NS records (alert on any output).
dnswatch watch example.com -T MX,NS,TXT -i 5m -q --json | while read -r ev; do notify "$ev"; done

# Migration check: old vs new authoritative servers must agree.
dnswatch compare example.com www.example.com -T A,AAAA,MX,TXT -s 192.0.2.53 -s 198.51.100.53
```

## Limitations

- No DNSSEC validation; no DNS-over-TLS or DNS-over-HTTPS.
- Querying authoritative servers directly works because dnswatch sends standard recursive queries and reads the answer section, but it does not follow referrals itself.
- `wait` compares exact sets; there's no "contains" mode.
- CI builds and tests on Linux, Windows and macOS. Watching for multiple days has only been tested indirectly.

## How it works

Each poll queries every (name, type, server) combination concurrently, with at most `--concurrency` in flight. The last *definitive* answer per combination is kept in memory, and a new answer is compared with it to produce events. Memory stays constant over time, so it grows only with the number of combinations.
