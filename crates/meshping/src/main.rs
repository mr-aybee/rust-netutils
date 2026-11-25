//! MeshPing command-line entry point.

use std::io::Write;
use std::net::IpAddr;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, ValueEnum};
use meshping::probe::{Mode, Prober};
use meshping::stats::{HostStats, Snapshot};
use net_common::target::{Endpoint, parse_endpoint};
use net_common::time::{iso8601, now_unix};
use net_common::{Status, parse_duration};
use net_icmp::Pinger;
use tokio::sync::mpsc;

const MAX_HOSTS: usize = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ModeArg {
    /// ICMP if permitted, otherwise TCP connect (labelled per host).
    Auto,
    Icmp,
    Tcp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Output {
    /// Summary table every --report interval and at exit.
    Table,
    /// One CSV line per probe.
    Csv,
    /// One JSON object per probe (JSON Lines).
    Json,
}

#[derive(Debug, Parser)]
#[command(
    name = "meshping",
    version,
    about = "Continuous multi-host latency and loss monitoring"
)]
struct Cli {
    /// Hosts as HOST or HOST:PORT (the port is used in TCP mode).
    hosts: Vec<String>,
    /// Read additional hosts from FILE (one per line, `#` comments; `-` for stdin).
    #[arg(short = 'f', long = "hosts")]
    hosts_file: Option<std::path::PathBuf>,
    /// Probe mode.
    #[arg(short, long, value_enum, default_value_t = ModeArg::Auto)]
    mode: ModeArg,
    /// Default port for TCP mode when a host has none.
    #[arg(short = 'p', long, default_value_t = 443)]
    tcp_port: u16,
    /// Time between probes to each host.
    #[arg(short, long, default_value = "1s", value_parser = parse_duration)]
    interval: Duration,
    /// Per-probe timeout (default: the smaller of 1s and --interval; must not exceed --interval).
    #[arg(short, long, value_parser = parse_duration)]
    timeout: Option<Duration>,
    /// Stop after this many probes per host (default: run until Ctrl+C).
    #[arg(short, long)]
    count: Option<u64>,
    /// Samples per host in the rolling statistics window.
    #[arg(short, long, default_value_t = 60, value_parser = clap::value_parser!(u32).range(1..=100_000))]
    window: u32,
    /// Output format.
    #[arg(short, long, value_enum, default_value_t = Output::Table)]
    output: Output,
    /// Interval between table reports (table output).
    #[arg(short, long, default_value = "10s", value_parser = parse_duration)]
    report: Duration,
    /// Suppress the final summary (csv/json output).
    #[arg(short, long)]
    quiet: bool,
}

struct Host {
    label: String,
    ip: IpAddr,
    prober: Prober,
}

struct Sample {
    host: usize,
    seq: u64,
    time: i64,
    result: Result<Duration, String>,
}

fn usage(msg: impl std::fmt::Display) -> ExitCode {
    eprintln!("meshping: {msg}");
    ExitCode::from(Status::Usage.code())
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            let _ = e.print();
            return ExitCode::from(if e.use_stderr() {
                Status::Usage.code()
            } else {
                0
            });
        }
    };

    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("meshping: failed to start runtime: {e}");
            return ExitCode::from(Status::Failure.code());
        }
    };

    rt.block_on(run(cli))
}

fn read_targets(cli: &Cli) -> Result<Vec<Endpoint>, String> {
    let mut items = cli.hosts.clone();

    if let Some(path) = &cli.hosts_file {
        let text = if path.as_os_str() == "-" {
            let mut s = String::new();
            std::io::Read::read_to_string(
                &mut std::io::Read::take(std::io::stdin(), 16 * 1024 * 1024),
                &mut s,
            )
            .map_err(|e| format!("cannot read stdin: {e}"))?;
            s
        } else {
            std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?
        };

        items.extend(
            text.lines()
                .map(|l| l.split('#').next().unwrap_or_default().trim().to_string())
                .filter(|l| !l.is_empty()),
        );
    }

    if items.is_empty() {
        return Err("no hosts given (pass HOST[:PORT] or --hosts FILE)".into());
    }

    if items.len() > MAX_HOSTS {
        return Err(format!("more than {MAX_HOSTS} hosts"));
    }

    items
        .iter()
        .map(|h| parse_endpoint(h, Some(cli.tcp_port)))
        .collect()
}

async fn resolve(ep: &Endpoint) -> Result<IpAddr, String> {
    tokio::net::lookup_host((ep.host.as_str(), ep.port))
        .await
        .map_err(|e| format!("cannot resolve '{}': {e}", ep.host))?
        .next()
        .map(|a| a.ip())
        .ok_or_else(|| format!("cannot resolve '{}': no addresses", ep.host))
}

async fn run(cli: Cli) -> ExitCode {
    let timeout = cli
        .timeout
        .unwrap_or_else(|| cli.interval.min(Duration::from_secs(1)));

    if timeout > cli.interval {
        return usage("--timeout must not exceed --interval");
    }

    if cli.count == Some(0) {
        return usage("--count must be at least 1");
    }

    let targets = match read_targets(&cli) {
        Ok(t) => t,
        Err(e) => return usage(e),
    };

    // Resolve once at start; probing then uses fixed addresses (no per-probe DNS cost).
    let mut hosts = Vec::with_capacity(targets.len());
    let mut fallback_noted = false;

    // One shared ICMP socket per address family, opened lazily.
    let mut pingers: [Option<Result<Arc<Pinger>, String>>; 2] = [None, None];
    let id = (std::process::id() & 0xffff) as u16;

    for ep in &targets {
        let ip = match resolve(ep).await {
            Ok(ip) => ip,
            Err(e) => {
                eprintln!("meshping: {e}");
                return ExitCode::from(Status::Failure.code());
            }
        };

        let prober = match cli.mode {
            ModeArg::Tcp => Prober::Tcp { port: ep.port },
            ModeArg::Icmp | ModeArg::Auto => {
                let fam = usize::from(ip.is_ipv6());
                let pinger = pingers[fam]
                    .get_or_insert_with(|| Pinger::open(ip.is_ipv6(), id).map(Arc::new))
                    .clone();

                match pinger {
                    Ok(pinger) => Prober::Icmp { pinger },
                    Err(e) if cli.mode == ModeArg::Icmp => {
                        eprintln!("meshping: {e}");
                        return ExitCode::from(Status::Failure.code());
                    }
                    Err(e) => {
                        if !fallback_noted {
                            eprintln!("meshping: {e}");
                            eprintln!(
                                "meshping: falling back to TCP connect timing (labelled 'tcp'); TCP and ICMP latencies are not directly comparable"
                            );
                            fallback_noted = true;
                        }

                        Prober::Tcp { port: ep.port }
                    }
                }
            }
        };

        let label = if matches!(prober, Prober::Tcp { .. }) {
            format!("{}:{}", ep.host, ep.port)
        } else {
            ep.host.clone()
        };

        hosts.push(Host { label, ip, prober });
    }

    let n = hosts.len();
    let mut stats: Vec<HostStats> = (0..n)
        .map(|_| HostStats::new(cli.window as usize))
        .collect();
    let modes: Vec<Mode> = hosts.iter().map(|h| h.prober.mode()).collect();
    let labels: Vec<String> = hosts.iter().map(|h| h.label.clone()).collect();
    let (tx, mut rx) = mpsc::channel::<Sample>(1024);

    // One task per host; start times are spread across the interval to avoid bursts.
    let local = tokio::task::LocalSet::new();

    for (i, host) in hosts.into_iter().enumerate() {
        let tx = tx.clone();
        let (interval, count) = (cli.interval, cli.count);
        let offset = interval.mul_f64(i as f64 / n as f64);
        local.spawn_local(async move {
            tokio::time::sleep(offset).await;
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut seq: u64 = 0;

            loop {
                if count.is_some_and(|c| seq >= c) {
                    break;
                }

                ticker.tick().await;
                let result = host.prober.probe(host.ip, timeout).await;

                if tx
                    .send(Sample {
                        host: i,
                        seq,
                        time: now_unix(),
                        result,
                    })
                    .await
                    .is_err()
                {
                    break;
                }

                seq += 1;
            }
        });
    }

    drop(tx);

    if cli.output == Output::Csv {
        println!("time,host,mode,seq,rtt_ms,status");
    }

    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    let mut report = tokio::time::interval_at(tokio::time::Instant::now() + cli.report, cli.report);
    let interrupted = local
        .run_until(async {
            loop {
                tokio::select! {
                    s = rx.recv() => match s {
                        None => return false,
                        Some(s) => {
                            let rtt_ms = s.result.as_ref().ok().map(|d| d.as_secs_f64() * 1000.0);
                            stats[s.host].record(rtt_ms);
                            emit_sample(cli.output, &s, &labels[s.host], modes[s.host], rtt_ms);
                        }
                    },
                    _ = report.tick(), if cli.output == Output::Table => print_table(&labels, &modes, &stats, false),
                    _ = &mut ctrl_c => return true,
                }
            }
        })
        .await;

    if cli.output == Output::Table {
        print_table(&labels, &modes, &stats, interrupted);
    } else if !cli.quiet {
        let mut err = std::io::stderr().lock();
        let _ = write!(err, "{}", table_text(&labels, &modes, &stats, interrupted));
    }

    let unreachable = stats.iter().any(|s| s.sent > 0 && s.received == 0);
    ExitCode::from(if unreachable {
        Status::Failure.code()
    } else {
        Status::Ok.code()
    })
}

fn emit_sample(output: Output, s: &Sample, label: &str, mode: Mode, rtt_ms: Option<f64>) {
    let mut out = std::io::stdout().lock();

    match output {
        Output::Table => {}
        Output::Csv => {
            let (rtt, status) = match &s.result {
                Ok(_) => (
                    format!("{:.3}", rtt_ms.unwrap_or_default()),
                    "ok".to_string(),
                ),
                Err(e) => (String::new(), format!("\"{}\"", e.replace('"', "'"))),
            };

            let _ = writeln!(
                out,
                "{},{label},{mode},{},{rtt},{status}",
                iso8601(s.time),
                s.seq
            );
        }
        Output::Json => {
            let v = serde_json::json!({
                "time": iso8601(s.time), "host": label, "mode": mode, "seq": s.seq,
                "rtt_ms": rtt_ms, "error": s.result.as_ref().err(),
            });
            let _ = writeln!(out, "{v}");
        }
    }
}

fn ms(v: Option<f64>) -> String {
    v.map_or_else(|| "-".into(), |x| format!("{x:.2}"))
}

fn table_text(labels: &[String], modes: &[Mode], stats: &[HostStats], interrupted: bool) -> String {
    let w = labels.iter().map(String::len).max().unwrap_or(4).max(4);
    let mut s = format!(
        "{}{}\n{:<w$}  {:<4}  {:>6}  {:>6}  {:>8}  {:>8}  {:>8}  {:>8}  {:>8}  {:>8}\n",
        iso8601(now_unix()),
        if interrupted { " (interrupted)" } else { "" },
        "HOST",
        "MODE",
        "SENT",
        "LOSS%",
        "LAST",
        "MIN",
        "AVG",
        "P95",
        "MAX",
        "JITTER"
    );

    for ((label, mode), st) in labels.iter().zip(modes).zip(stats) {
        let Snapshot {
            sent,
            loss_pct,
            last_ms,
            min_ms,
            avg_ms,
            p95_ms,
            max_ms,
            jitter_ms,
            ..
        } = st.snapshot();
        s.push_str(&format!(
            "{label:<w$}  {:<4}  {sent:>6}  {loss_pct:>6.1}  {:>8}  {:>8}  {:>8}  {:>8}  {:>8}  {:>8}\n",
            mode.to_string(),
            ms(last_ms),
            ms(min_ms),
            ms(avg_ms),
            ms(p95_ms),
            ms(max_ms),
            ms(jitter_ms)
        ));
    }

    s
}

fn print_table(labels: &[String], modes: &[Mode], stats: &[HostStats], interrupted: bool) {
    let _ = writeln!(
        std::io::stdout().lock(),
        "{}",
        table_text(labels, modes, stats, interrupted)
    );
}
