use clap::{Args, Parser, Subcommand};
use dnswatch::query::{self, Answer, Source};
use dnswatch::run::{self, Query, Settings};
use net_common::target::{parse_endpoint, validate_host};
use net_common::{Status, parse_duration};
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

/// Upper bound on name × type × server combinations per run.
const MAX_QUERIES: usize = 10_000;

#[derive(Debug, Parser)]
#[command(
    name = "dnswatch",
    version,
    about = "DNS record monitoring, propagation waiting and resolver comparison",
    propagate_version = true
)]
struct Cli {
    /// JSON output (one JSON object per line for watch/wait).
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Args)]
struct Common {
    /// Domain names to query.
    #[arg(required = true)]
    names: Vec<String>,
    /// Record types, comma-separated.
    #[arg(short = 'T', long = "type", default_value = "A", value_delimiter = ',')]
    types: Vec<String>,
    /// Resolver IP[:PORT] to query (repeatable). Default: the system resolver.
    #[arg(short, long = "server")]
    servers: Vec<String>,
    /// Per-query timeout.
    #[arg(short, long, default_value = "3s", value_parser = parse_duration)]
    timeout: Duration,
    /// Maximum queries in flight.
    #[arg(short = 'j', long, default_value_t = 64, value_parser = clap::value_parser!(u16).range(1..=1024))]
    concurrency: u16,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Poll records and report changes until interrupted.
    Watch {
        #[command(flatten)]
        common: Common,
        /// Time between polls.
        #[arg(short, long, default_value = "60s", value_parser = parse_duration)]
        interval: Duration,
        /// Exit (status 0) after the first change.
        #[arg(long)]
        until_change: bool,
        /// Do not print the initial state, only changes and errors.
        #[arg(short, long)]
        quiet: bool,
    },
    /// Wait until every server returns exactly the expected values (propagation check).
    Wait {
        #[command(flatten)]
        common: Common,
        /// Expected value(s) of the requested type, e.g. an IP address (repeatable).
        #[arg(short, long = "expect", required = true)]
        expect: Vec<String>,
        /// Time between polls.
        #[arg(short, long, default_value = "10s", value_parser = parse_duration)]
        interval: Duration,
        /// Give up after this long (exit status 1).
        #[arg(long, default_value = "10m", value_parser = parse_duration)]
        max_wait: Duration,
    },
    /// Query once and compare answers across servers.
    Compare {
        #[command(flatten)]
        common: Common,
    },
}

fn usage(msg: impl std::fmt::Display) -> ExitCode {
    eprintln!("dnswatch: {msg}");
    ExitCode::from(Status::Usage.code())
}

fn parse_server(s: &str) -> Result<SocketAddr, String> {
    let ep = parse_endpoint(s, Some(53))?;
    let ip: IpAddr = ep
        .host
        .parse()
        .map_err(|_| format!("--server must be an IP address, got '{}'", ep.host))?;
    Ok(SocketAddr::new(ip, ep.port))
}

type Prepared = (Arc<Vec<Source>>, Arc<Vec<Query>>);

fn setup(c: &Common) -> Result<Prepared, (Status, String)> {
    let usage = |m: String| (Status::Usage, m);
    let mut types = Vec::new();
    for t in &c.types {
        types.push(query::parse_type(t).map_err(usage)?);
    }

    let mut queries = Vec::new();

    for n in &c.names {
        validate_host(n).map_err(|e| usage(format!("invalid name '{n}': {e}")))?;

        for t in &types {
            queries.push(Query {
                name: n.clone(),
                rtype: *t,
            });
        }
    }

    let servers: Vec<Option<SocketAddr>> = if c.servers.is_empty() {
        vec![None]
    } else {
        c.servers
            .iter()
            .map(|s| parse_server(s).map(Some))
            .collect::<Result<_, _>>()
            .map_err(usage)?
    };

    if queries.len() * servers.len() > MAX_QUERIES {
        return Err(usage(format!(
            "more than {MAX_QUERIES} name/type/server combinations"
        )));
    }

    let sources = servers
        .into_iter()
        .map(|s| query::build_source(s, c.timeout))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| (Status::Failure, e))?;
    Ok((Arc::new(sources), Arc::new(queries)))
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
            eprintln!("dnswatch: failed to start runtime: {e}");
            return ExitCode::from(Status::Failure.code());
        }
    };

    rt.block_on(run(cli))
}

async fn run(cli: Cli) -> ExitCode {
    let json = cli.json;

    let common = match &cli.command {
        Command::Watch { common, .. }
        | Command::Wait { common, .. }
        | Command::Compare { common } => common,
    };

    let (sources, queries) = match setup(common) {
        Ok(v) => v,
        Err((status, msg)) => {
            eprintln!("dnswatch: {msg}");
            return ExitCode::from(status.code());
        }
    };

    let concurrency = usize::from(common.concurrency);
    let ctrl_c = async {
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    };

    match cli.command {
        Command::Watch {
            interval,
            until_change,
            quiet,
            ..
        } => {
            let s = Settings {
                interval,
                concurrency,
                json,
            };
            tokio::select! {
                _ = run::watch(sources, queries, &s, until_change, quiet) => ExitCode::from(Status::Ok.code()),
                () = ctrl_c => ExitCode::from(Status::Ok.code()),
            }
        }
        Command::Wait {
            expect,
            interval,
            max_wait,
            ..
        } => {
            if expect.iter().any(|e| e.trim().is_empty()) {
                return usage("--expect values must not be empty");
            }

            let s = Settings {
                interval,
                concurrency,
                json,
            };
            tokio::select! {
                _ = run::wait(sources, queries, &s, &expect) => ExitCode::from(Status::Ok.code()),
                () = tokio::time::sleep(max_wait) => {
                    eprintln!("dnswatch: expected values not seen on all servers within {}s", max_wait.as_secs());
                    ExitCode::from(Status::Failure.code())
                }
                () = ctrl_c => ExitCode::from(Status::Failure.code()),
            }
        }
        Command::Compare { .. } => {
            let results = run::compare(sources, queries, concurrency).await;
            let errors = results
                .iter()
                .any(|r| r.answers.iter().any(|(_, a)| !a.is_definitive()));
            let differ = results.iter().any(|r| {
                let defs: Vec<&Answer> = r
                    .answers
                    .iter()
                    .map(|(_, a)| a)
                    .filter(|a| a.is_definitive())
                    .collect();
                defs.windows(2).any(|w| w[0] != w[1])
            });
            let mut out = std::io::stdout().lock();

            if json {
                let doc = serde_json::json!({"version": 1, "results": results, "consistent": !differ && !errors});
                let _ = writeln!(out, "{doc:#}");
            } else {
                for r in &results {
                    let _ = writeln!(
                        out,
                        "{} {}  {}",
                        r.name,
                        r.rtype,
                        if r.consistent {
                            "CONSISTENT"
                        } else {
                            "DIFFERENT"
                        }
                    );

                    for (server, a) in &r.answers {
                        let _ = writeln!(out, "  @{server:<20} {}", a.summary());
                    }
                }
            }

            let status = if differ {
                Status::Failure
            } else if errors {
                Status::Inconclusive
            } else {
                Status::Ok
            };

            ExitCode::from(status.code())
        }
    }
}
