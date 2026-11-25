use std::io::Write;
use std::process::ExitCode;

use clap::Parser;
use net_common::Status;
use netprobe::cli::{Cli, Command};
use netprobe::output::{self, Verbosity};
use netprobe::probe::{dns, http, icmp, tcp, udp};
use netprobe::runner::{self, Plan, Report};
use netprobe::target::parse_endpoint;

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
            eprintln!("netprobe: failed to start runtime: {e}");
            return ExitCode::from(Status::Failure.code());
        }
    };

    ExitCode::from(rt.block_on(run(cli)).code())
}

async fn run(cli: Cli) -> Status {
    let verbosity = if cli.quiet {
        Verbosity::Quiet
    } else if cli.verbose {
        Verbosity::Verbose
    } else {
        Verbosity::Normal
    };

    let json = cli.json;
    let print = move |r: &netprobe::probe::ProbeResult| {
        if !json && verbosity != Verbosity::Quiet {
            let _ = writeln!(
                std::io::stdout().lock(),
                "{}",
                output::human_line(r, verbosity)
            );
        }
    };
    let cancel = async {
        // If the signal handler cannot be installed, never cancel.
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    };

    if let Command::Batch {
        file,
        concurrency,
        ca_file,
        common,
    } = cli.command
    {
        return run_batch(
            &file,
            concurrency,
            ca_file.as_deref(),
            &common,
            json,
            verbosity,
            cancel,
        )
        .await;
    }

    let (target, (results, interrupted)) = match cli.command {
        Command::Batch { .. } => unreachable!("handled above"),
        Command::Tcp { target, common } => {
            let ep = match parse_endpoint(&target, None) {
                Ok(ep) => ep,
                Err(e) => {
                    eprintln!("netprobe: {e}");
                    return Status::Usage;
                }
            };

            let plan = plan_of(&common, std::time::Duration::ZERO);
            let label = ep.to_string();
            let out = runner::run(
                plan,
                "tcp",
                &label,
                |seq| tcp::probe(&ep, seq),
                cancel,
                print,
            )
            .await;
            (label, out)
        }
        Command::Http {
            url,
            head,
            expect,
            ca_file,
            insecure,
            common,
        } => {
            let url = match netprobe::url::parse_url(&url) {
                Ok(u) => u,
                Err(e) => {
                    eprintln!("netprobe: {e}");
                    return Status::Usage;
                }
            };

            if let Some(bad) = expect.iter().find(|c| !(100..=599).contains(*c)) {
                eprintln!("netprobe: invalid --expect status code {bad}");
                return Status::Usage;
            }

            let tls = if url.tls {
                if insecure {
                    eprintln!(
                        "netprobe: WARNING: --insecure disables certificate verification; results do not prove the server is authentic"
                    );
                }

                match http::client_config(ca_file.as_deref(), insecure) {
                    Ok(c) => Some(c),
                    Err(e) => {
                        eprintln!("netprobe: {e}");
                        return Status::Failure;
                    }
                }
            } else {
                None
            };

            let opts = http::HttpOptions {
                method: if head {
                    http::Method::Head
                } else {
                    http::Method::Get
                },
                expect,
            };
            let plan = plan_of(&common, std::time::Duration::ZERO);
            let label = url.display();
            let out = runner::run(
                plan,
                "http",
                &label,
                |seq| http::probe(&url, tls.as_ref(), &opts, seq),
                cancel,
                print,
            )
            .await;
            (label, out)
        }
        Command::Udp {
            target,
            payload,
            payload_hex,
            common,
        } => {
            let parsed = parse_endpoint(&target, None).and_then(|ep| {
                let data = match (payload, payload_hex) {
                    (Some(p), _) => udp::decode_escaped(&p)?,
                    (None, Some(h)) => udp::decode_hex(&h)?,
                    (None, None) => Vec::new(),
                };

                if data.len() > udp::MAX_PAYLOAD {
                    return Err(format!("payload exceeds {} bytes", udp::MAX_PAYLOAD));
                }

                Ok((ep, data))
            });

            let (ep, data) = match parsed {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("netprobe: {e}");
                    return Status::Usage;
                }
            };

            let plan = plan_of(&common, std::time::Duration::from_secs(1));
            let label = ep.to_string();
            let out = runner::run(
                plan,
                "udp",
                &label,
                |seq| udp::probe(&ep, &data, common.timeout, seq),
                cancel,
                print,
            )
            .await;
            (label, out)
        }
        Command::Icmp { host, common } => {
            if let Err(e) = netprobe::target::validate_host(&host) {
                eprintln!("netprobe: invalid host '{host}': {e}");
                return Status::Usage;
            }

            let ip = match icmp::resolve_ip(&host).await {
                Ok(ip) => ip,
                Err(e) => {
                    eprintln!("netprobe: cannot resolve '{host}': {e}");
                    return Status::Failure;
                }
            };

            let sock = match icmp::IcmpSocket::open(ip.is_ipv6()) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("netprobe: {e}");
                    return Status::Failure;
                }
            };

            // Identifier distinguishes our packets on raw sockets.
            let id = (std::process::id() & 0xffff) as u16;
            let plan = plan_of(&common, std::time::Duration::from_secs(1));
            let label = host.clone();
            let out = runner::run(
                plan,
                "icmp",
                &label,
                |seq| icmp::probe(&sock, &host, ip, id, common.timeout, seq),
                cancel,
                print,
            )
            .await;
            (label, out)
        }
        Command::Dns {
            name,
            record_type,
            server,
            common,
        } => {
            let (rtype, server) = match parse_dns_args(&name, &record_type, server.as_deref()) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("netprobe: {e}");
                    return Status::Usage;
                }
            };

            let resolver = match dns::build_resolver(server, common.timeout) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("netprobe: {e}");
                    return Status::Failure;
                }
            };

            let plan = plan_of(&common, std::time::Duration::ZERO);
            let label = format!("{name} {rtype}");
            let out = runner::run(
                plan,
                "dns",
                &label,
                |seq| dns::probe(&resolver, &name, rtype, seq),
                cancel,
                print,
            )
            .await;
            (label, out)
        }
    };

    let report = Report::from_results(&results, interrupted);

    if json {
        if let Err(e) = output::write_json(&results, &report)
            && e.kind() != std::io::ErrorKind::BrokenPipe
        {
            eprintln!("netprobe: failed to write output: {e}");
            return Status::Failure;
        }
    } else if results.len() > 1 || verbosity == Verbosity::Quiet || interrupted {
        println!("{}", output::human_summary(&target, &report));
    }

    report.status()
}

fn parse_dns_args(
    name: &str,
    record_type: &str,
    server: Option<&str>,
) -> Result<
    (
        hickory_resolver::proto::rr::RecordType,
        Option<std::net::SocketAddr>,
    ),
    String,
> {
    netprobe::target::validate_host(name).map_err(|e| format!("invalid name '{name}': {e}"))?;
    let rtype = dns::parse_record_type(record_type)?;
    let server = match server {
        None => None,
        Some(s) => {
            let ep = parse_endpoint(s, Some(53))?;
            let ip: std::net::IpAddr = ep
                .host
                .parse()
                .map_err(|_| format!("--server must be an IP address, got '{}'", ep.host))?;
            Some(std::net::SocketAddr::new(ip, ep.port))
        }
    };
    Ok((rtype, server))
}

fn plan_of(c: &netprobe::cli::Common, grace: std::time::Duration) -> Plan {
    Plan {
        count: c.count,
        interval: c.interval,
        timeout: c.timeout,
        grace,
    }
}

async fn run_batch(
    file: &std::path::Path,
    concurrency: u16,
    ca_file: Option<&std::path::Path>,
    common: &netprobe::cli::Common,
    json: bool,
    verbosity: Verbosity,
    cancel: impl std::future::Future<Output = ()>,
) -> Status {
    use netprobe::batch;

    let text = if file.as_os_str() == "-" {
        let mut s = String::new();

        match std::io::Read::read_to_string(
            &mut std::io::Read::take(std::io::stdin(), 64 * 1024 * 1024),
            &mut s,
        ) {
            Ok(_) => s,
            Err(e) => {
                eprintln!("netprobe: cannot read stdin: {e}");
                return Status::Usage;
            }
        }
    } else {
        match std::fs::read_to_string(file) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("netprobe: cannot read {}: {e}", file.display());
                return Status::Usage;
            }
        }
    };

    let jobs = match batch::parse_jobs(&text) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("netprobe: {}: {e}", file.display());
            return Status::Usage;
        }
    };

    let total = jobs.len();

    let shared = match batch::Shared::for_jobs(&jobs, common.timeout, ca_file) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("netprobe: {e}");
            return Status::Failure;
        }
    };

    let plan = plan_of(common, std::time::Duration::ZERO);
    let on_done = |o: &batch::JobOutcome| {
        if json || verbosity == Verbosity::Quiet {
            return;
        }

        let mut out = std::io::stdout().lock();

        if o.results.len() == 1 {
            let _ = writeln!(out, "{}", output::human_line(&o.results[0], verbosity));
        } else {
            let _ = writeln!(out, "{}", output::human_summary(&o.label, &o.report));
        }
    };
    let (done, interrupted) = batch::run_all(
        jobs,
        plan,
        usize::from(concurrency),
        shared,
        cancel,
        on_done,
    )
    .await;

    let mut status = if interrupted && done.len() < total {
        Status::Failure
    } else {
        Status::Ok
    };

    let (mut ok, mut failed, mut inconclusive) = (0, 0, 0);

    for o in &done {
        match o.report.status() {
            Status::Ok => ok += 1,
            Status::Inconclusive => inconclusive += 1,
            _ => failed += 1,
        }

        status = status.worst(o.report.status());
    }

    let summary = output::BatchSummary {
        jobs: total,
        ok,
        failed,
        inconclusive,
        interrupted,
    };

    if json {
        let doc = output::BatchDoc {
            version: 1,
            jobs: done
                .iter()
                .map(|o| output::BatchJob {
                    label: &o.label,
                    results: &o.results,
                    summary: &o.report,
                })
                .collect(),
            summary,
        };

        if let Err(e) = output::write_batch_json(&doc)
            && e.kind() != std::io::ErrorKind::BrokenPipe
        {
            eprintln!("netprobe: failed to write output: {e}");
            return Status::Failure;
        }
    } else {
        println!(
            "=== batch: {} jobs, {} ok, {} failed, {} inconclusive{}",
            summary.jobs,
            summary.ok,
            summary.failed,
            summary.inconclusive,
            if interrupted {
                format!(" (interrupted, {} not run)", total - done.len())
            } else {
                String::new()
            }
        );
    }

    status
}
