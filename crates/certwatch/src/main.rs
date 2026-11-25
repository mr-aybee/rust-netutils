//! CertWatch command-line entry point.

use std::io::Write;
use std::process::ExitCode;
use std::sync::Arc;

use certwatch::check::{self, CheckResult, Policy, Verdict};
use certwatch::cli::{Cli, Command, PolicyArgs};
use certwatch::output::{self, Summary};
use certwatch::{inspect, tls};
use clap::Parser;
use net_common::Status;
use net_common::target::{Endpoint, parse_endpoint};
use tokio::task::JoinSet;

/// Upper bound on targets per run.
const MAX_TARGETS: usize = 100_000;

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
            eprintln!("certwatch: failed to start runtime: {e}");
            return ExitCode::from(Status::Failure.code());
        }
    };

    ExitCode::from(rt.block_on(run(cli)).code())
}

fn policy(p: &PolicyArgs) -> Result<Policy, String> {
    if p.crit_days < 0 || p.warn_days < 0 {
        return Err("--warn-days and --crit-days must not be negative".into());
    }

    if p.crit_days > p.warn_days {
        return Err("--crit-days must not exceed --warn-days".into());
    }

    Ok(Policy {
        warn_days: p.warn_days,
        crit_days: p.crit_days,
    })
}

fn status_of(v: Verdict) -> Status {
    match v {
        Verdict::Ok => Status::Ok,
        Verdict::Warning => Status::Warning,
        Verdict::Critical | Verdict::Error => Status::Failure,
    }
}

fn usage(msg: impl std::fmt::Display) -> Status {
    eprintln!("certwatch: {msg}");
    Status::Usage
}

async fn run(cli: Cli) -> Status {
    let (json, quiet, verbose) = (cli.json, cli.quiet, cli.verbose);
    let print = move |r: &CheckResult| {
        if json || (quiet && r.verdict == Verdict::Ok) {
            return;
        }

        let _ = writeln!(std::io::stdout().lock(), "{}", output::human(r, verbose));
    };

    let (results, interrupted) = match cli.command {
        Command::Inspect { files, policy: p } => {
            let policy = match policy(&p) {
                Ok(p) => p,
                Err(e) => return usage(e),
            };

            let results: Vec<CheckResult> =
                files.iter().map(|f| inspect::inspect(f, policy)).collect();
            results.iter().for_each(print);
            (results, false)
        }
        Command::Check {
            targets,
            file,
            sni,
            ca_file,
            no_system_roots,
            timeout,
            concurrency,
            policy: p,
        } => {
            let policy = match policy(&p) {
                Ok(p) => p,
                Err(e) => return usage(e),
            };

            let endpoints = match collect_targets(targets, file.as_deref()) {
                Ok(e) => e,
                Err(e) => return usage(e),
            };

            if let Some(name) = &sni
                && rustls::pki_types::ServerName::try_from(name.as_str()).is_err()
            {
                return usage(format!("invalid --sni '{name}'"));
            }

            let verifier = match tls::webpki_verifier(ca_file.as_deref(), !no_system_roots) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("certwatch: {e}");
                    return Status::Failure;
                }
            };

            run_checks(
                endpoints,
                sni,
                verifier,
                policy,
                timeout,
                usize::from(concurrency),
                print,
            )
            .await
        }
    };

    let summary = Summary::from(&results, interrupted);

    if json {
        if let Err(e) = output::write_json(&results, &summary)
            && e.kind() != std::io::ErrorKind::BrokenPipe
        {
            eprintln!("certwatch: failed to write output: {e}");
            return Status::Failure;
        }
    } else if results.len() > 1 || quiet || interrupted {
        println!("{}", summary.line());
    }

    let mut status = if interrupted {
        Status::Failure
    } else {
        Status::Ok
    };

    for r in &results {
        status = status.worst(status_of(r.verdict));
    }

    status
}

fn collect_targets(
    mut args: Vec<String>,
    file: Option<&std::path::Path>,
) -> Result<Vec<Endpoint>, String> {
    if let Some(path) = file {
        let text = if path.as_os_str() == "-" {
            let mut s = String::new();
            std::io::Read::read_to_string(
                &mut std::io::Read::take(std::io::stdin(), 64 * 1024 * 1024),
                &mut s,
            )
            .map_err(|e| format!("cannot read stdin: {e}"))?;
            s
        } else {
            std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?
        };

        args.extend(
            text.lines()
                .map(|l| l.split('#').next().unwrap_or_default().trim().to_string())
                .filter(|l| !l.is_empty()),
        );
    }

    if args.is_empty() {
        return Err("no targets given (pass HOST[:PORT] or --file)".into());
    }

    if args.len() > MAX_TARGETS {
        return Err(format!("more than {MAX_TARGETS} targets"));
    }

    args.iter().map(|t| parse_endpoint(t, Some(443))).collect()
}

async fn run_checks(
    endpoints: Vec<Endpoint>,
    sni: Option<String>,
    verifier: Arc<rustls::client::WebPkiServerVerifier>,
    policy: Policy,
    timeout: std::time::Duration,
    concurrency: usize,
    mut on_done: impl FnMut(&CheckResult),
) -> (Vec<CheckResult>, bool) {
    let total = endpoints.len();
    let sni: Option<Arc<str>> = sni.map(Arc::from);
    let mut pending = endpoints.into_iter().enumerate();
    let mut set = JoinSet::new();
    let mut spawn_next = |set: &mut JoinSet<(usize, CheckResult)>| {
        if let Some((i, ep)) = pending.next() {
            let (verifier, sni) = (Arc::clone(&verifier), sni.clone());
            set.spawn(async move {
                (
                    i,
                    check::check(&ep, sni.as_deref(), &verifier, policy, timeout).await,
                )
            });
        }
    };

    for _ in 0..concurrency.max(1) {
        spawn_next(&mut set);
    }

    let cancel = tokio::signal::ctrl_c();
    tokio::pin!(cancel);
    let mut done: Vec<(usize, CheckResult)> = Vec::with_capacity(total);
    let mut interrupted = false;

    loop {
        tokio::select! {
            next = set.join_next() => match next {
                None => break,
                Some(Ok((i, r))) => {
                    on_done(&r);
                    done.push((i, r));
                    spawn_next(&mut set);
                }
                Some(Err(e)) => eprintln!("certwatch: internal task error: {e}"),
            },
            _ = &mut cancel => {
                interrupted = true;
                set.abort_all();

                break;
            }
        }
    }

    done.sort_by_key(|(i, _)| *i);
    (done.into_iter().map(|(_, r)| r).collect(), interrupted)
}
