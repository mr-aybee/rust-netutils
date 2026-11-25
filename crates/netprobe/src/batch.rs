//! Batch mode: run many probes from a target file with bounded concurrency.
//!
//! File format (one job per line, `#` comments and blank lines ignored):
//! ```text
//! tcp  example.com:443
//! http https://example.com/health
//! dns  example.com AAAA
//! udp  10.0.0.5:53
//! icmp 10.0.0.1
//! ```

use crate::probe::{ProbeResult, dns, http, icmp, tcp, udp};
use crate::runner::{self, Plan, Report};
use crate::target::{Endpoint, parse_endpoint, validate_host};
use crate::url::{HttpUrl, parse_url};
use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::RecordType;
use rustls::ClientConfig;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinSet;

/// Upper bound on jobs per batch file, to keep memory predictable.
pub const MAX_JOBS: usize = 100_000;
pub const MAX_LINE: usize = 4096;

#[derive(Debug, Clone, PartialEq)]
pub enum Job {
    Tcp(Endpoint),
    Http(HttpUrl),
    Dns(String, RecordType),
    Udp(Endpoint),
    Icmp(String),
}

impl Job {
    pub fn label(&self) -> String {
        match self {
            Job::Tcp(e) => format!("tcp {e}"),
            Job::Http(u) => format!("http {}", u.display()),
            Job::Dns(n, t) => format!("dns {n} {t}"),
            Job::Udp(e) => format!("udp {e}"),
            Job::Icmp(h) => format!("icmp {h}"),
        }
    }
}

/// Parse a batch file. Errors carry the 1-based line number.
pub fn parse_jobs(text: &str) -> Result<Vec<Job>, String> {
    let mut jobs = Vec::new();

    for (i, raw) in text.lines().enumerate() {
        let n = i + 1;

        if raw.len() > MAX_LINE {
            return Err(format!("line {n}: longer than {MAX_LINE} bytes"));
        }

        let line = raw.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }

        let mut parts = line.split_whitespace();
        let kind = parts.next().unwrap_or_default();
        let arg = parts
            .next()
            .ok_or_else(|| format!("line {n}: missing target"))?;
        let extra = parts.next();
        let job = match (kind, extra) {
            ("tcp", None) => {
                Job::Tcp(parse_endpoint(arg, None).map_err(|e| format!("line {n}: {e}"))?)
            }
            ("udp", None) => {
                Job::Udp(parse_endpoint(arg, None).map_err(|e| format!("line {n}: {e}"))?)
            }
            ("http", None) => Job::Http(parse_url(arg).map_err(|e| format!("line {n}: {e}"))?),
            ("icmp", None) => {
                validate_host(arg).map_err(|e| format!("line {n}: invalid host '{arg}': {e}"))?;
                Job::Icmp(arg.to_string())
            }
            ("dns", t) => {
                validate_host(arg).map_err(|e| format!("line {n}: invalid name '{arg}': {e}"))?;
                let rt = dns::parse_record_type(t.unwrap_or("A"))
                    .map_err(|e| format!("line {n}: {e}"))?;

                if parts.next().is_some() {
                    return Err(format!("line {n}: too many fields"));
                }

                Job::Dns(arg.to_string(), rt)
            }
            ("tcp" | "udp" | "http" | "icmp", Some(_)) => {
                return Err(format!("line {n}: too many fields"));
            }
            (other, _) => {
                return Err(format!(
                    "line {n}: unknown probe '{other}' (expected tcp, http, dns, udp, icmp)"
                ));
            }
        };

        jobs.push(job);

        if jobs.len() > MAX_JOBS {
            return Err(format!("more than {MAX_JOBS} jobs"));
        }
    }

    if jobs.is_empty() {
        return Err("batch file contains no jobs".into());
    }

    Ok(jobs)
}

/// Shared, lazily built resources.
pub struct Shared {
    pub tls: Option<Arc<ClientConfig>>,
    pub resolver: Option<TokioResolver>,
}

impl Shared {
    pub fn for_jobs(
        jobs: &[Job],
        timeout: Duration,
        ca_file: Option<&std::path::Path>,
    ) -> Result<Self, String> {
        let tls = if jobs.iter().any(|j| matches!(j, Job::Http(u) if u.tls)) {
            Some(http::client_config(ca_file, false)?)
        } else {
            None
        };

        let resolver = if jobs.iter().any(|j| matches!(j, Job::Dns(..))) {
            Some(dns::build_resolver(None, timeout)?)
        } else {
            None
        };

        Ok(Self { tls, resolver })
    }
}

/// Outcome for one job.
pub struct JobOutcome {
    pub index: usize,
    pub label: String,
    pub results: Vec<ProbeResult>,
    pub report: Report,
}

async fn run_job(job: Job, plan: Plan, shared: Arc<Shared>) -> (String, Vec<ProbeResult>) {
    let label = job.label();
    let never = std::future::pending::<()>();
    let quiet = |_: &ProbeResult| {};

    let (results, _) = match &job {
        Job::Tcp(ep) => runner::run(plan, "tcp", &label, |s| tcp::probe(ep, s), never, quiet).await,
        Job::Udp(ep) => {
            let plan = Plan {
                grace: Duration::from_secs(1),
                ..plan
            };
            runner::run(
                plan,
                "udp",
                &label,
                |s| udp::probe(ep, &[], plan.timeout, s),
                never,
                quiet,
            )
            .await
        }
        Job::Http(u) => {
            let opts = http::HttpOptions {
                method: http::Method::Get,
                expect: Vec::new(),
            };
            runner::run(
                plan,
                "http",
                &label,
                |s| http::probe(u, shared.tls.as_ref(), &opts, s),
                never,
                quiet,
            )
            .await
        }
        Job::Dns(name, rt) => match &shared.resolver {
            Some(res) => {
                runner::run(
                    plan,
                    "dns",
                    &label,
                    |s| dns::probe(res, name, *rt, s),
                    never,
                    quiet,
                )
                .await
            }
            None => (
                vec![setup_failure("dns", &label, "resolver unavailable")],
                false,
            ),
        },
        Job::Icmp(host) => match icmp_setup(host).await {
            Ok((sock, ip)) => {
                let plan = Plan {
                    grace: Duration::from_secs(1),
                    ..plan
                };

                // Each job owns its socket, so concurrent jobs cannot consume each other's replies.
                let id = (std::process::id() & 0xffff) as u16;
                runner::run(
                    plan,
                    "icmp",
                    &label,
                    |s| icmp::probe(&sock, host, ip, id, plan.timeout, s),
                    never,
                    quiet,
                )
                .await
            }
            Err(e) => (vec![setup_failure("icmp", &label, &e)], false),
        },
    };

    (label, results)
}

async fn icmp_setup(host: &str) -> Result<(icmp::IcmpSocket, std::net::IpAddr), String> {
    let ip = icmp::resolve_ip(host)
        .await
        .map_err(|e| format!("cannot resolve: {e}"))?;
    Ok((icmp::IcmpSocket::open(ip.is_ipv6())?, ip))
}

fn setup_failure(kind: &'static str, label: &str, err: &str) -> ProbeResult {
    let target = label.strip_prefix(kind).map_or(label, str::trim_start);
    let mut r = ProbeResult::new(kind, target.to_string(), 1);
    r.error = Some(err.to_string());
    r
}

/// Run all jobs with at most `concurrency` in flight. `on_done` is called as
/// each job finishes. Returns outcomes in input order and whether it was interrupted.
pub async fn run_all<C>(
    jobs: Vec<Job>,
    plan: Plan,
    concurrency: usize,
    shared: Shared,
    cancel: C,
    mut on_done: impl FnMut(&JobOutcome),
) -> (Vec<JobOutcome>, bool)
where
    C: std::future::Future<Output = ()>,
{
    let shared = Arc::new(shared);
    let limit = concurrency.max(1);
    let total = jobs.len();
    let mut pending = jobs.into_iter().enumerate();
    let mut set = JoinSet::new();
    // Only `limit` tasks exist at any time; the next job is spawned when one finishes.
    let mut spawn_next = |set: &mut JoinSet<_>| {
        if let Some((index, job)) = pending.next() {
            let shared = Arc::clone(&shared);
            set.spawn(async move {
                let (label, results) = run_job(job, plan, shared).await;
                (index, label, results)
            });
        }
    };
    for _ in 0..limit {
        spawn_next(&mut set);
    }
    tokio::pin!(cancel);
    let mut done: Vec<JobOutcome> = Vec::with_capacity(total);
    let mut interrupted = false;
    loop {
        tokio::select! {
            next = set.join_next() => match next {
                None => break,
                Some(Ok((index, label, results))) => {
                    let report = Report::from_results(&results, false);
                    let o = JobOutcome { index, label, results, report };
                    on_done(&o);
                    done.push(o);
                    spawn_next(&mut set);
                }
                Some(Err(e)) => eprintln!("netprobe: internal task error: {e}"),
            },
            () = &mut cancel => {
                interrupted = true;
                set.abort_all();

                break;
            }
        }
    }
    done.sort_by_key(|o| o.index);
    (done, interrupted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_file() {
        let jobs = parse_jobs("# comment\n\ntcp example.com:443\nhttp https://x.org/ # trailing\ndns a.b aaaa\ndns c.d\nudp [::1]:53\nicmp 10.0.0.1\n").unwrap();
        assert_eq!(jobs.len(), 6);
        assert_eq!(jobs[2], Job::Dns("a.b".into(), RecordType::AAAA));
        assert_eq!(jobs[3], Job::Dns("c.d".into(), RecordType::A));
    }

    #[test]
    fn reports_line_numbers() {
        let e = parse_jobs("tcp a:1\nbogus x\n").unwrap_err();
        assert!(e.starts_with("line 2:"), "{e}");
        assert!(
            parse_jobs("tcp a:1 extra")
                .unwrap_err()
                .contains("too many")
        );
        assert!(parse_jobs("tcp").unwrap_err().contains("missing target"));
        assert!(parse_jobs("# only comments\n").is_err());
    }
}
