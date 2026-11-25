//! Repetition, deadlines, pacing and cancellation for probes.

use crate::probe::{Outcome, ProbeResult, ms};
use crate::stats::{Summary, summarize};
use net_common::Status;
use serde::Serialize;
use std::future::Future;
use std::time::Duration;

/// How many attempts to make and how to pace them.
#[derive(Debug, Clone, Copy)]
pub struct Plan {
    pub count: u32,
    pub interval: Duration,
    pub timeout: Duration,
    /// Extra time beyond `timeout` before the runner aborts an attempt. Probes that
    /// enforce `timeout` themselves (UDP) use a margin so their own result wins.
    pub grace: Duration,
}

/// Aggregate over all attempts for one target.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub sent: u32,
    pub ok: u32,
    pub failed: u32,
    pub inconclusive: u32,
    pub loss_pct: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency: Option<Summary>,
    pub interrupted: bool,
}

impl Report {
    pub fn from_results(results: &[ProbeResult], interrupted: bool) -> Self {
        let count = |o| results.iter().filter(|r| r.outcome == o).count() as u32;
        let (ok, failed, inconclusive) = (
            count(Outcome::Ok),
            count(Outcome::Failed),
            count(Outcome::Inconclusive),
        );
        let sent = results.len() as u32;
        let mut samples: Vec<f64> = results
            .iter()
            .filter(|r| r.outcome == Outcome::Ok)
            .map(|r| r.elapsed_ms)
            .collect();
        Report {
            sent,
            ok,
            failed,
            inconclusive,
            loss_pct: if sent == 0 {
                0.0
            } else {
                f64::from(failed) * 100.0 / f64::from(sent)
            },
            latency: summarize(&mut samples),
            interrupted,
        }
    }

    /// Exit status for this report. An interrupted run with no results is a failure.
    pub fn status(&self) -> Status {
        if self.sent == 0 {
            return Status::Failure;
        }

        let mut s = Status::Ok;

        if self.inconclusive > 0 {
            s = s.worst(Status::Inconclusive);
        }

        if self.failed > 0 {
            s = s.worst(Status::Failure);
        }

        s
    }
}

/// Apply the per-attempt deadline. On expiry a `Failed` result with "timed out" is produced.
pub async fn with_deadline<F>(
    timeout: Duration,
    kind: &'static str,
    target: &str,
    seq: u32,
    fut: F,
) -> ProbeResult
where
    F: Future<Output = ProbeResult>,
{
    match tokio::time::timeout(timeout, fut).await {
        Ok(r) => r,
        Err(_) => {
            let mut r = ProbeResult::new(kind, target.to_string(), seq);
            r.error = Some(format!("timed out after {}", fmt_duration(timeout)));
            r.elapsed_ms = ms(timeout);
            r
        }
    }
}

fn fmt_duration(d: Duration) -> String {
    if d.subsec_nanos() == 0 {
        format!("{}s", d.as_secs())
    } else {
        format!("{}ms", d.as_millis())
    }
}

/// Run `make(seq)` `plan.count` times, pacing by `plan.interval`, until done or `cancel` resolves.
/// `on_result` is invoked as each attempt completes (for streaming output).
pub async fn run<M, F, C>(
    plan: Plan,
    kind: &'static str,
    target: &str,
    mut make: M,
    cancel: C,
    mut on_result: impl FnMut(&ProbeResult),
) -> (Vec<ProbeResult>, bool)
where
    M: FnMut(u32) -> F,
    F: Future<Output = ProbeResult>,
    C: Future<Output = ()>,
{
    tokio::pin!(cancel);
    let mut results = Vec::with_capacity(plan.count.min(4096) as usize);
    for seq in 1..=plan.count {
        let attempt = with_deadline(plan.timeout + plan.grace, kind, target, seq, make(seq));
        tokio::select! {
            r = attempt => { on_result(&r); results.push(r); }
            () = &mut cancel => return (results, true),
        }

        if seq < plan.count {
            tokio::select! {
                () = tokio::time::sleep(plan.interval) => {}
                () = &mut cancel => return (results, true),
            }
        }
    }
    (results, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn res(o: Outcome, ms: f64) -> ProbeResult {
        let mut r = ProbeResult::new("t", "x".into(), 1);
        r.outcome = o;
        r.elapsed_ms = ms;
        r
    }

    #[test]
    fn status_rules() {
        assert_eq!(Report::from_results(&[], true).status(), Status::Failure);
        assert_eq!(
            Report::from_results(&[res(Outcome::Ok, 1.0)], false).status(),
            Status::Ok
        );
        assert_eq!(
            Report::from_results(
                &[res(Outcome::Ok, 1.0), res(Outcome::Inconclusive, 0.0)],
                false
            )
            .status(),
            Status::Inconclusive
        );
        assert_eq!(
            Report::from_results(
                &[res(Outcome::Failed, 1.0), res(Outcome::Inconclusive, 0.0)],
                false
            )
            .status(),
            Status::Failure
        );
    }

    #[test]
    fn loss_and_latency_only_from_ok() {
        let r = Report::from_results(
            &[res(Outcome::Ok, 10.0), res(Outcome::Failed, 3000.0)],
            false,
        );
        assert_eq!(r.loss_pct, 50.0);
        assert_eq!(r.latency.unwrap().max_ms, 10.0);
    }

    #[tokio::test]
    async fn deadline_produces_timeout() {
        let r = with_deadline(Duration::from_millis(20), "t", "x", 1, async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            res(Outcome::Ok, 0.0)
        })
        .await;
        assert_eq!(r.outcome, Outcome::Failed);
        assert!(r.error.unwrap().contains("timed out"));
    }

    #[tokio::test]
    async fn cancel_stops_run() {
        let plan = Plan {
            count: 100,
            interval: Duration::from_secs(10),
            timeout: Duration::from_secs(1),
            grace: Duration::ZERO,
        };
        let (results, interrupted) = run(
            plan,
            "t",
            "x",
            |_| async { res(Outcome::Ok, 1.0) },
            tokio::time::sleep(Duration::from_millis(50)),
            |_| {},
        )
        .await;
        assert!(interrupted);
        assert_eq!(results.len(), 1);
    }
}
