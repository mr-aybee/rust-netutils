//! Human and JSON rendering. Data goes to stdout, diagnostics to stderr.

use std::io::{self, Write};

use serde::Serialize;

use crate::probe::{Outcome, ProbeResult};
use crate::runner::Report;

/// How much detail human output shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verbosity {
    /// Summary only.
    Quiet,
    /// One line per attempt.
    Normal,
    /// One line per attempt plus timing breakdown and DNS answers.
    Verbose,
}

/// Format one attempt as a single human-readable line.
pub fn human_line(r: &ProbeResult, verbosity: Verbosity) -> String {
    let mut line = format!("{} {} seq={} ", r.probe, r.target, r.seq);

    match r.outcome {
        Outcome::Ok => line.push_str(&format!("ok {:.2} ms", r.elapsed_ms)),
        Outcome::Failed => line.push_str("FAILED"),
        Outcome::Inconclusive => line.push_str("INCONCLUSIVE"),
    }

    match r.address {
        // ICMP has no port; show the bare IP.
        Some(a) if r.probe == "icmp" => line.push_str(&format!(" addr={}", a.ip())),
        Some(a) => line.push_str(&format!(" addr={a}")),
        None => {}
    }

    if let Some(d) = &r.detail {
        line.push_str(&format!(" {d}"));
    }

    if let Some(e) = &r.error {
        line.push_str(&format!(": {e}"));
    }

    if verbosity == Verbosity::Verbose {
        for a in &r.answers {
            line.push_str(&format!("\n    {a}"));
        }

        let t = &r.timings;
        let parts: Vec<String> = [
            ("dns", t.dns_ms),
            ("connect", t.connect_ms),
            ("tls", t.tls_ms),
            ("first_byte", t.first_byte_ms),
        ]
        .into_iter()
        .filter_map(|(n, v)| v.map(|v| format!("{n}={v:.2}ms")))
        .collect();

        if !parts.is_empty() {
            line.push_str(&format!(" [{}]", parts.join(" ")));
        }
    }

    line
}

/// Summary line(s) for a target: counts and, when available, latency statistics.
pub fn human_summary(target: &str, rep: &Report) -> String {
    let mut s = format!(
        "--- {target}: {} sent, {} ok, {} failed, {} inconclusive, {:.1}% failed{}",
        rep.sent,
        rep.ok,
        rep.failed,
        rep.inconclusive,
        rep.loss_pct,
        if rep.interrupted {
            " (interrupted)"
        } else {
            ""
        }
    );

    if let Some(l) = &rep.latency {
        s.push_str(&format!(
            "\nlatency min/avg/p50/p95/max/stddev = {:.2}/{:.2}/{:.2}/{:.2}/{:.2}/{:.2} ms",
            l.min_ms, l.avg_ms, l.p50_ms, l.p95_ms, l.max_ms, l.stddev_ms
        ));
    }

    s
}

/// JSON document for a single-target run.
#[derive(Serialize)]
pub struct JsonDoc<'a> {
    /// Schema version.
    pub version: u32,
    /// One result per attempt.
    pub results: &'a [ProbeResult],
    /// Aggregate over the attempts.
    pub summary: &'a Report,
}

/// Write the single-target JSON document to stdout.
pub fn write_json(results: &[ProbeResult], rep: &Report) -> io::Result<()> {
    let doc = JsonDoc {
        version: 1,
        results,
        summary: rep,
    };
    let mut out = io::stdout().lock();
    serde_json::to_writer_pretty(&mut out, &doc)?;
    writeln!(out)
}

/// One job in the batch JSON document.
#[derive(Serialize)]
pub struct BatchJob<'a> {
    /// Job label.
    pub label: &'a str,
    /// One result per attempt.
    pub results: &'a [ProbeResult],
    /// Aggregate over the attempts.
    pub summary: &'a Report,
}

/// Counts of batch jobs by status.
#[derive(Serialize)]
pub struct BatchSummary {
    /// Jobs in the batch file.
    pub jobs: usize,
    /// Jobs where every attempt succeeded.
    pub ok: usize,
    /// Jobs with at least one failed attempt.
    pub failed: usize,
    /// Jobs with inconclusive but no failed attempts.
    pub inconclusive: usize,
    /// Whether Ctrl+C stopped the batch early.
    pub interrupted: bool,
}

/// JSON document for a batch run.
#[derive(Serialize)]
pub struct BatchDoc<'a> {
    /// Schema version.
    pub version: u32,
    /// Jobs in input order.
    pub jobs: Vec<BatchJob<'a>>,
    /// Counts by status.
    pub summary: BatchSummary,
}

/// Write the batch JSON document to stdout.
pub fn write_batch_json(doc: &BatchDoc<'_>) -> io::Result<()> {
    let mut out = io::stdout().lock();
    serde_json::to_writer_pretty(&mut out, doc)?;
    writeln!(out)
}
