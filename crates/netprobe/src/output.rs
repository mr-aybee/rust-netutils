//! Human and JSON rendering. Data goes to stdout, diagnostics to stderr.

use std::io::{self, Write};

use serde::Serialize;

use crate::probe::{Outcome, ProbeResult};
use crate::runner::Report;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verbosity {
    Quiet,
    Normal,
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

#[derive(Serialize)]
pub struct JsonDoc<'a> {
    pub version: u32,
    pub results: &'a [ProbeResult],
    pub summary: &'a Report,
}

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

#[derive(Serialize)]
pub struct BatchJob<'a> {
    pub label: &'a str,
    pub results: &'a [ProbeResult],
    pub summary: &'a Report,
}

#[derive(Serialize)]
pub struct BatchSummary {
    pub jobs: usize,
    pub ok: usize,
    pub failed: usize,
    pub inconclusive: usize,
    pub interrupted: bool,
}

#[derive(Serialize)]
pub struct BatchDoc<'a> {
    pub version: u32,
    pub jobs: Vec<BatchJob<'a>>,
    pub summary: BatchSummary,
}

pub fn write_batch_json(doc: &BatchDoc<'_>) -> io::Result<()> {
    let mut out = io::stdout().lock();
    serde_json::to_writer_pretty(&mut out, doc)?;
    writeln!(out)
}
