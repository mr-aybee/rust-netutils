//! Human and JSON rendering.

use std::io::{self, Write};

use serde::Serialize;

use crate::check::{CheckResult, Verdict};

fn expiry_text(r: &CheckResult) -> Option<String> {
    let leaf = r.chain.first()?;
    let date = &leaf.not_after[..10];
    Some(match leaf.days_left {
        d if d < 0 => format!("expired {} day(s) ago ({date})", -d),
        d => format!("expires in {d} day(s) ({date})"),
    })
}

/// Format one result (and, if `verbose`, its full chain) for the terminal.
pub fn human(r: &CheckResult, verbose: bool) -> String {
    let mut s = format!("{:<8} {}", r.verdict.label(), r.target);

    if let Some(e) = expiry_text(r) {
        s.push_str(&format!("  {e}"));
    }

    if let Some(leaf) = r.chain.first() {
        s.push_str(&format!("  subject: {}", leaf.subject));
    }

    if let Some(v) = &r.tls_version {
        s.push_str(&format!("  {v}"));
    }

    for p in r.problems.iter().filter(|p| !p.is_empty()) {
        s.push_str(&format!("\n         ! {p}"));
    }

    if verbose {
        if let Some(sni) = &r.sni {
            s.push_str(&format!(
                "\n         sni={sni} addr={}",
                r.address.map(|a| a.to_string()).unwrap_or_default()
            ));
        }

        for (i, c) in r.chain.iter().enumerate() {
            s.push_str(&format!(
                "\n         [{i}] {}\n             issuer:  {}\n             valid:   {} .. {} ({} days left)\n             key:     {}  sig: {}\n             sha256:  {}",
                c.subject, c.issuer, c.not_before, c.not_after, c.days_left, c.key, c.signature_algorithm, c.sha256_fingerprint
            ));

            if !c.sans.is_empty() {
                s.push_str(&format!("\n             SANs:    {}", c.sans.join(", ")));
            }
        }
    }

    s
}

/// Counts of results by verdict.
#[derive(Debug, Default, Serialize)]
pub struct Summary {
    /// Targets checked.
    pub total: usize,
    /// Results with verdict `ok`.
    pub ok: usize,
    /// Results with verdict `warning`.
    pub warning: usize,
    /// Results with verdict `critical`.
    pub critical: usize,
    /// Results with verdict `error`.
    pub error: usize,
    /// Whether Ctrl+C stopped the run early.
    pub interrupted: bool,
}

impl Summary {
    /// Count verdicts in `results`.
    pub fn from(results: &[CheckResult], interrupted: bool) -> Self {
        let count = |v| results.iter().filter(|r| r.verdict == v).count();
        Summary {
            total: results.len(),
            ok: count(Verdict::Ok),
            warning: count(Verdict::Warning),
            critical: count(Verdict::Critical),
            error: count(Verdict::Error),
            interrupted,
        }
    }

    /// One-line human summary.
    pub fn line(&self) -> String {
        format!(
            "--- {} checked: {} ok, {} warning, {} critical, {} error{}",
            self.total,
            self.ok,
            self.warning,
            self.critical,
            self.error,
            if self.interrupted {
                " (interrupted)"
            } else {
                ""
            }
        )
    }
}

#[derive(Serialize)]
struct Doc<'a> {
    version: u32,
    results: &'a [CheckResult],
    summary: &'a Summary,
}

/// Write the JSON document (`version`, `results`, `summary`) to stdout.
pub fn write_json(results: &[CheckResult], summary: &Summary) -> io::Result<()> {
    let mut out = io::stdout().lock();
    serde_json::to_writer_pretty(
        &mut out,
        &Doc {
            version: 1,
            results,
            summary,
        },
    )?;
    writeln!(out)
}
