//! DNS probe using hickory-resolver with caching disabled so every attempt
//! performs a real query.

use super::{Outcome, ProbeResult, ms};
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::net::NetError;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RecordType;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::{Duration, Instant};

/// Record types supported by the probe.
pub const SUPPORTED: &[&str] = &[
    "A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "PTR", "SRV", "CAA",
];

/// Parse a record type name (case-insensitive) from the supported set.
pub fn parse_record_type(s: &str) -> Result<RecordType, String> {
    let up = s.to_ascii_uppercase();
    if !SUPPORTED.contains(&up.as_str()) {
        return Err(format!(
            "unsupported record type '{s}' (supported: {})",
            SUPPORTED.join(", ")
        ));
    }
    RecordType::from_str(&up).map_err(|e| e.to_string())
}

/// Build a resolver. `server` overrides the system configuration.
pub fn build_resolver(
    server: Option<SocketAddr>,
    timeout: Duration,
) -> Result<TokioResolver, String> {
    let provider = TokioRuntimeProvider::default();
    let mut builder = match server {
        Some(addr) => {
            let mut ns = NameServerConfig::udp_and_tcp(addr.ip());
            for conn in &mut ns.connections {
                conn.port = addr.port();
            }
            TokioResolver::builder_with_config(
                ResolverConfig::from_parts(None, vec![], vec![ns]),
                provider,
            )
        }
        None => TokioResolver::builder(provider)
            .map_err(|e| format!("cannot read system DNS configuration: {e}"))?,
    };
    let opts: &mut ResolverOpts = builder.options_mut();
    opts.cache_size = 0;
    opts.attempts = 1;
    opts.timeout = timeout;
    builder
        .build()
        .map_err(|e| format!("cannot build DNS resolver: {e}"))
}

fn describe(e: &NetError) -> String {
    if e.is_nx_domain() {
        "NXDOMAIN (name does not exist)".into()
    } else if e.is_no_records_found() {
        "no records of the requested type".into()
    } else {
        e.to_string()
    }
}

pub async fn probe(
    resolver: &TokioResolver,
    name: &str,
    rtype: RecordType,
    seq: u32,
) -> ProbeResult {
    let mut r = ProbeResult::new("dns", format!("{name} {rtype}"), seq);
    let start = Instant::now();
    match resolver.lookup(name, rtype).await {
        Ok(lookup) => {
            let mut answers: Vec<String> = lookup
                .answers()
                .iter()
                .map(|rec| format!("{} {} {}", rec.record_type(), rec.ttl, rec.data))
                .collect();
            // Canonical order so repeated runs and diffs are stable.
            answers.sort_unstable();
            r.outcome = Outcome::Ok;
            r.detail = Some(format!("{} answer(s)", answers.len()));
            r.answers = answers;
        }
        Err(e) => r.error = Some(describe(&e)),
    }
    r.elapsed_ms = ms(start.elapsed());
    r.timings.dns_ms = Some(r.elapsed_ms);
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_types() {
        assert_eq!(parse_record_type("aaaa"), Ok(RecordType::AAAA));
        assert_eq!(parse_record_type("MX"), Ok(RecordType::MX));
        assert!(parse_record_type("ANY").is_err());
        assert!(parse_record_type("bogus").is_err());
    }
}
