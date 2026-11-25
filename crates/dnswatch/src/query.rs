//! DNS querying with a canonical, TTL-independent view of answers.

use hickory_resolver::TokioResolver;
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RecordType;
use serde::Serialize;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

pub const SUPPORTED: &[&str] = &[
    "A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "PTR", "SRV", "CAA",
];

pub fn parse_type(s: &str) -> Result<RecordType, String> {
    let up = s.trim().to_ascii_uppercase();
    if !SUPPORTED.contains(&up.as_str()) {
        return Err(format!(
            "unsupported record type '{s}' (supported: {})",
            SUPPORTED.join(", ")
        ));
    }

    RecordType::from_str(&up).map_err(|e| e.to_string())
}

/// Outcome of one query. Only the first three are definitive states that can "change".
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", content = "records", rename_all = "lowercase")]
pub enum Answer {
    /// Records in canonical order, formatted `TYPE rdata` (TTL excluded).
    Records(Vec<String>),
    /// The name does not exist.
    Nxdomain,
    /// The name exists but has no records of this type.
    Nodata,
    /// Transient or unexpected failure (timeout, SERVFAIL, refused...).
    Error(String),
}

impl Answer {
    pub fn is_definitive(&self) -> bool {
        !matches!(self, Answer::Error(_))
    }

    pub fn summary(&self) -> String {
        match self {
            Answer::Records(r) if r.is_empty() => "(empty)".into(),
            Answer::Records(r) => r.join(", "),
            Answer::Nxdomain => "NXDOMAIN".into(),
            Answer::Nodata => "NODATA (no records of this type)".into(),
            Answer::Error(e) => format!("error: {e}"),
        }
    }

    /// Values of the requested type only (drops CNAMEs followed on the way).
    pub fn values_of(&self, rtype: RecordType) -> Vec<String> {
        let prefix = format!("{rtype} ");

        match self {
            Answer::Records(r) => r
                .iter()
                .filter_map(|x| x.strip_prefix(&prefix).map(str::to_string))
                .collect(),
            _ => Vec::new(),
        }
    }
}

/// Records added and removed between two record sets.
pub fn diff(old: &Answer, new: &Answer) -> (Vec<String>, Vec<String>) {
    let empty = Vec::new();

    let o = if let Answer::Records(r) = old {
        r
    } else {
        &empty
    };

    let n = if let Answer::Records(r) = new {
        r
    } else {
        &empty
    };

    let added = n.iter().filter(|x| !o.contains(x)).cloned().collect();
    let removed = o.iter().filter(|x| !n.contains(x)).cloned().collect();
    (added, removed)
}

/// A resolver to query and how it is labelled in output.
pub struct Source {
    pub label: String,
    pub resolver: TokioResolver,
}

pub fn build_source(server: Option<SocketAddr>, timeout: Duration) -> Result<Source, String> {
    let provider = TokioRuntimeProvider::default();

    let (label, mut builder) = match server {
        Some(addr) => {
            let mut ns = NameServerConfig::udp_and_tcp(addr.ip());
            for c in &mut ns.connections {
                c.port = addr.port();
            }

            let label = if addr.port() == 53 {
                addr.ip().to_string()
            } else {
                addr.to_string()
            };

            (
                label,
                TokioResolver::builder_with_config(
                    ResolverConfig::from_parts(None, vec![], vec![ns]),
                    provider,
                ),
            )
        }
        None => (
            "system".to_string(),
            TokioResolver::builder(provider)
                .map_err(|e| format!("cannot read system DNS configuration: {e}"))?,
        ),
    };

    let opts = builder.options_mut();
    opts.cache_size = 0;
    opts.attempts = 1;
    opts.timeout = timeout;
    let resolver = builder
        .build()
        .map_err(|e| format!("cannot build resolver: {e}"))?;
    Ok(Source { label, resolver })
}

pub async fn query(resolver: &TokioResolver, name: &str, rtype: RecordType) -> Answer {
    match resolver.lookup(name, rtype).await {
        Ok(lookup) => {
            let mut recs: Vec<String> = lookup
                .answers()
                .iter()
                .map(|r| format!("{} {}", r.record_type(), r.data))
                .collect();
            recs.sort_unstable();
            recs.dedup();

            if recs.is_empty() {
                Answer::Nodata
            } else {
                Answer::Records(recs)
            }
        }
        Err(e) if e.is_nx_domain() => Answer::Nxdomain,
        Err(e) if e.is_no_records_found() => Answer::Nodata,
        Err(e) => Answer::Error(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diffs() {
        let a = Answer::Records(vec!["A 1.1.1.1".into(), "A 2.2.2.2".into()]);
        let b = Answer::Records(vec!["A 2.2.2.2".into(), "A 3.3.3.3".into()]);
        assert_eq!(
            diff(&a, &b),
            (vec!["A 3.3.3.3".to_string()], vec!["A 1.1.1.1".to_string()])
        );
        assert_eq!(diff(&Answer::Nxdomain, &a).0.len(), 2);
    }

    #[test]
    fn values_filter_type() {
        let a = Answer::Records(vec!["A 1.2.3.4".into(), "CNAME x.example.".into()]);
        assert_eq!(a.values_of(RecordType::A), vec!["1.2.3.4"]);
        assert!(Answer::Nxdomain.values_of(RecordType::A).is_empty());
    }

    #[test]
    fn types() {
        assert_eq!(parse_type("aaaa"), Ok(RecordType::AAAA));
        assert!(parse_type("ANY").is_err());
    }

    #[test]
    fn json_shape() {
        let v = serde_json::to_value(Answer::Records(vec!["A 1.2.3.4".into()])).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"status": "records", "records": ["A 1.2.3.4"]})
        );
        assert_eq!(
            serde_json::to_value(Answer::Nxdomain).unwrap(),
            serde_json::json!({"status": "nxdomain"})
        );
    }
}
