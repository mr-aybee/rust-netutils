//! Remote certificate check: connect, handshake, evaluate policy.

use crate::cert::{self, CertInfo};
use crate::tls::{RecordingVerifier, classify};
use net_common::target::Endpoint;
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::ServerName;
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpStream, lookup_host};

/// Overall verdict for one target, ordered by severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Ok,
    Warning,
    Critical,
    Error,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Ok => "OK",
            Verdict::Warning => "WARNING",
            Verdict::Critical => "CRITICAL",
            Verdict::Error => "ERROR",
        }
    }
}

/// Expiry thresholds in days.
#[derive(Debug, Clone, Copy)]
pub struct Policy {
    pub warn_days: i64,
    pub crit_days: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    pub target: String,
    pub verdict: Verdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<SocketAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_version: Option<String>,
    /// Chain validation passed (trust, hostname, validity period). Absent for local files.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trusted: Option<bool>,
    /// Category of the validation failure (`expired`, `hostname_mismatch`, `untrusted`, ...).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_error_kind: Option<&'static str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub problems: Vec<String>,
    /// Days until the leaf certificate expires.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub days_left: Option<i64>,
    /// Days until the first certificate in the presented chain expires.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_days_left: Option<i64>,
    /// Presented chain, leaf first.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub chain: Vec<CertInfo>,
    pub elapsed_ms: f64,
}

impl CheckResult {
    pub fn error(target: String, msg: String, start: Instant) -> Self {
        Self {
            target,
            verdict: Verdict::Error,
            address: None,
            sni: None,
            tls_version: None,
            trusted: None,
            validation_error_kind: None,
            problems: vec![msg],
            days_left: None,
            chain_days_left: None,
            chain: Vec::new(),
            elapsed_ms: start.elapsed().as_secs_f64() * 1000.0,
        }
    }
}

pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Apply expiry thresholds and validation outcome to a parsed chain.
pub fn evaluate(
    chain: &[CertInfo],
    validation: Option<(&'static str, String)>,
    policy: Policy,
) -> (Verdict, Vec<String>, Option<i64>, Option<i64>) {
    let mut problems = Vec::new();
    let mut verdict = Verdict::Ok;
    let leaf_days = chain.first().map(|c| c.days_left);

    // The root is not normally sent; if a self-signed CA is in the chain, ignore it for expiry.
    let chain_days = chain
        .iter()
        .filter(|c| !(c.is_ca && c.self_signed))
        .map(|c| c.days_left)
        .min();

    if let Some((_, msg)) = &validation {
        problems.push(msg.clone());
        verdict = verdict.max(Verdict::Critical);
    }

    if let Some(days) = chain_days {
        let which = if chain_days == leaf_days {
            "certificate"
        } else {
            "a certificate in the chain"
        };

        if days < 0 {
            problems.push(format!("{which} expired {} day(s) ago", -days));
            verdict = verdict.max(Verdict::Critical);
        } else if days <= policy.crit_days {
            problems.push(format!(
                "{which} expires in {days} day(s) (critical threshold {} days)",
                policy.crit_days
            ));
            verdict = verdict.max(Verdict::Critical);
        } else if days <= policy.warn_days {
            problems.push(format!(
                "{which} expires in {days} day(s) (warning threshold {} days)",
                policy.warn_days
            ));
            verdict = verdict.max(Verdict::Warning);
        }
    }

    if let Some(leaf) = chain.first() {
        problems.extend(cert::weaknesses(leaf));
    }

    // Problems are deduplicated so an expired leaf is not reported twice.
    problems.dedup();
    (verdict, problems, leaf_days, chain_days)
}

/// Resolve, connect and handshake; then evaluate. `deadline` covers the whole check.
pub async fn check(
    ep: &Endpoint,
    sni: Option<&str>,
    verifier: &Arc<WebPkiServerVerifier>,
    policy: Policy,
    deadline: Duration,
) -> CheckResult {
    let start = Instant::now();
    let target = ep.to_string();

    match tokio::time::timeout(deadline, check_inner(ep, sni, verifier, policy, start)).await {
        Ok(r) => r,
        Err(_) => CheckResult::error(
            target,
            format!("timed out after {}", fmt_dur(deadline)),
            start,
        ),
    }
}

fn fmt_dur(d: Duration) -> String {
    if d.subsec_nanos() == 0 {
        format!("{}s", d.as_secs())
    } else {
        format!("{}ms", d.as_millis())
    }
}

async fn check_inner(
    ep: &Endpoint,
    sni: Option<&str>,
    verifier: &Arc<WebPkiServerVerifier>,
    policy: Policy,
    start: Instant,
) -> CheckResult {
    let target = ep.to_string();

    let addrs: Vec<SocketAddr> = match lookup_host((ep.host.as_str(), ep.port)).await {
        Ok(a) => a.collect(),
        Err(e) => return CheckResult::error(target, format!("resolve failed: {e}"), start),
    };

    let mut last_err = None;
    let mut conn = None;

    for addr in &addrs {
        match TcpStream::connect(addr).await {
            Ok(s) => {
                conn = Some((s, *addr));
                break;
            }
            Err(e) => last_err = Some(e),
        }
    }

    let Some((stream, addr)) = conn else {
        let msg = last_err.map_or_else(
            || "no addresses found".to_string(),
            |e| format!("connect failed: {e}"),
        );
        return CheckResult::error(target, msg, start);
    };

    let name_str = sni.unwrap_or(&ep.host).to_string();
    let server_name = match ServerName::try_from(name_str.clone()) {
        Ok(n) => n,
        Err(e) => {
            return CheckResult::error(
                target,
                format!("invalid server name '{name_str}': {e}"),
                start,
            );
        }
    };

    let recorder = RecordingVerifier::new(Arc::clone(verifier));
    let config = match recorder.client_config() {
        Ok(c) => c,
        Err(e) => return CheckResult::error(target, e, start),
    };

    let tls = match tokio_rustls::TlsConnector::from(config)
        .connect(server_name, stream)
        .await
    {
        Ok(t) => t,
        Err(e) => {
            let mut r = CheckResult::error(target, format!("TLS handshake failed: {e}"), start);
            r.address = Some(addr);
            r.sni = Some(name_str);

            return r;
        }
    };

    let (_, session) = tls.get_ref();
    let tls_version = session
        .protocol_version()
        .map(|v| format!("{v:?}").replace("TLSv1_", "TLS 1."));
    let now = now_unix();
    let mut chain = Vec::new();
    let mut parse_errors = Vec::new();

    for der in session.peer_certificates().unwrap_or_default() {
        match cert::parse(der, now) {
            Ok(c) => chain.push(c),
            Err(e) => parse_errors.push(e),
        }
    }

    // Close without sending application data.
    drop(tls);

    let validation = match recorder.verdict() {
        Some(Ok(())) => None,
        Some(Err(e)) => Some(classify(&e)),
        None => Some(("invalid", "server presented no certificate".to_string())),
    };

    let kind = validation.as_ref().map(|(k, _)| *k);
    let (verdict, mut problems, days_left, chain_days_left) = evaluate(&chain, validation, policy);
    problems.extend(parse_errors);
    CheckResult {
        target,
        verdict,
        address: Some(addr),
        sni: Some(name_str),
        tls_version,
        trusted: Some(kind.is_none()),
        validation_error_kind: kind,
        problems,
        days_left,
        chain_days_left,
        chain,
        elapsed_ms: start.elapsed().as_secs_f64() * 1000.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(days: i64, ca: bool, self_signed: bool) -> CertInfo {
        CertInfo {
            subject: "CN=x".into(),
            issuer: "CN=y".into(),
            sans: vec![],
            serial: "01".into(),
            not_before: String::new(),
            not_after: String::new(),
            not_after_unix: 0,
            not_before_unix: 0,
            days_left: days,
            key: "EC 256".into(),
            signature_algorithm: "ecdsa-with-SHA256".into(),
            is_ca: ca,
            self_signed,
            sha256_fingerprint: String::new(),
        }
    }

    const P: Policy = Policy {
        warn_days: 30,
        crit_days: 7,
    };

    #[test]
    fn thresholds() {
        assert_eq!(evaluate(&[info(90, false, false)], None, P).0, Verdict::Ok);
        assert_eq!(
            evaluate(&[info(30, false, false)], None, P).0,
            Verdict::Warning
        );
        assert_eq!(
            evaluate(&[info(7, false, false)], None, P).0,
            Verdict::Critical
        );
        assert_eq!(
            evaluate(&[info(-1, false, false)], None, P).0,
            Verdict::Critical
        );
    }

    #[test]
    fn intermediate_expiry_counts_but_root_does_not() {
        let (v, p, leaf, chain) =
            evaluate(&[info(90, false, false), info(10, true, false)], None, P);
        assert_eq!((v, leaf, chain), (Verdict::Warning, Some(90), Some(10)));
        assert!(p[0].contains("in the chain"));
        let (v, ..) = evaluate(&[info(90, false, false), info(1, true, true)], None, P);
        assert_eq!(v, Verdict::Ok);
    }

    #[test]
    fn validation_failure_is_critical() {
        let (v, p, ..) = evaluate(
            &[info(90, false, false)],
            Some(("untrusted", "untrusted: x".into())),
            P,
        );
        assert_eq!(v, Verdict::Critical);
        assert_eq!(p, vec!["untrusted: x".to_string()]);
    }
}
