//! Inspection of local certificate files (PEM bundles or a single DER certificate).

use std::path::Path;
use std::time::Instant;

use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;

use crate::cert;
use crate::check::{CheckResult, Policy, evaluate, now_unix};

/// Refuse files larger than this to keep memory bounded.
pub const MAX_FILE: u64 = 16 * 1024 * 1024;

pub fn read_certs(bytes: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    if bytes.windows(11).any(|w| w == b"-----BEGIN ") {
        let certs: Vec<Vec<u8>> = CertificateDer::pem_slice_iter(bytes)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("invalid PEM: {e}"))?
            .into_iter()
            .map(|c| c.as_ref().to_vec())
            .collect();

        if certs.is_empty() {
            return Err("no CERTIFICATE blocks found".into());
        }

        Ok(certs)
    } else {
        Ok(vec![bytes.to_vec()])
    }
}

pub fn inspect(path: &Path, policy: Policy) -> CheckResult {
    let start = Instant::now();
    let target = path.display().to_string();

    let bytes = match std::fs::metadata(path).and_then(|m| {
        if m.len() > MAX_FILE {
            Err(std::io::Error::other(format!(
                "file larger than {MAX_FILE} bytes"
            )))
        } else {
            std::fs::read(path)
        }
    }) {
        Ok(b) => b,
        Err(e) => return CheckResult::error(target, format!("cannot read file: {e}"), start),
    };

    let ders = match read_certs(&bytes) {
        Ok(d) => d,
        Err(e) => return CheckResult::error(target, e, start),
    };

    let now = now_unix();
    let mut chain = Vec::with_capacity(ders.len());

    for der in &ders {
        match cert::parse(der, now) {
            Ok(c) => chain.push(c),
            Err(e) => return CheckResult::error(target, e, start),
        }
    }

    let (verdict, problems, days_left, chain_days_left) = evaluate(&chain, None, policy);
    let mut r = CheckResult::error(target, String::new(), start);
    r.verdict = verdict;
    r.problems = problems;
    r.days_left = days_left;
    r.chain_days_left = chain_days_left;
    r.chain = chain;
    r
}
