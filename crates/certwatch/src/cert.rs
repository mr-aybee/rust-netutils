//! X.509 certificate summary extracted from DER.

use serde::Serialize;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::public_key::PublicKey;

const SECS_PER_DAY: i64 = 86_400;

/// Human- and machine-friendly view of one certificate.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    /// DNS names and IP addresses from the Subject Alternative Name extension.
    pub sans: Vec<String>,
    pub serial: String,
    pub not_before: String,
    pub not_after: String,
    /// Unix seconds; kept for computation, omitted from JSON.
    #[serde(skip)]
    pub not_after_unix: i64,
    #[serde(skip)]
    pub not_before_unix: i64,
    /// Whole days until expiry (negative once expired).
    pub days_left: i64,
    pub key: String,
    pub signature_algorithm: String,
    pub is_ca: bool,
    pub self_signed: bool,
    pub sha256_fingerprint: String,
}

/// Parse a DER certificate. `now` is Unix seconds.
pub fn parse(der: &[u8], now: i64) -> Result<CertInfo, String> {
    let (_, cert) =
        X509Certificate::from_der(der).map_err(|e| format!("invalid certificate: {e}"))?;
    let validity = cert.validity();
    let not_after_unix = validity.not_after.timestamp();
    let not_before_unix = validity.not_before.timestamp();
    let mut sans = Vec::new();
    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        for name in &ext.value.general_names {
            match name {
                GeneralName::DNSName(d) => sans.push((*d).to_string()),
                GeneralName::IPAddress(b) => sans.push(ip_from_bytes(b)),
                _ => {}
            }
        }
    }
    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    Ok(CertInfo {
        self_signed: subject == issuer,
        subject,
        issuer,
        sans,
        serial: cert.raw_serial_as_string(),
        not_before: iso8601(not_before_unix),
        not_after: iso8601(not_after_unix),
        not_after_unix,
        not_before_unix,
        days_left: days_until(not_after_unix, now),
        key: describe_key(&cert),
        signature_algorithm: signature_name(&cert.signature_algorithm.algorithm.to_id_string()),
        is_ca: cert.is_ca(),
        sha256_fingerprint: fingerprint(der),
    })
}

/// Whole days from `now` until `ts`, rounded toward negative infinity.
pub fn days_until(ts: i64, now: i64) -> i64 {
    (ts - now).div_euclid(SECS_PER_DAY)
}

fn ip_from_bytes(b: &[u8]) -> String {
    match b.len() {
        4 => std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string(),
        16 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(b);
            std::net::Ipv6Addr::from(a).to_string()
        }
        _ => format!("<invalid IP of {} bytes>", b.len()),
    }
}

fn describe_key(cert: &X509Certificate<'_>) -> String {
    let spki = cert.public_key();
    match spki.parsed() {
        Ok(PublicKey::RSA(k)) => format!("RSA {}", k.key_size()),
        Ok(PublicKey::EC(p)) => format!("EC {}", p.key_size()),
        _ => match spki.algorithm.algorithm.to_id_string().as_str() {
            "1.3.101.112" => "Ed25519".into(),
            "1.3.101.113" => "Ed448".into(),
            other => format!("unknown ({other})"),
        },
    }
}

/// Map common signature algorithm OIDs to names.
pub fn signature_name(oid: &str) -> String {
    match oid {
        "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption",
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption",
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption",
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption",
        "1.2.840.113549.1.1.10" => "RSASSA-PSS",
        "1.2.840.10045.4.1" => "ecdsa-with-SHA1",
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256",
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384",
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512",
        "1.3.101.112" => "Ed25519",
        other => return other.to_string(),
    }
    .to_string()
}

pub fn fingerprint(der: &[u8]) -> String {
    let d = ring::digest::digest(&ring::digest::SHA256, der);
    let mut s = String::with_capacity(95);
    for (i, b) in d.as_ref().iter().enumerate() {
        if i > 0 {
            s.push(':');
        }
        s.push_str(&format!("{b:02X}"));
    }
    s
}

pub use net_common::time::iso8601;

/// Problems worth flagging regardless of trust status.
pub fn weaknesses(c: &CertInfo) -> Vec<String> {
    let mut out = Vec::new();
    // A self-signed certificate's own signature is never verified, so its algorithm is irrelevant.
    if !c.self_signed
        && (c.signature_algorithm.contains("sha1") || c.signature_algorithm.contains("SHA1"))
    {
        out.push(format!(
            "weak signature algorithm {}",
            c.signature_algorithm
        ));
    }
    if let Some(bits) = c
        .key
        .strip_prefix("RSA ")
        .and_then(|b| b.parse::<u32>().ok())
        && bits < 2048
    {
        out.push(format!("weak RSA key ({bits} bits)"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(iso8601(1_428_883_199), "2015-04-12T23:59:59Z");
        assert_eq!(iso8601(-1), "1969-12-31T23:59:59Z");
        assert_eq!(iso8601(4_102_444_800), "2100-01-01T00:00:00Z");
    }

    #[test]
    fn day_rounding() {
        assert_eq!(days_until(86_400 * 3, 0), 3);
        assert_eq!(days_until(86_400 * 3 - 1, 0), 2);
        assert_eq!(days_until(0, 1), -1);
    }

    #[test]
    fn parses_generated_cert() {
        let mut params =
            rcgen::CertificateParams::new(vec!["example.test".to_string(), "10.0.0.1".to_string()])
                .unwrap();
        params.not_after = rcgen::date_time_ymd(2030, 1, 1);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let now = 1_893_456_000 - 10 * 86_400; // 2030-01-01 minus 10 days
        let info = parse(cert.der(), now).unwrap();
        assert_eq!(info.sans, vec!["example.test", "10.0.0.1"]);
        assert_eq!(info.not_after, "2030-01-01T00:00:00Z");
        assert_eq!(info.days_left, 10);
        assert_eq!(info.key, "EC 256");
        assert_eq!(info.signature_algorithm, "ecdsa-with-SHA256");
        assert!(info.self_signed);
        assert_eq!(info.sha256_fingerprint.len(), 95);
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse(b"not a certificate", 0).is_err());
    }

    proptest::proptest! {
        #[test]
        fn iso_never_panics(ts in 0i64..253_402_300_800) {
            let s = iso8601(ts);
            proptest::prop_assert_eq!(s.len(), 20);
        }

        #[test]
        fn parse_never_panics(b in proptest::collection::vec(proptest::num::u8::ANY, 0..300)) {
            let _ = parse(&b, 0);
        }
    }
}
