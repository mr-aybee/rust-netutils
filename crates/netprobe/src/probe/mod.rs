//! Probe result model shared by every protocol.

pub mod dns;
pub mod http;
pub mod icmp;
#[cfg(windows)]
mod icmp_windows;
pub mod tcp;
pub mod udp;

use serde::Serialize;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

/// Outcome of a single probe attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Ok,
    Failed,
    /// The probe ran but its result cannot be determined (e.g. UDP silence).
    Inconclusive,
}

/// Timing breakdown in milliseconds; absent phases are omitted.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Timings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connect_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_byte_ms: Option<f64>,
}

/// Result of one probe attempt.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProbeResult {
    pub probe: &'static str,
    pub target: String,
    pub seq: u32,
    pub outcome: Outcome,
    /// Total wall time of the attempt.
    pub elapsed_ms: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<SocketAddr>,
    #[serde(skip_serializing_if = "is_default")]
    pub timings: Timings,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Answer records (DNS) in canonical order.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub answers: Vec<String>,
}

fn is_default(t: &Timings) -> bool {
    *t == Timings::default()
}

impl ProbeResult {
    pub fn new(probe: &'static str, target: String, seq: u32) -> Self {
        Self {
            probe,
            target,
            seq,
            outcome: Outcome::Failed,
            elapsed_ms: 0.0,
            address: None,
            timings: Timings::default(),
            detail: None,
            error: None,
            answers: Vec::new(),
        }
    }
}

pub(crate) fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1_000.0
}

/// Map I/O errors to short, stable descriptions.
pub(crate) fn describe_io(e: &io::Error) -> String {
    match e.kind() {
        io::ErrorKind::ConnectionRefused => "connection refused".into(),
        io::ErrorKind::ConnectionReset => "connection reset".into(),
        io::ErrorKind::TimedOut => "timed out".into(),
        io::ErrorKind::PermissionDenied => "permission denied".into(),
        io::ErrorKind::HostUnreachable => "host unreachable".into(),
        io::ErrorKind::NetworkUnreachable => "network unreachable".into(),
        io::ErrorKind::AddrNotAvailable => "address not available".into(),
        _ => e.to_string(),
    }
}
