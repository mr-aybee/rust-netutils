//! TCP connect probe: resolve, then attempt each address until one connects.

use std::net::SocketAddr;
use std::time::Instant;

use tokio::net::{TcpStream, lookup_host};

use super::{ProbeResult, describe_io, ms};
use crate::target::Endpoint;

/// Resolve an endpoint using the system resolver.
pub(crate) async fn resolve(ep: &Endpoint) -> std::io::Result<Vec<SocketAddr>> {
    let addrs: Vec<SocketAddr> = lookup_host((ep.host.as_str(), ep.port)).await?.collect();
    if addrs.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no addresses found",
        ));
    }

    Ok(addrs)
}

/// Connect to the first reachable address. Overall deadline is applied by the caller.
pub(crate) async fn connect(addrs: &[SocketAddr]) -> std::io::Result<(TcpStream, SocketAddr)> {
    let mut last = None;

    for &addr in addrs {
        match TcpStream::connect(addr).await {
            Ok(s) => return Ok((s, addr)),
            Err(e) => last = Some(e),
        }
    }

    Err(last.unwrap_or_else(|| std::io::Error::other("no addresses")))
}

/// Resolve and connect once, recording DNS and connect time.
pub async fn probe(ep: &Endpoint, seq: u32) -> ProbeResult {
    let mut r = ProbeResult::new("tcp", ep.to_string(), seq);
    let start = Instant::now();

    let addrs = match resolve(ep).await {
        Ok(a) => a,
        Err(e) => {
            r.error = Some(format!("resolve failed: {}", describe_io(&e)));
            r.elapsed_ms = ms(start.elapsed());

            return r;
        }
    };

    r.timings.dns_ms = Some(ms(start.elapsed()));
    let c0 = Instant::now();

    match connect(&addrs).await {
        Ok((stream, addr)) => {
            r.timings.connect_ms = Some(ms(c0.elapsed()));
            r.address = Some(addr);
            r.outcome = super::Outcome::Ok;
            drop(stream);
        }
        Err(e) => r.error = Some(describe_io(&e)),
    }

    r.elapsed_ms = ms(start.elapsed());
    r
}
