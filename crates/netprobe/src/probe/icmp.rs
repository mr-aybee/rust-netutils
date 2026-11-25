//! ICMP echo probe built on the shared `net-icmp` engine.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

pub use net_icmp::{IcmpSocket, PAYLOAD_LEN, SocketKind, build_echo, checksum};

use super::{Outcome, ProbeResult, ms, tcp};
use crate::target::Endpoint;

/// Resolve to the first address of the host (port is ignored).
pub async fn resolve_ip(host: &str) -> io::Result<IpAddr> {
    let ep = Endpoint {
        host: host.to_string(),
        port: 1,
    };
    Ok(tcp::resolve(&ep).await?[0].ip())
}

/// Send one echo request and record the outcome.
pub async fn probe(
    sock: &IcmpSocket,
    host: &str,
    ip: IpAddr,
    id: u16,
    wait: Duration,
    seq: u32,
) -> ProbeResult {
    let mut r = ProbeResult::new("icmp", host.to_string(), seq);
    r.address = Some(SocketAddr::new(ip, 0));

    match sock.echo(ip, id, (seq & 0xffff) as u16, wait).await {
        net_icmp::Echo::Reply { rtt, bytes } => {
            r.outcome = Outcome::Ok;
            r.detail = Some(format!("{bytes} bytes"));
            r.elapsed_ms = ms(rtt);
        }
        net_icmp::Echo::NoReply => {
            r.error = Some("no echo reply".into());
            r.elapsed_ms = ms(wait);
        }
        net_icmp::Echo::Error(e) => r.error = Some(e),
    }

    r
}
