//! Per-host probing: ICMP echo or TCP connect timing.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use net_icmp::{Echo, Pinger};
use tokio::net::TcpStream;

/// Probe method actually used for a host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// ICMP echo.
    Icmp,
    /// TCP connect timing.
    Tcp,
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Mode::Icmp => "icmp",
            Mode::Tcp => "tcp",
        })
    }
}

/// How one host is probed.
pub enum Prober {
    /// Shared per address family: one socket, replies demultiplexed by sequence.
    Icmp {
        /// Shared ICMP socket for this host's address family.
        pinger: Arc<Pinger>,
    },
    /// TCP connect timing to a port.
    Tcp {
        /// Port to connect to.
        port: u16,
    },
}

impl Prober {
    /// Probe method of this prober.
    pub fn mode(&self) -> Mode {
        match self {
            Prober::Icmp { .. } => Mode::Icmp,
            Prober::Tcp { .. } => Mode::Tcp,
        }
    }

    /// One probe. `Ok(rtt)` on reply, `Err(reason)` on loss.
    ///
    /// TCP: a completed handshake *or* a refusal (RST) proves the host answered and
    /// both are timed; only silence (timeout) or local errors count as loss.
    pub async fn probe(&self, ip: IpAddr, timeout: Duration) -> Result<Duration, String> {
        match self {
            Prober::Icmp { pinger } => match pinger.ping(ip, timeout).await {
                Echo::Reply { rtt, .. } => Ok(rtt),
                Echo::NoReply => Err("timeout".into()),
                Echo::Error(e) => Err(e),
            },
            Prober::Tcp { port } => {
                let start = Instant::now();

                match tokio::time::timeout(timeout, TcpStream::connect(SocketAddr::new(ip, *port)))
                    .await
                {
                    Ok(Ok(_stream)) => Ok(start.elapsed()),
                    Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                        Ok(start.elapsed())
                    }
                    Ok(Err(e)) => Err(e.to_string()),
                    Err(_) => Err("timeout".into()),
                }
            }
        }
    }
}
