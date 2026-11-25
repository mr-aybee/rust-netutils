//! ICMP echo probe.
//!
//! Socket strategy, in order:
//! 1. Unprivileged datagram ICMP socket (Linux when the user's group is within
//!    `net.ipv4.ping_group_range`; macOS by default).
//! 2. Raw ICMP socket (root / `CAP_NET_RAW`; Administrator on Windows).
//!
//! If neither is permitted the probe fails with an explanatory error. There is
//! never a silent fallback to another protocol.

use super::{Outcome, ProbeResult, describe_io, ms, tcp};
use crate::target::Endpoint;
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

const ECHO_REQUEST_V4: u8 = 8;
const ECHO_REPLY_V4: u8 = 0;
const UNREACHABLE_V4: u8 = 3;
const TIME_EXCEEDED_V4: u8 = 11;
const ECHO_REQUEST_V6: u8 = 128;
const ECHO_REPLY_V6: u8 = 129;
const UNREACHABLE_V6: u8 = 1;
const TIME_EXCEEDED_V6: u8 = 3;

/// Bytes of payload carried in each echo request.
pub const PAYLOAD_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketKind {
    Datagram,
    Raw,
    /// Windows IP Helper API (`IcmpSendEcho`), unprivileged.
    WindowsApi,
}

/// An open ICMP socket for one address family.
pub struct IcmpSocket {
    /// `None` for the Windows API backend, which is not socket-based.
    sock: Option<UdpSocket>,
    kind: SocketKind,
    v6: bool,
}

impl IcmpSocket {
    pub fn kind(&self) -> SocketKind {
        self.kind
    }

    /// Open a datagram socket, falling back to raw if datagram ICMP is not permitted.
    /// On Windows the unprivileged IP Helper API is used instead.
    pub fn open(v6: bool) -> Result<Self, String> {
        #[cfg(windows)]
        {
            super::icmp_windows::available(v6)?;
            return Ok(Self {
                sock: None,
                kind: SocketKind::WindowsApi,
                v6,
            });
        }
        #[cfg(not(windows))]
        Self::open_socket(v6)
    }

    #[cfg_attr(windows, allow(dead_code))]
    fn open_socket(v6: bool) -> Result<Self, String> {
        let (domain, proto) = if v6 {
            (Domain::IPV6, Protocol::ICMPV6)
        } else {
            (Domain::IPV4, Protocol::ICMPV4)
        };
        let attempt = |ty: Type| -> io::Result<UdpSocket> {
            let s = Socket::new(domain, ty, Some(proto))?;
            s.set_nonblocking(true)?;
            let std: std::net::UdpSocket = s.into();
            UdpSocket::from_std(std)
        };
        let dgram_err = match attempt(Type::DGRAM) {
            Ok(sock) => {
                return Ok(Self {
                    sock: Some(sock),
                    kind: SocketKind::Datagram,
                    v6,
                });
            }
            Err(e) => e,
        };
        match attempt(Type::RAW) {
            Ok(sock) => Ok(Self {
                sock: Some(sock),
                kind: SocketKind::Raw,
                v6,
            }),
            Err(raw_err) => Err(permission_hint(&dgram_err, &raw_err)),
        }
    }
}

fn permission_hint(dgram: &io::Error, raw: &io::Error) -> String {
    let base = format!(
        "ICMP not permitted (datagram socket: {}; raw socket: {})",
        describe_io(dgram),
        describe_io(raw)
    );
    if cfg!(target_os = "linux") {
        format!(
            "{base}. Allow unprivileged ping with `sysctl -w net.ipv4.ping_group_range=\"0 2147483647\"`, run as root, or grant CAP_NET_RAW"
        )
    } else if cfg!(windows) {
        format!("{base}. On Windows ICMP currently requires an elevated (Administrator) prompt")
    } else {
        base
    }
}

/// Internet checksum (RFC 1071).
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = data
        .chunks(2)
        .map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])))
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build an echo request. For IPv6 the kernel fills in the checksum.
pub fn build_echo(v6: bool, id: u16, seq: u16) -> Vec<u8> {
    let mut p = vec![0u8; 8 + PAYLOAD_LEN];
    p[0] = if v6 { ECHO_REQUEST_V6 } else { ECHO_REQUEST_V4 };
    p[4..6].copy_from_slice(&id.to_be_bytes());
    p[6..8].copy_from_slice(&seq.to_be_bytes());
    for (i, b) in p[8..].iter_mut().enumerate() {
        *b = b'a' + (i % 26) as u8;
    }
    if !v6 {
        let c = checksum(&p);
        p[2..4].copy_from_slice(&c.to_be_bytes());
    }
    p
}

/// Strip an IPv4 header if present (raw sockets, and datagram sockets on macOS).
fn strip_ipv4_header(buf: &[u8]) -> &[u8] {
    if buf.len() >= 20 && buf[0] >> 4 == 4 {
        let ihl = usize::from(buf[0] & 0x0f) * 4;
        if ihl >= 20 && buf.len() >= ihl + 8 {
            return &buf[ihl..];
        }
    }
    buf
}

/// What a received ICMP message means for our request.
#[derive(Debug, PartialEq, Eq)]
pub enum Reply {
    Echo { len: usize },
    Unreachable(u8),
    TimeExceeded,
    Unrelated,
}

/// Classify a received message. `check_id` is false for datagram sockets,
/// where the kernel rewrites the identifier and filters replies per socket.
pub fn classify(v6: bool, raw_buf: &[u8], id: u16, seq: u16, check_id: bool) -> Reply {
    let msg = if v6 {
        raw_buf
    } else {
        strip_ipv4_header(raw_buf)
    };
    if msg.len() < 8 {
        return Reply::Unrelated;
    }
    let matches = |m: &[u8]| {
        m.len() >= 8
            && u16::from_be_bytes([m[6], m[7]]) == seq
            && (!check_id || u16::from_be_bytes([m[4], m[5]]) == id)
    };
    let (reply, unreach, exceeded) = if v6 {
        (ECHO_REPLY_V6, UNREACHABLE_V6, TIME_EXCEEDED_V6)
    } else {
        (ECHO_REPLY_V4, UNREACHABLE_V4, TIME_EXCEEDED_V4)
    };
    let t = msg[0];
    if t == reply {
        return if matches(msg) {
            Reply::Echo { len: msg.len() }
        } else {
            Reply::Unrelated
        };
    }
    if t == unreach || t == exceeded {
        // Error messages embed the offending packet after the 8-byte header.
        let inner = &msg[8..];
        let inner_icmp = if v6 {
            inner.get(40..)
        } else {
            Some(strip_ipv4_header(inner)).filter(|i| i.len() < inner.len())
        };
        let ours = inner_icmp.is_some_and(matches);
        if ours || !check_id {
            return if t == unreach {
                Reply::Unreachable(msg[1])
            } else {
                Reply::TimeExceeded
            };
        }
    }
    Reply::Unrelated
}

fn unreachable_text(v6: bool, code: u8) -> &'static str {
    match (v6, code) {
        (false, 0) | (true, 3) => "destination network/host unreachable",
        (false, 1) => "destination host unreachable",
        (false, 3) | (true, 4) => "destination port unreachable",
        (false, 13) | (true, 1) => "administratively prohibited",
        _ => "destination unreachable",
    }
}

/// Resolve to the first address of the endpoint (port is ignored).
pub async fn resolve_ip(host: &str) -> io::Result<IpAddr> {
    let ep = Endpoint {
        host: host.to_string(),
        port: 1,
    };
    Ok(tcp::resolve(&ep).await?[0].ip())
}

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
    let Some(socket) = sock.sock.as_ref() else {
        return probe_windows_api(r, ip, wait).await;
    };
    let wire_seq = (seq & 0xffff) as u16;
    let packet = build_echo(sock.v6, id, wire_seq);
    let start = Instant::now();
    let deadline = start + wait;
    let dest: SocketAddr = SocketAddr::new(ip, 0);
    if let Err(e) = socket.send_to(&packet, dest).await {
        r.error = Some(format!("send failed: {}", describe_io(&e)));
        return r;
    }
    let mut buf = [0u8; 1500];
    loop {
        let recv = tokio::time::timeout_at(deadline.into(), socket.recv_from(&mut buf)).await;
        let (n, _from) = match recv {
            Err(_) => {
                r.error = Some("no echo reply".into());
                break;
            }
            Ok(Err(e)) => {
                r.error = Some(describe_io(&e));
                break;
            }
            Ok(Ok(v)) => v,
        };
        match classify(
            sock.v6,
            &buf[..n],
            id,
            wire_seq,
            sock.kind == SocketKind::Raw,
        ) {
            Reply::Echo { len } => {
                r.outcome = Outcome::Ok;
                r.detail = Some(format!("{len} bytes"));
                break;
            }
            Reply::Unreachable(code) => {
                r.error = Some(unreachable_text(sock.v6, code).into());
                break;
            }
            Reply::TimeExceeded => {
                r.error = Some("time to live exceeded".into());
                break;
            }
            Reply::Unrelated => continue,
        }
    }
    r.elapsed_ms = ms(start.elapsed());
    r
}

#[cfg(windows)]
async fn probe_windows_api(mut r: ProbeResult, ip: IpAddr, wait: Duration) -> ProbeResult {
    use super::icmp_windows::{Echo, echo};
    let payload = build_echo(false, 0, 0)[8..].to_vec();
    let start = Instant::now();
    // IcmpSendEcho blocks; run it on the blocking pool so cancellation and other tasks proceed.
    let res = tokio::task::spawn_blocking(move || echo(ip, &payload, wait)).await;
    r.elapsed_ms = ms(start.elapsed());
    match res {
        Ok(Echo::Reply { bytes }) => {
            r.outcome = Outcome::Ok;
            r.detail = Some(format!("{bytes} bytes"));
        }
        Ok(Echo::TimedOut) => r.error = Some("no echo reply".into()),
        Ok(Echo::Error(e)) => r.error = Some(e),
        Err(e) => r.error = Some(format!("internal error: {e}")),
    }
    r
}

#[cfg(not(windows))]
async fn probe_windows_api(mut r: ProbeResult, _ip: IpAddr, _wait: Duration) -> ProbeResult {
    r.error = Some("internal error: ICMP socket missing".into());
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_rfc1071_example() {
        // Example from RFC 1071 section 3.
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(checksum(&data), !0xddf2);
    }

    #[test]
    fn echo_checksum_verifies() {
        let p = build_echo(false, 0x1234, 7);
        assert_eq!(checksum(&p), 0);
        assert_eq!(p[0], ECHO_REQUEST_V4);
    }

    #[test]
    fn classify_reply_with_and_without_ip_header() {
        let mut reply = build_echo(false, 9, 5);
        reply[0] = ECHO_REPLY_V4;
        assert_eq!(
            classify(false, &reply, 9, 5, true),
            Reply::Echo { len: reply.len() }
        );
        assert_eq!(classify(false, &reply, 9, 6, true), Reply::Unrelated);
        assert_eq!(classify(false, &reply, 1, 5, true), Reply::Unrelated);
        assert_eq!(
            classify(false, &reply, 1, 5, false),
            Reply::Echo { len: reply.len() }
        );
        let mut with_ip = vec![0x45u8; 1];
        with_ip.extend_from_slice(&[0u8; 19]);
        with_ip.extend_from_slice(&reply);
        assert_eq!(
            classify(false, &with_ip, 9, 5, true),
            Reply::Echo { len: reply.len() }
        );
    }

    #[test]
    fn classify_unreachable_embeds_original() {
        let original = build_echo(false, 9, 5);
        let mut msg = vec![UNREACHABLE_V4, 1, 0, 0, 0, 0, 0, 0];
        msg.push(0x45);
        msg.extend_from_slice(&[0u8; 19]);
        msg.extend_from_slice(&original);
        assert_eq!(classify(false, &msg, 9, 5, true), Reply::Unreachable(1));
        assert_eq!(classify(false, &msg, 8, 5, true), Reply::Unrelated);
    }

    proptest::proptest! {
        #[test]
        fn classify_never_panics(b in proptest::collection::vec(proptest::num::u8::ANY, 0..120), v6: bool, raw: bool) {
            let _ = classify(v6, &b, 1, 1, raw);
        }
    }
}
