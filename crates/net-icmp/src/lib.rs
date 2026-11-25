//! Shared ICMP echo engine for rust-netutils (private crate).
//!
//! Socket strategy, in order:
//! 1. Unprivileged datagram ICMP socket (Linux when the user's group is within
//!    `net.ipv4.ping_group_range`; macOS by default).
//! 2. Raw ICMP socket (root / `CAP_NET_RAW`; Administrator on Windows).
//!
//! If neither is permitted the probe fails with an explanatory error. There is
//! never a silent fallback to another protocol.

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
            windows::available(v6)?;
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

/// Short description of common I/O errors.
fn describe_io(e: &io::Error) -> String {
    match e.kind() {
        io::ErrorKind::PermissionDenied => "permission denied".into(),
        io::ErrorKind::HostUnreachable => "host unreachable".into(),
        io::ErrorKind::NetworkUnreachable => "network unreachable".into(),
        _ => e.to_string(),
    }
}

/// Result of one echo exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Echo {
    /// Echo reply received after `rtt`; `bytes` is the ICMP message size.
    Reply { rtt: Duration, bytes: usize },
    /// No reply before the deadline.
    NoReply,
    /// Unreachable, TTL exceeded, or a local error.
    Error(String),
}

impl IcmpSocket {
    /// Send one echo request to `ip` and wait up to `wait` for the matching reply.
    /// `id` distinguishes this socket's packets on raw sockets (ignored elsewhere).
    pub async fn echo(&self, ip: IpAddr, id: u16, seq: u16, wait: Duration) -> Echo {
        let Some(socket) = self.sock.as_ref() else {
            return echo_windows_api(ip, wait).await;
        };
        let packet = build_echo(self.v6, id, seq);
        let start = Instant::now();
        let deadline = start + wait;
        if let Err(e) = socket.send_to(&packet, SocketAddr::new(ip, 0)).await {
            return Echo::Error(format!("send failed: {}", describe_io(&e)));
        }
        let raw = self.kind == SocketKind::Raw;
        let mut buf = [0u8; 1500];
        loop {
            let (n, from) =
                match tokio::time::timeout_at(deadline.into(), socket.recv_from(&mut buf)).await {
                    Err(_) => return Echo::NoReply,
                    Ok(Err(e)) => return Echo::Error(describe_io(&e)),
                    Ok(Ok(v)) => v,
                };
            match classify(self.v6, &buf[..n], id, seq, raw) {
                // Raw sockets see every ICMP message on the host: require the reply to come from the target.
                Reply::Echo { .. } if raw && from.ip() != ip => continue,
                Reply::Echo { len } => {
                    return Echo::Reply {
                        rtt: start.elapsed(),
                        bytes: len,
                    };
                }
                Reply::Unreachable(code) => {
                    return Echo::Error(unreachable_text(self.v6, code).into());
                }
                Reply::TimeExceeded => return Echo::Error("time to live exceeded".into()),
                Reply::Unrelated => continue,
            }
        }
    }
}

/// Kind of ICMP message relevant to an echo exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgKind {
    EchoReply { len: usize },
    Unreachable(u8),
    TimeExceeded,
}

/// A parsed message: its kind plus the identifier and sequence it refers to
/// (for error messages, those of the embedded original echo request).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Parsed {
    pub kind: MsgKind,
    pub id: u16,
    pub seq: u16,
}

/// Parse a received ICMP message without matching it to a particular request.
pub fn parse(v6: bool, raw_buf: &[u8]) -> Option<Parsed> {
    let msg = if v6 {
        raw_buf
    } else {
        strip_ipv4_header(raw_buf)
    };
    if msg.len() < 8 {
        return None;
    }
    let ids = |m: &[u8]| {
        (m.len() >= 8).then(|| {
            (
                u16::from_be_bytes([m[4], m[5]]),
                u16::from_be_bytes([m[6], m[7]]),
            )
        })
    };
    let (reply, unreach, exceeded) = if v6 {
        (ECHO_REPLY_V6, UNREACHABLE_V6, TIME_EXCEEDED_V6)
    } else {
        (ECHO_REPLY_V4, UNREACHABLE_V4, TIME_EXCEEDED_V4)
    };
    let t = msg[0];
    if t == reply {
        let (id, seq) = ids(msg)?;
        return Some(Parsed {
            kind: MsgKind::EchoReply { len: msg.len() },
            id,
            seq,
        });
    }
    if t == unreach || t == exceeded {
        let inner = &msg[8..];
        let inner_icmp = if v6 {
            inner.get(40..)?
        } else {
            Some(strip_ipv4_header(inner)).filter(|i| i.len() < inner.len())?
        };
        let (id, seq) = ids(inner_icmp)?;
        let kind = if t == unreach {
            MsgKind::Unreachable(msg[1])
        } else {
            MsgKind::TimeExceeded
        };
        return Some(Parsed { kind, id, seq });
    }
    None
}

type Waiters = std::sync::Mutex<
    std::collections::HashMap<u16, (IpAddr, tokio::sync::oneshot::Sender<(MsgKind, Instant)>)>,
>;

/// One shared ICMP socket for many concurrent echo exchanges.
///
/// A single receive task demultiplexes replies by sequence number (unique per
/// in-flight request) and source address. With raw sockets this avoids the
/// O(N²) cost of N sockets each receiving every ICMP packet on the host.
pub struct Pinger {
    inner: std::sync::Arc<IcmpSocket>,
    waiters: std::sync::Arc<Waiters>,
    next_seq: std::sync::atomic::AtomicU16,
    id: u16,
    receiver: Option<tokio::task::JoinHandle<()>>,
}

impl Pinger {
    /// Open a shared socket (must be called inside a Tokio runtime).
    pub fn open(v6: bool, id: u16) -> Result<Self, String> {
        let inner = std::sync::Arc::new(IcmpSocket::open(v6)?);
        let waiters: std::sync::Arc<Waiters> = std::sync::Arc::default();
        let receiver = inner.sock.is_some().then(|| {
            let (sock, waiters) = (
                std::sync::Arc::clone(&inner),
                std::sync::Arc::clone(&waiters),
            );
            tokio::spawn(async move { receive_loop(sock, waiters, id).await })
        });
        Ok(Self {
            inner,
            waiters,
            next_seq: std::sync::atomic::AtomicU16::new(0),
            id,
            receiver,
        })
    }

    pub fn kind(&self) -> SocketKind {
        self.inner.kind
    }

    /// Send one echo request and wait up to `wait` for the reply.
    pub async fn ping(&self, ip: IpAddr, wait: Duration) -> Echo {
        let Some(socket) = self.inner.sock.as_ref() else {
            return echo_windows_api(ip, wait).await;
        };
        let (tx, rx) = tokio::sync::oneshot::channel();
        // Pick a sequence number not currently in flight.
        let seq = {
            let Ok(mut w) = self.waiters.lock() else {
                return Echo::Error("internal error: lock poisoned".into());
            };
            let mut seq = self
                .next_seq
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mut tries = 0u32;
            while w.contains_key(&seq) {
                seq = self
                    .next_seq
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tries += 1;
                if tries > u32::from(u16::MAX) {
                    return Echo::Error("too many requests in flight".into());
                }
            }
            w.insert(seq, (ip, tx));
            seq
        };
        let packet = build_echo(self.inner.v6, self.id, seq);
        let start = Instant::now();
        let result = match socket.send_to(&packet, SocketAddr::new(ip, 0)).await {
            Err(e) => Echo::Error(format!("send failed: {}", describe_io(&e))),
            Ok(_) => match tokio::time::timeout(wait, rx).await {
                Ok(Ok((MsgKind::EchoReply { len }, at))) => Echo::Reply {
                    rtt: at.saturating_duration_since(start),
                    bytes: len,
                },
                Ok(Ok((MsgKind::Unreachable(code), _))) => {
                    Echo::Error(unreachable_text(self.inner.v6, code).into())
                }
                Ok(Ok((MsgKind::TimeExceeded, _))) => Echo::Error("time to live exceeded".into()),
                Ok(Err(_)) => Echo::Error("receiver stopped".into()),
                Err(_) => Echo::NoReply,
            },
        };
        if let Ok(mut w) = self.waiters.lock() {
            w.remove(&seq);
        }
        result
    }
}

impl Drop for Pinger {
    fn drop(&mut self) {
        if let Some(h) = &self.receiver {
            h.abort();
        }
    }
}

async fn receive_loop(sock: std::sync::Arc<IcmpSocket>, waiters: std::sync::Arc<Waiters>, id: u16) {
    let Some(socket) = sock.sock.as_ref() else {
        return;
    };
    let raw = sock.kind == SocketKind::Raw;
    let mut buf = [0u8; 1500];
    loop {
        let Ok((n, from)) = socket.recv_from(&mut buf).await else {
            continue;
        };
        let at = Instant::now();
        let Some(p) = parse(sock.v6, &buf[..n]) else {
            continue;
        };
        // Datagram sockets: the kernel rewrites the identifier and filters per socket.
        if raw && p.id != id {
            continue;
        }
        let Ok(mut w) = waiters.lock() else { return };
        let matches = match (w.get(&p.seq), p.kind) {
            // Echo replies must come from the probed address; errors come from routers.
            (Some((target, _)), MsgKind::EchoReply { .. }) => *target == from.ip(),
            (Some(_), _) => true,
            (None, _) => false,
        };
        if matches && let Some((_, tx)) = w.remove(&p.seq) {
            let _ = tx.send((p.kind, at));
        }
    }
}

#[cfg(windows)]
async fn echo_windows_api(ip: IpAddr, wait: Duration) -> Echo {
    let payload = build_echo(false, 0, 0)[8..].to_vec();
    let start = Instant::now();
    // IcmpSendEcho blocks; run it on the blocking pool so other tasks proceed.
    match tokio::task::spawn_blocking(move || windows::echo(ip, &payload, wait)).await {
        Ok(windows::Echo::Reply { bytes }) => Echo::Reply {
            rtt: start.elapsed(),
            bytes,
        },
        Ok(windows::Echo::TimedOut) => Echo::NoReply,
        Ok(windows::Echo::Error(e)) => Echo::Error(e),
        Err(e) => Echo::Error(format!("internal error: {e}")),
    }
}

#[cfg(not(windows))]
async fn echo_windows_api(_ip: IpAddr, _wait: Duration) -> Echo {
    Echo::Error("internal error: ICMP socket missing".into())
}

#[cfg(windows)]
mod windows;

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

    #[test]
    fn parse_reply_and_error() {
        let mut reply = build_echo(false, 9, 5);
        reply[0] = ECHO_REPLY_V4;
        assert_eq!(
            parse(false, &reply),
            Some(Parsed {
                kind: MsgKind::EchoReply { len: reply.len() },
                id: 9,
                seq: 5
            })
        );
        let original = build_echo(false, 9, 6);
        let mut msg = vec![UNREACHABLE_V4, 3, 0, 0, 0, 0, 0, 0, 0x45];
        msg.extend_from_slice(&[0u8; 19]);
        msg.extend_from_slice(&original);
        assert_eq!(
            parse(false, &msg),
            Some(Parsed {
                kind: MsgKind::Unreachable(3),
                id: 9,
                seq: 6
            })
        );
        assert_eq!(parse(false, &[8, 0, 0]), None);
    }

    proptest::proptest! {
        #[test]
        fn parse_never_panics(b in proptest::collection::vec(proptest::num::u8::ANY, 0..120), v6: bool) {
            let _ = parse(v6, &b);
        }

        #[test]
        fn classify_never_panics(b in proptest::collection::vec(proptest::num::u8::ANY, 0..120), v6: bool, raw: bool) {
            let _ = classify(v6, &b, 1, 1, raw);
        }
    }
}
