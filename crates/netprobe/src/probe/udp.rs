//! UDP request/response probe.
//!
//! UDP is connectionless: silence does not prove a port is closed (the
//! datagram, the reply, or an ICMP error may be filtered). Results are:
//! - reply received            -> Ok
//! - ICMP port unreachable     -> Failed (reported by the OS as refused/reset)
//! - no reply before deadline  -> Inconclusive

use super::{Outcome, ProbeResult, describe_io, ms, tcp};
use crate::target::Endpoint;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

/// Largest UDP payload over IPv4.
pub const MAX_PAYLOAD: usize = 65_507;

/// Decode a payload given as text with escapes (`\n`, `\r`, `\t`, `\0`, `\\`, `\xHH`).
pub fn decode_escaped(s: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());

            continue;
        }

        match chars.next() {
            Some('n') => out.push(b'\n'),
            Some('r') => out.push(b'\r'),
            Some('t') => out.push(b'\t'),
            Some('0') => out.push(0),
            Some('\\') => out.push(b'\\'),
            Some('x') => {
                let hex: String = chars.by_ref().take(2).collect();
                let b = (hex.len() == 2)
                    .then(|| u8::from_str_radix(&hex, 16).ok())
                    .flatten()
                    .ok_or_else(|| format!("invalid \\x escape '\\x{hex}'"))?;
                out.push(b);
            }
            Some(other) => return Err(format!("unknown escape '\\{other}'")),
            None => return Err("trailing backslash in payload".into()),
        }
    }

    Ok(out)
}

/// Decode a hex payload; whitespace is ignored.
pub fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let digits: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if !digits.len().is_multiple_of(2) {
        return Err("hex payload must have an even number of digits".into());
    }

    digits
        .chunks(2)
        .map(|p| {
            std::str::from_utf8(p)
                .ok()
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .ok_or_else(|| "invalid hex digit in payload".to_string())
        })
        .collect()
}

fn preview(b: &[u8]) -> String {
    let shown: String = b
        .iter()
        .take(32)
        .map(|&c| {
            if c.is_ascii_graphic() || c == b' ' {
                c as char
            } else {
                '.'
            }
        })
        .collect();

    if b.len() > 32 {
        format!("{shown}…")
    } else {
        shown
    }
}

/// Send `payload` and wait up to `wait` for a reply.
pub async fn probe(ep: &Endpoint, payload: &[u8], wait: Duration, seq: u32) -> ProbeResult {
    let mut r = ProbeResult::new("udp", ep.to_string(), seq);
    let start = Instant::now();
    let deadline = start + wait;
    let addr = match tokio::time::timeout_at(deadline.into(), tcp::resolve(ep)).await {
        Ok(Ok(a)) => a[0],
        Ok(Err(e)) => {
            r.error = Some(format!("resolve failed: {}", describe_io(&e)));
            r.elapsed_ms = ms(start.elapsed());

            return r;
        }
        Err(_) => {
            r.error = Some("timed out resolving host".into());
            r.elapsed_ms = ms(start.elapsed());

            return r;
        }
    };

    r.timings.dns_ms = Some(ms(start.elapsed()));
    r.address = Some(addr);
    let sent_at = Instant::now();

    match exchange(addr, payload, deadline).await {
        Ok(Some(reply)) => {
            r.outcome = Outcome::Ok;
            r.timings.first_byte_ms = Some(ms(sent_at.elapsed()));
            r.detail = Some(format!(
                "{} byte reply \"{}\"",
                reply.len(),
                preview(&reply)
            ));
        }
        Ok(None) => {
            r.outcome = Outcome::Inconclusive;
            r.detail = Some("no reply (port may be open and silent, or filtered)".into());
        }
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset
            ) =>
        {
            r.error = Some("port unreachable (ICMP)".into());
        }
        Err(e) => r.error = Some(describe_io(&e)),
    }

    r.elapsed_ms = ms(start.elapsed());
    r
}

async fn exchange(
    addr: SocketAddr,
    payload: &[u8],
    deadline: Instant,
) -> io::Result<Option<Vec<u8>>> {
    let bind: SocketAddr = if addr.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };

    let sock = UdpSocket::bind(bind).await?;

    // Connecting filters replies to this peer and surfaces ICMP errors.
    sock.connect(addr).await?;
    sock.send(payload).await?;
    let mut buf = vec![0u8; 65_536];
    match tokio::time::timeout_at(deadline.into(), sock.recv(&mut buf)).await {
        Ok(Ok(n)) => {
            buf.truncate(n);
            Ok(Some(buf))
        }
        Ok(Err(e)) => Err(e),
        Err(_) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes() {
        assert_eq!(
            decode_escaped("a\\n\\x00\\xff\\\\").unwrap(),
            b"a\n\x00\xff\\"
        );

        for bad in ["\\x", "\\xg1", "\\q", "x\\"] {
            assert!(decode_escaped(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn hex() {
        assert_eq!(
            decode_hex("de ad BE ef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert!(decode_hex("abc").is_err());
        assert!(decode_hex("zz").is_err());
    }

    #[test]
    fn previews() {
        assert_eq!(preview(b"hi\x00"), "hi.");
    }
}
