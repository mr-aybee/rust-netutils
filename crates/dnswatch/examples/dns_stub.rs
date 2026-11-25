//! Benchmark fixture: UDP DNS stub answering `A 192.0.2.1` (TTL 30) for any name.
//! Usage: cargo run --release --example dns_stub -- 127.0.0.1:15353

use std::net::UdpSocket;

fn main() -> std::io::Result<()> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:15353".into());
    let sock = UdpSocket::bind(&addr)?;
    eprintln!("dns_stub listening on {}", sock.local_addr()?);
    let mut buf = [0u8; 512];

    loop {
        let (n, peer) = sock.recv_from(&mut buf)?;
        if n < 12 {
            continue;
        }

        let q = &buf[..n];
        let mut i = 12;
        while i < n && q[i] != 0 {
            i += 1 + q[i] as usize;
        }

        let qend = (i + 5).min(n);
        let is_a = qend >= i + 3 && q[i + 1] == 0 && q[i + 2] == 1;
        let mut r = Vec::with_capacity(64);
        r.extend_from_slice(&q[0..2]);
        r.extend_from_slice(&[0x85, 0x80, 0, 1, 0, u8::from(is_a), 0, 0, 0, 0]);
        r.extend_from_slice(&q[12..qend]);

        if is_a {
            r.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, 1]);
        }

        sock.send_to(&r, peer)?;
    }
}
