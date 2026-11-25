//! Benchmark fixture: open N loopback TCP connections (2N sockets + 1 listener) and hold them.
//! Usage: cargo run --release --example socket_load -- 5000   (raise `ulimit -n` first)
#![allow(clippy::unwrap_used)] // Fixture binary: fail fast.

use std::net::{TcpListener, TcpStream};

fn main() {
    let n: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(5000);
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let mut held = Vec::with_capacity(n * 2);

    for _ in 0..n {
        let c = TcpStream::connect(addr).unwrap();
        let (s, _) = l.accept().unwrap();
        held.push(c);
        held.push(s);
    }

    println!("ready {} sockets on port {}", held.len() + 1, addr.port());
    std::thread::park();
}
