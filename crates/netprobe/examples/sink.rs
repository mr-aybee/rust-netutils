//! Benchmark fixture: TCP listener that accepts and immediately closes connections.
//! Usage: cargo run --release --example sink -- 127.0.0.1:7000

use std::net::TcpListener;

fn main() -> std::io::Result<()> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:7000".into());
    let listener = TcpListener::bind(&addr)?;
    eprintln!("sink listening on {}", listener.local_addr()?);
    for conn in listener.incoming() {
        drop(conn);
    }
    Ok(())
}
