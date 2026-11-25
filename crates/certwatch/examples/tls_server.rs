//! Benchmark fixture: TLS server with a generated root -> leaf chain for `localhost`.
//! Writes the root CA to `<dir>/root.pem` and serves handshakes until killed.
//! Usage: cargo run --release --example tls_server -- 127.0.0.1:17443 /tmp/dir
#![allow(clippy::unwrap_used)] // Fixture binary: fail fast.

use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

fn main() {
    let mut args = std::env::args().skip(1);
    let addr = args.next().unwrap_or_else(|| "127.0.0.1:17443".into());
    let dir = std::path::PathBuf::from(args.next().unwrap_or_else(|| ".".into()));
    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.distinguished_name
        .push(DnType::CommonName, "certwatch bench root");
    let root = CertifiedIssuer::self_signed(ca, KeyPair::generate().unwrap()).unwrap();
    std::fs::write(dir.join("root.pem"), root.pem()).unwrap();
    let key = KeyPair::generate().unwrap();
    let mut leaf_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    let leaf = leaf_params.signed_by(&key, &root).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![leaf.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    )
    .unwrap();
    let config = Arc::new(config);
    let listener = TcpListener::bind(&addr).unwrap();
    eprintln!("tls_server listening on {}", listener.local_addr().unwrap());
    for conn in listener.incoming() {
        let Ok(mut tcp) = conn else { continue };
        let config = Arc::clone(&config);
        std::thread::spawn(move || {
            let Ok(mut c) = rustls::ServerConnection::new(config) else {
                return;
            };
            let mut tls = rustls::Stream::new(&mut c, &mut tcp);
            let mut buf = [0u8; 64];
            let _ = tls.read(&mut buf);
            // Close cleanly so clients (e.g. openssl) do not report an unexpected EOF.
            tls.conn.send_close_notify();
            let _ = tls.flush();
        });
    }
}
