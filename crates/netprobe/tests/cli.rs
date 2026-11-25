//! End-to-end CLI tests against local fixtures (no internet access required).
#![allow(clippy::unwrap_used)] // Test fixtures: panicking on setup failure is the desired behavior.

use assert_cmd::Command;
use predicates::prelude::*;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::thread;
use std::time::Duration;

fn netprobe() -> Command {
    Command::cargo_bin("netprobe").unwrap()
}

/// A port with nothing listening (bind then release).
fn closed_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// TCP server that answers each connection with `response` (if any) then closes.
fn serve(response: Option<&'static [u8]>, connections: usize) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    thread::spawn(move || {
        for s in l.incoming().take(connections) {
            let Ok(mut s) = s else { continue };

            if let Some(resp) = response {
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf);
                let _ = s.write_all(resp);
            } else {
                // Hold the connection open without answering.
                thread::sleep(Duration::from_secs(5));
            }
        }
    });
    addr
}

#[test]
fn version_and_help() {
    netprobe()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
    netprobe()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("tcp"));
}

#[test]
fn usage_errors_exit_2() {
    netprobe().assert().code(2);
    netprobe()
        .args(["tcp", "no-port"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("missing port"));
    netprobe()
        .args(["tcp", "a:1", "--timeout", "0s"])
        .assert()
        .code(2);
    netprobe().args(["http", "ftp://x"]).assert().code(2);
    netprobe()
        .args(["dns", "example.com", "-T", "ANY"])
        .assert()
        .code(2);
    netprobe()
        .args(["udp", "a:1", "--payload-hex", "abc"])
        .assert()
        .code(2);
}

#[test]
fn tcp_ok_and_refused() {
    let addr = serve(Some(b""), 3);
    netprobe()
        .args(["tcp", &addr.to_string(), "-c", "3", "-i", "10ms"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("3 ok"));
    netprobe()
        .args(["tcp", &format!("127.0.0.1:{}", closed_port())])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("connection refused"));
}

#[test]
fn tcp_json_document() {
    let addr = serve(Some(b""), 1);
    let out = netprobe()
        .args(["tcp", &addr.to_string(), "--json"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["version"], 1);
    assert_eq!(v["results"][0]["outcome"], "ok");
    assert_eq!(v["results"][0]["address"], addr.to_string());
    assert!(v["results"][0]["timings"]["connect_ms"].as_f64().unwrap() >= 0.0);
    assert_eq!(v["summary"]["ok"], 1);
}

#[test]
fn http_status_handling() {
    let ok = serve(Some(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), 2);
    netprobe()
        .args(["http", &format!("http://{ok}/health")])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("HTTP 200 OK"));
    netprobe()
        .args(["http", &format!("http://{ok}/"), "--expect", "204"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("unexpected status 200"));

    let err = serve(Some(b"HTTP/1.1 503 Service Unavailable\r\n\r\n"), 1);
    netprobe()
        .args(["http", &format!("http://{err}/")])
        .assert()
        .code(1);

    let redirect = serve(Some(b"HTTP/1.1 302 Found\r\nLocation: /next\r\n\r\n"), 1);
    netprobe()
        .args(["http", &format!("http://{redirect}/")])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("location=/next"));

    let garbage = serve(Some(b"SSH-2.0-OpenSSH_9.0\r\n"), 1);
    netprobe()
        .args(["http", &format!("http://{garbage}/")])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("not an HTTP/1.x response"));
}

#[test]
fn http_timeout_when_server_silent() {
    let silent = serve(None, 1);
    netprobe()
        .args(["http", &format!("http://{silent}/"), "--timeout", "300ms"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("timed out after 300ms"));
}

/// Minimal TLS server using a certificate issued for "localhost".
mod tls {
    use super::*;
    use rustls::ServerConfig;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::sync::Arc;

    pub fn serve_tls(dir: &std::path::Path) -> (SocketAddr, std::path::PathBuf) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let pem = dir.join("ca.pem");
        std::fs::write(&pem, cert.cert.pem()).unwrap();
        let chain = vec![CertificateDer::from(cert.cert.der().to_vec())];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
        let config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(chain, key)
                .unwrap();
        let config = Arc::new(config);
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        thread::spawn(move || {
            for s in l.incoming().take(4) {
                let Ok(mut tcp) = s else { continue };

                let Ok(mut conn) = rustls::ServerConnection::new(Arc::clone(&config)) else {
                    continue;
                };

                let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
                let mut buf = [0u8; 2048];
                if tls.read(&mut buf).is_ok() {
                    let _ = tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
                    let _ = tls.flush();
                }
            }
        });
        (addr, pem)
    }
}

#[test]
fn https_trust_is_enforced() {
    let dir = std::env::temp_dir().join(format!("netprobe-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (addr, ca) = tls::serve_tls(&dir);
    let url = format!("https://localhost:{}/", addr.port());

    // Untrusted self-signed certificate must fail by default.
    netprobe()
        .args(["http", &url])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("TLS handshake failed"));

    // Trusted via --ca-file.
    netprobe()
        .args(["http", &url, "--ca-file"])
        .arg(&ca)
        .assert()
        .code(0)
        .stdout(predicate::str::contains("tls=1.3"));

    // --insecure succeeds but warns.
    netprobe()
        .args(["http", &url, "--insecure"])
        .assert()
        .code(0)
        .stderr(predicate::str::contains("WARNING"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn udp_reply_refused_and_silent() {
    let echo = UdpSocket::bind("127.0.0.1:0").unwrap();
    let echo_addr = echo.local_addr().unwrap();
    thread::spawn(move || {
        let mut buf = [0u8; 1500];
        if let Ok((n, peer)) = echo.recv_from(&mut buf) {
            let _ = echo.send_to(&buf[..n], peer);
        }
    });
    netprobe()
        .args(["udp", &echo_addr.to_string(), "-p", "ping\\n"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("5 byte reply"));

    // A bound socket that never replies: inconclusive (exit 3).
    let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
    let silent_addr = silent.local_addr().unwrap();
    netprobe()
        .args(["udp", &silent_addr.to_string(), "-t", "300ms"])
        .assert()
        .code(3)
        .stdout(predicate::str::contains("INCONCLUSIVE"));
    drop(silent);

    // Closed port: kernel sends ICMP port unreachable on loopback (Linux/macOS).
    #[cfg(unix)]
    {
        let closed = UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        netprobe()
            .args(["udp", &closed.to_string(), "-t", "1s"])
            .assert()
            .code(1)
            .stdout(predicate::str::contains("port unreachable"));
    }
}

/// Minimal authoritative DNS stub: A 192.0.2.7 for any name except `missing.test` (NXDOMAIN).
fn dns_stub() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = sock.local_addr().unwrap();
    thread::spawn(move || {
        let mut buf = [0u8; 512];
        while let Ok((n, peer)) = sock.recv_from(&mut buf) {
            let q = &buf[..n];

            if n < 12 {
                continue;
            }

            // Question name ends at the first zero-length label.
            let mut i = 12;
            let mut labels = Vec::new();

            while i < n && q[i] != 0 {
                let len = q[i] as usize;
                labels.push(String::from_utf8_lossy(&q[i + 1..i + 1 + len]).to_string());
                i += 1 + len;
            }

            let qend = i + 5; // zero byte + qtype + qclass
            let name = labels.join(".");
            let nx = name == "missing.test";
            let mut r = Vec::with_capacity(64);
            r.extend_from_slice(&q[0..2]); // id
            r.extend_from_slice(&[0x81, if nx { 0x83 } else { 0x80 }]); // QR RD RA, rcode
            r.extend_from_slice(&[0, 1, 0, if nx { 0 } else { 1 }, 0, 0, 0, 0]);
            r.extend_from_slice(&q[12..qend]);

            if !nx {
                r.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 7]);
            }

            let _ = sock.send_to(&r, peer);
        }
    });
    addr
}

#[test]
fn dns_against_stub() {
    let server = dns_stub().to_string();
    netprobe()
        .args(["dns", "host.test.", "-s", &server, "-v"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("192.0.2.7"));
    netprobe()
        .args(["dns", "missing.test.", "-s", &server])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("NXDOMAIN"));
    netprobe()
        .args(["dns", "x.test", "-s", "not-an-ip"])
        .assert()
        .code(2);
}

#[test]
fn batch_mixed_results() {
    let ok = serve(Some(b"HTTP/1.1 200 OK\r\n\r\n"), 2);
    let file = format!(
        "tcp {ok}\nhttp http://{ok}/\ntcp 127.0.0.1:{}\n",
        closed_port()
    );
    let out = netprobe()
        .args(["batch", "-", "--json", "-j", "2"])
        .write_stdin(file)
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["summary"]["jobs"], 3);
    assert_eq!(v["summary"]["ok"], 2);
    assert_eq!(v["summary"]["failed"], 1);

    // Output preserves input order.
    assert!(
        v["jobs"][2]["label"]
            .as_str()
            .unwrap()
            .starts_with("tcp 127.0.0.1")
    );
}

#[test]
fn batch_rejects_bad_file() {
    netprobe()
        .args(["batch", "-"])
        .write_stdin("tcp a:1\nnope x\n")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("line 2"));
    netprobe()
        .args(["batch", "/nonexistent/file"])
        .assert()
        .code(2);
}

/// Windows uses the unprivileged IP Helper API, so ICMP must work without elevation.
#[cfg(windows)]
#[test]
fn windows_icmp_unprivileged() {
    netprobe()
        .args(["icmp", "127.0.0.1", "-c", "2", "-i", "100ms"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("2 ok"));
}
