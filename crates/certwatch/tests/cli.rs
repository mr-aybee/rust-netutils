//! End-to-end tests against local TLS servers backed by a generated PKI.
#![allow(clippy::unwrap_used)] // Test fixtures: panicking on setup failure is the desired behavior.

use assert_cmd::Command;
use predicates::prelude::*;
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use time::{Duration, OffsetDateTime};

fn certwatch() -> Command {
    Command::cargo_bin("certwatch").unwrap()
}

struct Pki {
    dir: PathBuf,
    root_pem: PathBuf,
    root: CertifiedIssuer<'static, KeyPair>,
    intermediate: CertifiedIssuer<'static, KeyPair>,
}

fn ca_params(cn: &str) -> CertificateParams {
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name.push(DnType::CommonName, cn);
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.not_before = OffsetDateTime::now_utc() - Duration::days(30);
    p.not_after = OffsetDateTime::now_utc() + Duration::days(3650);
    p
}

fn pki(name: &str) -> Pki {
    let dir = std::env::temp_dir().join(format!("certwatch-test-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let root =
        CertifiedIssuer::self_signed(ca_params("Test Root"), KeyPair::generate().unwrap()).unwrap();
    let intermediate = CertifiedIssuer::signed_by(
        ca_params("Test Intermediate"),
        KeyPair::generate().unwrap(),
        &root,
    )
    .unwrap();
    let root_pem = dir.join("root.pem");
    std::fs::write(&root_pem, root.pem()).unwrap();
    Pki {
        dir,
        root_pem,
        root,
        intermediate,
    }
}

/// Issue a leaf for `localhost` valid from `from_days` to `to_days` relative to now.
fn leaf(
    pki: &Pki,
    from_days: i64,
    to_days: i64,
) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let mut p = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    p.distinguished_name.push(DnType::CommonName, "localhost");
    p.not_before = OffsetDateTime::now_utc() + Duration::days(from_days);
    p.not_after = OffsetDateTime::now_utc() + Duration::days(to_days);
    let key = KeyPair::generate().unwrap();
    let cert = p.signed_by(&key, &pki.intermediate).unwrap();
    (
        cert.der().clone(),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    )
}

/// Serve TLS with the given chain for up to `conns` connections.
fn serve(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    conns: usize,
) -> SocketAddr {
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(chain, key)
    .unwrap();
    let config = Arc::new(config);
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    thread::spawn(move || {
        for s in l.incoming().take(conns) {
            let Ok(mut tcp) = s else { continue };
            let Ok(mut conn) = rustls::ServerConnection::new(Arc::clone(&config)) else {
                continue;
            };
            let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
            let mut buf = [0u8; 64];
            // Drive the handshake; the client closes without sending data.
            let _ = tls.read(&mut buf);
            let _ = tls.flush();
        }
    });
    addr
}

fn target(addr: SocketAddr) -> String {
    format!("localhost:{}", addr.port())
}

fn trusted<'a>(cmd: &'a mut Command, root: &Path) -> &'a mut Command {
    cmd.arg("--ca-file").arg(root).arg("--no-system-roots")
}

#[test]
fn valid_chain_is_ok() {
    let pki = pki("valid");
    let (cert, key) = leaf(&pki, -1, 90);
    let addr = serve(vec![cert, pki.intermediate.der().clone()], key, 1);
    trusted(certwatch().args(["check", &target(addr)]), &pki.root_pem)
        .assert()
        .code(0)
        .stdout(
            predicate::str::starts_with("OK")
                .and(predicate::str::contains("subject: CN=localhost")),
        );
}

#[test]
fn expiring_soon_warns_then_fails() {
    let pki = pki("expiring");
    let (cert, key) = leaf(&pki, -1, 10);
    let addr = serve(vec![cert, pki.intermediate.der().clone()], key, 2);
    trusted(certwatch().args(["check", &target(addr)]), &pki.root_pem)
        .assert()
        .code(4)
        .stdout(
            predicate::str::contains("WARNING")
                .and(predicate::str::contains("warning threshold 30 days")),
        );
    trusted(
        certwatch().args([
            "check",
            &target(addr),
            "--crit-days",
            "14",
            "--warn-days",
            "30",
        ]),
        &pki.root_pem,
    )
    .assert()
    .code(1)
    .stdout(predicate::str::contains("CRITICAL"));
}

#[test]
fn expired_is_critical() {
    let pki = pki("expired");
    let (cert, key) = leaf(&pki, -60, -2);
    let addr = serve(vec![cert, pki.intermediate.der().clone()], key, 1);
    let out = trusted(
        certwatch().args(["check", &target(addr), "--json"]),
        &pki.root_pem,
    )
    .assert()
    .code(1)
    .get_output()
    .stdout
    .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let r = &v["results"][0];
    assert_eq!(r["verdict"], "critical");
    assert_eq!(r["validation_error_kind"], "expired");
    assert_eq!(r["trusted"], false);
    assert!(r["days_left"].as_i64().unwrap() < 0);
}

#[test]
fn hostname_mismatch_via_sni() {
    let pki = pki("mismatch");
    let (cert, key) = leaf(&pki, -1, 90);
    let addr = serve(vec![cert, pki.intermediate.der().clone()], key, 1);
    let out = trusted(
        certwatch().args(["check", &target(addr), "--sni", "other.test", "--json"]),
        &pki.root_pem,
    )
    .assert()
    .code(1)
    .get_output()
    .stdout
    .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(
        v["results"][0]["validation_error_kind"],
        "hostname_mismatch"
    );
    assert_eq!(v["results"][0]["sni"], "other.test");
}

#[test]
fn untrusted_and_incomplete_chain() {
    let pki = pki("untrusted");
    let (cert, key) = leaf(&pki, -1, 90);
    // Full chain but root not trusted (system roots only).
    let full = serve(
        vec![cert.clone(), pki.intermediate.der().clone()],
        key.clone_key(),
        1,
    );
    certwatch()
        .args(["check", &target(full)])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("unknown issuer"));
    // Root trusted, but server omits the intermediate.
    let incomplete = serve(vec![cert], key, 1);
    trusted(
        certwatch().args(["check", &target(incomplete), "-v"]),
        &pki.root_pem,
    )
    .assert()
    .code(1)
    .stdout(
        predicate::str::contains("incomplete chain")
            .and(predicate::str::contains("[0] CN=localhost")),
    );
}

#[test]
fn chain_expiry_includes_intermediate() {
    let pki = pki("intermediate");
    // Short-lived intermediate.
    let mut p = ca_params("Short Intermediate");
    p.not_after = OffsetDateTime::now_utc() + Duration::days(5);
    let short = CertifiedIssuer::signed_by(p, KeyPair::generate().unwrap(), &pki.root).unwrap();
    let mut lp = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    lp.not_before = OffsetDateTime::now_utc() - Duration::days(1);
    lp.not_after = OffsetDateTime::now_utc() + Duration::days(4);
    let key = KeyPair::generate().unwrap();
    let cert = lp.signed_by(&key, &short).unwrap();
    let addr = serve(
        vec![cert.der().clone(), short.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        1,
    );
    let out = trusted(
        certwatch().args(["check", &target(addr), "--json"]),
        &pki.root_pem,
    )
    .assert()
    .code(1)
    .get_output()
    .stdout
    .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["results"][0]["chain"].as_array().unwrap().len(), 2);
    assert!(v["results"][0]["chain_days_left"].as_i64().unwrap() <= 4);
}

#[test]
fn connection_errors_and_ordering() {
    let closed = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let pki = pki("order");
    let (cert, key) = leaf(&pki, -1, 90);
    let addr = serve(vec![cert, pki.intermediate.der().clone()], key, 1);
    let file = format!("# targets\n127.0.0.1:{closed}\n{}\n", target(addr));
    let out = trusted(
        certwatch().args(["check", "-f", "-", "--json"]),
        &pki.root_pem,
    )
    .write_stdin(file)
    .assert()
    .code(1)
    .get_output()
    .stdout
    .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["results"][0]["verdict"], "error");
    assert_eq!(v["results"][1]["verdict"], "ok");
    assert_eq!(v["summary"]["total"], 2);
}

#[test]
fn inspect_files() {
    let pki = pki("inspect");
    let bundle = pki.dir.join("bundle.pem");
    std::fs::write(
        &bundle,
        format!("{}{}", pki.intermediate.pem(), pki.root.pem()),
    )
    .unwrap();
    certwatch()
        .args(["inspect"])
        .arg(&bundle)
        .arg("-v")
        .assert()
        .code(0)
        .stdout(predicate::str::contains("[1] CN=Test Root"));
    let der = pki.dir.join("root.der");
    std::fs::write(&der, pki.root.der().as_ref()).unwrap();
    certwatch().arg("inspect").arg(&der).assert().code(0);
    certwatch()
        .args(["inspect", "/nonexistent.pem"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("cannot read file"));
    let _ = std::fs::remove_dir_all(&pki.dir);
}

#[test]
fn usage_errors() {
    certwatch().assert().code(2);
    certwatch()
        .arg("check")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("no targets"));
    certwatch().args(["check", "bad host"]).assert().code(2);
    certwatch()
        .args(["check", "a.test", "-w", "5", "-C", "10"])
        .assert()
        .code(2);
    certwatch()
        .args(["check", "a.test", "--no-system-roots"])
        .assert()
        .code(2);
}
