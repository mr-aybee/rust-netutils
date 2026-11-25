//! End-to-end tests against programmable local DNS stubs (no internet required).
#![allow(clippy::unwrap_used)] // Test fixtures: panicking on setup failure is the desired behavior.

use assert_cmd::Command;
use predicates::prelude::*;
use std::collections::HashMap;
use std::io::Read;
use std::net::{SocketAddr, UdpSocket};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// What the stub answers for a name.
#[derive(Clone)]
enum Reply {
    A(Vec<[u8; 4]>),
    ServFail,
}

type Zone = Arc<Mutex<HashMap<String, Reply>>>;

/// Authoritative-style stub: A records from `zone`, NXDOMAIN for unknown names,
/// NODATA for non-A queries on known names.
fn stub(zone: Zone) -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = sock.local_addr().unwrap();
    thread::spawn(move || {
        let mut buf = [0u8; 512];
        while let Ok((n, peer)) = sock.recv_from(&mut buf) {
            if n < 12 {
                continue;
            }

            let q = &buf[..n];
            let mut i = 12;
            let mut labels = Vec::new();

            while i < n && q[i] != 0 {
                let len = q[i] as usize;
                labels.push(String::from_utf8_lossy(&q[i + 1..i + 1 + len]).to_lowercase());
                i += 1 + len;
            }

            let qtype = u16::from_be_bytes([q[i + 1], q[i + 2]]);
            let qend = i + 5;
            let name = labels.join(".");
            let reply = zone.lock().unwrap().get(&name).cloned();
            let (rcode, answers): (u8, Vec<[u8; 4]>) = match reply {
                None => (3, vec![]),
                Some(Reply::ServFail) => (2, vec![]),
                Some(Reply::A(ips)) if qtype == 1 => (0, ips),
                Some(Reply::A(_)) => (0, vec![]),
            };

            let mut r = Vec::with_capacity(128);
            r.extend_from_slice(&q[0..2]);
            r.extend_from_slice(&[0x85, 0x80 | rcode]); // QR AA RD, RA + rcode
            r.extend_from_slice(&[0, 1, 0, answers.len() as u8, 0, 0, 0, 0]);
            r.extend_from_slice(&q[12..qend]);

            for ip in answers {
                r.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4]);
                r.extend_from_slice(&ip);
            }

            let _ = sock.send_to(&r, peer);
        }
    });
    addr
}

fn zone(entries: &[(&str, Reply)]) -> Zone {
    Arc::new(Mutex::new(
        entries
            .iter()
            .map(|(n, r)| (n.to_string(), r.clone()))
            .collect(),
    ))
}

fn dnswatch() -> Command {
    Command::cargo_bin("dnswatch").unwrap()
}

/// Spawn dnswatch, run `during` while it executes, and return (exit code, stdout) once it
/// exits or `limit` elapses (then it is killed).
fn run_live(args: &[&str], limit: Duration, during: impl FnOnce()) -> (Option<i32>, String) {
    let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin("dnswatch"))
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    during();
    let start = Instant::now();

    let code = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status.code();
        }

        if start.elapsed() > limit {
            child.kill().unwrap();
            child.wait().unwrap();

            break None;
        }

        thread::sleep(Duration::from_millis(20));
    };

    let mut out = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    (code, out)
}

#[test]
fn watch_reports_change_with_diff() {
    let z = zone(&[("app.test", Reply::A(vec![[192, 0, 2, 1]]))]);
    let server = stub(Arc::clone(&z)).to_string();
    let (code, out) = run_live(
        &[
            "watch",
            "app.test",
            "-s",
            &server,
            "-i",
            "200ms",
            "--until-change",
        ],
        Duration::from_secs(10),
        || {
            thread::sleep(Duration::from_millis(700));
            z.lock()
                .unwrap()
                .insert("app.test".into(), Reply::A(vec![[192, 0, 2, 2]]));
        },
    );
    assert_eq!(code, Some(0), "{out}");
    assert!(
        out.contains("INITIAL") && out.contains("A 192.0.2.1"),
        "{out}"
    );
    assert!(
        out.contains("CHANGED") && out.contains("+ A 192.0.2.2") && out.contains("- A 192.0.2.1"),
        "{out}"
    );
}

#[test]
fn transient_errors_are_not_changes() {
    let z = zone(&[("app.test", Reply::A(vec![[192, 0, 2, 1]]))]);
    let server = stub(Arc::clone(&z)).to_string();
    let (_, out) = run_live(
        &["watch", "app.test", "-s", &server, "-i", "200ms", "--json"],
        Duration::from_millis(2500),
        || {
            thread::sleep(Duration::from_millis(500));
            z.lock().unwrap().insert("app.test".into(), Reply::ServFail);
            thread::sleep(Duration::from_millis(700));
            z.lock()
                .unwrap()
                .insert("app.test".into(), Reply::A(vec![[192, 0, 2, 1]]));
        },
    );
    let events: Vec<serde_json::Value> = out
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let kinds: Vec<&str> = events
        .iter()
        .map(|e| e["event"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, vec!["initial", "error", "recovered"], "{out}");
    assert_eq!(events[0]["answer"]["records"][0], "A 192.0.2.1");
}

#[test]
fn nxdomain_to_records_is_a_change() {
    let z = zone(&[]);
    let server = stub(Arc::clone(&z)).to_string();
    let (code, out) = run_live(
        &[
            "watch",
            "new.test",
            "-s",
            &server,
            "-i",
            "200ms",
            "--until-change",
            "-q",
        ],
        Duration::from_secs(10),
        || {
            thread::sleep(Duration::from_millis(600));
            z.lock()
                .unwrap()
                .insert("new.test".into(), Reply::A(vec![[198, 51, 100, 7]]));
        },
    );
    assert_eq!(code, Some(0), "{out}");
    assert!(
        !out.contains("INITIAL"),
        "-q hides the initial state: {out}"
    );
    assert!(out.contains("+ A 198.51.100.7"), "{out}");
}

#[test]
fn wait_succeeds_when_all_servers_match() {
    let z1 = zone(&[("app.test", Reply::A(vec![[192, 0, 2, 1]]))]);
    let z2 = zone(&[("app.test", Reply::A(vec![[192, 0, 2, 9]]))]);
    let (s1, s2) = (
        stub(Arc::clone(&z1)).to_string(),
        stub(Arc::clone(&z2)).to_string(),
    );
    let (code, out) = run_live(
        &[
            "wait",
            "app.test",
            "-e",
            "192.0.2.1",
            "-s",
            &s1,
            "-s",
            &s2,
            "-i",
            "200ms",
            "--max-wait",
            "10s",
        ],
        Duration::from_secs(12),
        || {
            thread::sleep(Duration::from_millis(600));
            z2.lock()
                .unwrap()
                .insert("app.test".into(), Reply::A(vec![[192, 0, 2, 1]]));
        },
    );
    assert_eq!(code, Some(0), "{out}");
    assert!(
        out.contains("1/2 matching") && out.contains("2/2 matching"),
        "{out}"
    );
}

#[test]
fn wait_times_out() {
    let z = zone(&[("app.test", Reply::A(vec![[192, 0, 2, 1]]))]);
    let server = stub(z).to_string();
    dnswatch()
        .args([
            "wait",
            "app.test",
            "-e",
            "192.0.2.99",
            "-s",
            &server,
            "-i",
            "100ms",
            "--max-wait",
            "500ms",
        ])
        .timeout(Duration::from_secs(10))
        .assert()
        .code(1)
        .stderr(predicate::str::contains("not seen"));
}

#[test]
fn compare_consistent_different_and_errors() {
    let same1 = stub(zone(&[(
        "app.test",
        Reply::A(vec![[192, 0, 2, 1], [192, 0, 2, 2]]),
    )]))
    .to_string();

    // Same set in a different order must still be consistent.
    let same2 = stub(zone(&[(
        "app.test",
        Reply::A(vec![[192, 0, 2, 2], [192, 0, 2, 1]]),
    )]))
    .to_string();
    let other = stub(zone(&[("app.test", Reply::A(vec![[203, 0, 113, 5]]))])).to_string();
    let failing = stub(zone(&[("app.test", Reply::ServFail)])).to_string();

    dnswatch()
        .args(["compare", "app.test", "-s", &same1, "-s", &same2])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("CONSISTENT"));
    let out = dnswatch()
        .args(["compare", "app.test", "-s", &same1, "-s", &other, "--json"])
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["consistent"], false);
    assert_eq!(v["results"][0]["consistent"], false);
    dnswatch()
        .args(["compare", "app.test", "-s", &same1, "-s", &failing])
        .assert()
        .code(3);

    // NODATA for a type the name lacks, NXDOMAIN for unknown names.
    dnswatch()
        .args([
            "compare",
            "app.test",
            "missing.test",
            "-T",
            "A,AAAA",
            "-s",
            &same1,
        ])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("NODATA").and(predicate::str::contains("NXDOMAIN")));
}

#[test]
fn usage_errors() {
    dnswatch().assert().code(2);
    dnswatch().args(["compare", "bad name"]).assert().code(2);
    dnswatch()
        .args(["compare", "a.test", "-T", "ANY"])
        .assert()
        .code(2);
    dnswatch()
        .args(["compare", "a.test", "-s", "dns.google"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("IP address"));
    dnswatch().args(["wait", "a.test"]).assert().code(2);
}
