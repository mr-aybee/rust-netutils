//! End-to-end tests against sockets created by the test process itself
//! (their owner PID is always visible without privileges).
#![allow(clippy::unwrap_used)] // Test fixtures: panicking on setup failure is the desired behavior.

use assert_cmd::Command;
use predicates::prelude::*;
use std::io::Read;
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::process::Stdio;
use std::thread;
use std::time::{Duration, Instant};

fn portwatch() -> Command {
    let mut c = Command::cargo_bin("portwatch").unwrap();
    c.timeout(Duration::from_secs(30));
    c
}

#[test]
fn finds_listener_with_owner_pid() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port().to_string();
    let pid = std::process::id().to_string();
    portwatch()
        .args(["-p", &port, "-l"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("LISTEN").and(predicate::str::contains(pid)));
}

#[test]
fn no_match_exits_1() {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
        .to_string();
    portwatch()
        .args(["-L", &port, "-t"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("0 socket(s)"));
}

#[test]
fn json_and_established_pair() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let _client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let (_server_side, _) = l.accept().unwrap();
    let out = portwatch()
        .args(["-p", &port.to_string(), "-t", "--json"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let states: Vec<&str> = v["sockets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["state"].as_str().unwrap())
        .collect();
    // Listener + both ends of the connection.
    assert_eq!(
        states.iter().filter(|s| **s == "LISTEN").count(),
        1,
        "{states:?}"
    );
    assert_eq!(
        states.iter().filter(|s| **s == "ESTABLISHED").count(),
        2,
        "{states:?}"
    );
    assert!(
        v["sockets"][0]["pids"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!(std::process::id()))
    );
    portwatch()
        .args(["-L", &port.to_string(), "-s", "established", "-q"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("ESTABLISHED"));
}

#[test]
fn udp_sockets() {
    let u = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = u.local_addr().unwrap().port().to_string();
    portwatch()
        .args(["-u", "-L", &port])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("udp"));
    portwatch().args(["-t", "-L", &port]).assert().code(1);
}

#[test]
fn watch_reports_open_and_close() {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin("portwatch"))
        .args([
            "--watch",
            "-i",
            "100ms",
            "-L",
            &port.to_string(),
            "-t",
            "--json",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    thread::sleep(Duration::from_millis(400));
    let l = TcpListener::bind(("127.0.0.1", port)).unwrap();
    thread::sleep(Duration::from_millis(500));
    drop(l);
    thread::sleep(Duration::from_millis(500));
    child.kill().unwrap();
    child.wait().unwrap();
    let mut out = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    let events: Vec<serde_json::Value> = out
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let kinds: Vec<&str> = events
        .iter()
        .map(|e| e["event"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, vec!["opened", "closed"], "{out}");
    assert_eq!(events[0]["socket"]["state"], "LISTEN");
    assert!(events[0]["time"].as_str().unwrap().ends_with('Z'));
}

#[test]
fn usage_errors() {
    portwatch().args(["-s", "bogus"]).assert().code(2);
    portwatch().args(["-p", "70000"]).assert().code(2);
    portwatch().args(["-t", "-u"]).assert().code(2);
    portwatch().args(["-a", "not-an-ip"]).assert().code(2);
}

#[test]
fn snapshot_is_fast() {
    let start = Instant::now();
    let _ = portwatch().arg("-q").assert();
    assert!(start.elapsed() < Duration::from_secs(10));
}
