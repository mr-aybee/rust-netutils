//! End-to-end CLI tests using local TCP endpoints (ICMP permissions vary between hosts,
//! so the deterministic tests use TCP mode).
#![allow(clippy::unwrap_used)] // Test fixtures: panicking on setup failure is the desired behavior.

use assert_cmd::Command;
use predicates::prelude::*;
use std::net::TcpListener;
use std::time::Duration;

fn meshping() -> Command {
    let mut c = Command::cargo_bin("meshping").unwrap();
    c.timeout(Duration::from_secs(30));
    c
}

/// Listener that accepts and drops connections, kept alive for the test.
fn listener() -> (TcpListener, String) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    let clone = l.try_clone().unwrap();
    std::thread::spawn(move || for _ in clone.incoming() {});
    (l, addr)
}

fn closed_port() -> String {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .to_string()
}

#[test]
fn tcp_mode_counts_and_table() {
    let (_l, addr) = listener();
    meshping()
        .args([&addr, "-m", "tcp", "-c", "4", "-i", "50ms"])
        .assert()
        .code(0)
        .stdout(
            predicate::str::contains("HOST").and(predicate::str::contains(format!(
                "{addr}  tcp        4     0.0"
            ))),
        );
}

/// Windows retries a refused SYN for ~2 s before reporting it, so a closed port
/// cannot be timed there (documented limitation); the open-port tests cover Windows.
#[cfg(not(windows))]
#[test]
fn refused_connection_is_a_reply_not_loss() {
    let closed = closed_port();
    meshping()
        .args([&closed, "-m", "tcp", "-c", "3", "-i", "50ms"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("0.0"));
}

#[test]
fn unreachable_host_is_full_loss_and_exit_1() {
    // TEST-NET/unroutable: either times out or fails locally; both are loss.
    meshping()
        .args([
            "10.255.255.1:80",
            "-m",
            "tcp",
            "-c",
            "2",
            "-i",
            "150ms",
            "-t",
            "100ms",
        ])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("100.0"));
}

#[test]
fn json_lines_per_probe_with_summary_on_stderr() {
    let (_l, addr) = listener();
    let out = meshping()
        .args([&addr, "-m", "tcp", "-c", "3", "-i", "50ms", "-o", "json"])
        .assert()
        .code(0)
        .get_output()
        .clone();
    let lines: Vec<serde_json::Value> = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[2]["seq"], 2);
    assert_eq!(lines[0]["mode"], "tcp");
    assert!(lines[0]["rtt_ms"].as_f64().unwrap() >= 0.0);
    assert!(String::from_utf8(out.stderr).unwrap().contains("HOST"));
}

#[test]
fn csv_and_quiet() {
    let (_l, addr) = listener();
    let out = meshping()
        .args([
            &addr, "-m", "tcp", "-c", "2", "-i", "50ms", "-o", "csv", "-q",
        ])
        .assert()
        .code(0)
        .get_output()
        .clone();
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.starts_with("time,host,mode,seq,rtt_ms,status\n"));
    assert_eq!(text.lines().count(), 3);
    assert!(out.stderr.is_empty(), "quiet suppresses the summary");
}

#[test]
fn hosts_file_and_multiple_hosts() {
    let (_l1, a1) = listener();
    let (_l2, a2) = listener();
    meshping()
        .args(["-f", "-", "-m", "tcp", "-c", "2", "-i", "50ms"])
        .write_stdin(format!("# fleet\n{a1}\n\n{a2} # second\n"))
        .assert()
        .code(0)
        .stdout(predicate::str::contains(a1).and(predicate::str::contains(a2)));
}

#[test]
fn usage_errors() {
    meshping()
        .assert()
        .code(2)
        .stderr(predicate::str::contains("no hosts"));
    meshping()
        .args(["127.0.0.1", "-i", "100ms", "-t", "1s"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--timeout"));
    meshping().args(["127.0.0.1", "-c", "0"]).assert().code(2);
    meshping().args(["bad host"]).assert().code(2);
    meshping().args(["127.0.0.1", "-m", "udp"]).assert().code(2);
}

#[test]
fn unresolvable_host_fails_fast() {
    meshping()
        .args(["nonexistent-zzq.invalid", "-m", "tcp", "-c", "1"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("cannot resolve"));
}
