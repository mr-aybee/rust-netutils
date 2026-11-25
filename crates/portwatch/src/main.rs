//! PortWatch command-line entry point.

use std::io::Write;
use std::net::IpAddr;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use net_common::time::{iso8601, now_unix};
use net_common::{Status, parse_duration};
use portwatch::model::{Change, Filter, Scope, Snapshotter, Sock, diff};

#[derive(Debug, Parser)]
#[command(
    name = "portwatch",
    version,
    about = "Inspect and watch TCP/UDP sockets, ports and owning processes"
)]
struct Cli {
    /// Match sockets whose local OR remote port is PORT (repeatable / comma-separated).
    #[arg(short, long = "port", value_delimiter = ',')]
    ports: Vec<u16>,
    /// Match the local port only.
    #[arg(short = 'L', long = "local-port", value_delimiter = ',')]
    local_ports: Vec<u16>,
    /// Match sockets owned by PID.
    #[arg(long = "pid", value_delimiter = ',')]
    pids: Vec<u32>,
    /// Match process names containing NAME (case-insensitive; Linux).
    #[arg(short = 'n', long = "process")]
    process: Option<String>,
    /// Match a local or remote IP address.
    #[arg(short = 'a', long = "address")]
    address: Option<IpAddr>,
    /// TCP states, e.g. LISTEN,ESTABLISHED,TIME_WAIT.
    #[arg(short = 's', long = "state", value_delimiter = ',')]
    states: Vec<String>,
    /// Only listening TCP sockets and bound UDP sockets.
    #[arg(short, long)]
    listening: bool,
    /// TCP only.
    #[arg(short, long, conflicts_with = "udp")]
    tcp: bool,
    /// UDP only.
    #[arg(short, long)]
    udp: bool,
    /// IPv4 only.
    #[arg(short = '4', conflicts_with = "ipv6")]
    ipv4: bool,
    /// IPv6 only.
    #[arg(short = '6')]
    ipv6: bool,
    /// Keep watching and report sockets opening, closing and changing state.
    #[arg(short, long)]
    watch: bool,
    /// Poll interval for --watch.
    #[arg(short, long, default_value = "1s", value_parser = parse_duration)]
    interval: Duration,
    /// JSON output (a document for listing, JSON Lines for --watch).
    #[arg(long)]
    json: bool,
    /// No header, notes or summary.
    #[arg(short, long)]
    quiet: bool,
}

const STATES: &[&str] = &[
    "CLOSED",
    "LISTEN",
    "SYN_SENT",
    "SYN_RCVD",
    "ESTABLISHED",
    "FIN_WAIT_1",
    "FIN_WAIT_2",
    "CLOSE_WAIT",
    "CLOSING",
    "LAST_ACK",
    "TIME_WAIT",
    "DELETE_TCB",
];

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            let _ = e.print();
            return ExitCode::from(if e.use_stderr() {
                Status::Usage.code()
            } else {
                0
            });
        }
    };

    let mut states = Vec::new();
    for s in &cli.states {
        let up = s.trim().to_ascii_uppercase().replace('-', "_");
        let up = match up.as_str() {
            "FIN_WAIT1" => "FIN_WAIT_1".to_string(),
            "FIN_WAIT2" => "FIN_WAIT_2".to_string(),
            "SYN_RECV" | "SYN_RECEIVED" => "SYN_RCVD".to_string(),
            _ => up,
        };

        if !STATES.contains(&up.as_str()) {
            eprintln!(
                "portwatch: unknown TCP state '{s}' (expected one of {})",
                STATES.join(", ")
            );
            return ExitCode::from(Status::Usage.code());
        }

        states.push(up);
    }

    let filter = Filter {
        ports: cli.ports.clone(),
        local_ports: cli.local_ports.clone(),
        pids: cli.pids.clone(),
        states,
        listening: cli.listening,
        process: cli.process.clone(),
        address: cli.address,
    };
    let scope = Scope {
        tcp: !cli.udp,
        udp: !cli.tcp && cli.states.is_empty(),
        ipv4: !cli.ipv6,
        ipv6: !cli.ipv4,
    };
    let mut snapshotter = Snapshotter::default();
    let mut take = || -> Result<Vec<Sock>, String> {
        Ok(snapshotter
            .take(scope)?
            .into_iter()
            .filter(|s| filter.matches(s))
            .collect())
    };

    let current = match take() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("portwatch: {e}");
            return ExitCode::from(Status::Failure.code());
        }
    };

    if !cli.watch {
        print_list(&current, cli.json, cli.quiet);

        // Like grep: no match is status 1, so `portwatch -p 8080` answers "is anything there?".
        return ExitCode::from(if current.is_empty() {
            Status::Failure.code()
        } else {
            Status::Ok.code()
        });
    }

    if !cli.quiet && !cli.json {
        eprintln!(
            "portwatch: watching {} matching socket(s); interval {:?}; Ctrl+C to stop",
            current.len(),
            cli.interval
        );
    }

    let mut previous = current;

    loop {
        std::thread::sleep(cli.interval);

        let now = match take() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("portwatch: {e}");
                continue;
            }
        };

        let time = iso8601(now_unix());
        let mut out = std::io::stdout().lock();

        for change in diff(&previous, &now) {
            let line = if cli.json {
                let mut v = serde_json::to_value(&change).unwrap_or_default();
                v["time"] = serde_json::Value::String(time.clone());
                v.to_string()
            } else {
                match &change {
                    Change::Opened { socket } => format!("{time}  OPENED  {}", row(socket)),
                    Change::Closed { socket } => format!("{time}  CLOSED  {}", row(socket)),
                    Change::State { socket, previous } => {
                        format!("{time}  STATE   {}  (was {previous})", row(socket))
                    }
                }
            };

            if writeln!(out, "{line}").is_err() {
                return ExitCode::from(Status::Ok.code());
            }
        }

        previous = now;
    }
}

fn owner(s: &Sock) -> String {
    match (s.pids.as_slice(), &s.process) {
        ([], _) => "-".into(),
        ([pid], Some(name)) => format!("{pid}/{name}"),
        (pids, Some(name)) => format!(
            "{}/{name}",
            pids.iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(",")
        ),
        (pids, None) => pids
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(","),
    }
}

fn row(s: &Sock) -> String {
    let remote = match s.remote {
        Some(r) if r.port() == 0 && r.ip().is_unspecified() => "*".to_string(),
        Some(r) => r.to_string(),
        None => "*".to_string(),
    };

    format!(
        "{:<4} {:<45} {:<45} {:<11} {}",
        s.proto.to_string(),
        s.local.to_string(),
        remote,
        s.state.as_deref().unwrap_or("-"),
        owner(s)
    )
}

fn print_list(socks: &[Sock], json: bool, quiet: bool) {
    let mut out = std::io::stdout().lock();

    if json {
        let doc = serde_json::json!({"version": 1, "sockets": socks, "count": socks.len()});
        let _ = writeln!(out, "{doc:#}");

        return;
    }

    if !quiet {
        let _ = writeln!(
            out,
            "{:<4} {:<45} {:<45} {:<11} PID/PROCESS",
            "PROTO", "LOCAL", "REMOTE", "STATE"
        );
    }

    for s in socks {
        if writeln!(out, "{}", row(s)).is_err() {
            return;
        }
    }

    if !quiet {
        let hidden = socks.iter().filter(|s| s.pids.is_empty()).count();
        let _ = writeln!(out, "{} socket(s)", socks.len());

        if hidden > 0 {
            eprintln!(
                "portwatch: owner unknown for {hidden} socket(s); other users' processes need elevated privileges"
            );
        }
    }
}
