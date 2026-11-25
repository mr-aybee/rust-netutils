//! Command-line interface definition.

use clap::{Args, Parser, Subcommand};
use net_common::parse_duration;
use std::time::Duration;

#[derive(Debug, Parser)]
#[command(
    name = "netprobe",
    version,
    about = "Multi-protocol network diagnostics",
    propagate_version = true
)]
pub struct Cli {
    /// Emit a single JSON document on stdout instead of human-readable text.
    #[arg(long, global = true)]
    pub json: bool,
    /// Suppress per-attempt lines; print only the summary.
    #[arg(short, long, global = true, conflicts_with = "verbose")]
    pub quiet: bool,
    /// Show timing breakdown for every attempt.
    #[arg(short, long, global = true)]
    pub verbose: bool,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Test TCP connectivity (resolve + connect) to HOST:PORT.
    Tcp {
        /// Target as HOST:PORT or [IPv6]:PORT.
        target: String,
        #[command(flatten)]
        common: Common,
    },
    /// Send an HTTP(S) request and report status and timing phases.
    Http {
        /// URL (http:// or https://).
        url: String,
        /// Use HEAD instead of GET.
        #[arg(long)]
        head: bool,
        /// Accepted status codes (comma-separated). Default: 200-399.
        #[arg(long, value_delimiter = ',')]
        expect: Vec<u16>,
        /// Additional PEM file of trusted CA certificates.
        #[arg(long, value_name = "PEM")]
        ca_file: Option<std::path::PathBuf>,
        /// DANGEROUS: skip certificate chain and hostname verification.
        #[arg(long, conflicts_with = "ca_file")]
        insecure: bool,
        #[command(flatten)]
        common: Common,
    },
    /// Send a UDP datagram and wait for a reply. Silence is reported as inconclusive.
    Udp {
        /// Target as HOST:PORT or [IPv6]:PORT.
        target: String,
        /// Payload text; supports \n \r \t \0 \\ and \xHH escapes.
        #[arg(short, long, conflicts_with = "payload_hex")]
        payload: Option<String>,
        /// Payload as hex digits (whitespace ignored).
        #[arg(long)]
        payload_hex: Option<String>,
        #[command(flatten)]
        common: Common,
    },
    /// Send ICMP echo requests (unprivileged where the OS allows, otherwise raw).
    Icmp {
        /// Host name or IP address.
        host: String,
        #[command(flatten)]
        common: Common,
    },
    /// Run probes listed in FILE (one `<probe> <target>` per line) concurrently.
    Batch {
        /// Target file; use `-` for stdin.
        file: std::path::PathBuf,
        /// Maximum probes in flight.
        #[arg(short = 'j', long, default_value_t = 16, value_parser = clap::value_parser!(u16).range(1..=1024))]
        concurrency: u16,
        /// Additional PEM file of trusted CA certificates for https jobs.
        #[arg(long, value_name = "PEM")]
        ca_file: Option<std::path::PathBuf>,
        #[command(flatten)]
        common: Common,
    },
    /// Resolve NAME and report answers and query latency.
    Dns {
        /// Domain name to query.
        name: String,
        /// Record type: A, AAAA, CNAME, MX, TXT, NS, SOA, PTR, SRV, CAA.
        #[arg(short = 'T', long = "type", default_value = "A")]
        record_type: String,
        /// Query this resolver (IP or IP:PORT, default port 53) instead of the system resolver.
        #[arg(short, long)]
        server: Option<String>,
        #[command(flatten)]
        common: Common,
    },
}

#[derive(Debug, Clone, Args)]
pub struct Common {
    /// Per-attempt deadline (e.g. 500ms, 3s).
    #[arg(short, long, default_value = "3s", value_parser = parse_duration)]
    pub timeout: Duration,
    /// Number of attempts.
    #[arg(short, long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..=1_000_000))]
    pub count: u32,
    /// Delay between attempts.
    #[arg(short, long, default_value = "1s", value_parser = parse_duration)]
    pub interval: Duration,
}
