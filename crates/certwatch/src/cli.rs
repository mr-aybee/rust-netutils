//! Command-line interface.

use std::path::PathBuf;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use net_common::parse_duration;

#[derive(Debug, Parser)]
#[command(
    name = "certwatch",
    version,
    about = "TLS certificate inspection and expiry monitoring",
    propagate_version = true
)]
/// Parsed command line.
pub struct Cli {
    /// Emit a single JSON document on stdout.
    #[arg(long, global = true)]
    pub json: bool,
    /// Print only problems and the summary.
    #[arg(short, long, global = true, conflicts_with = "verbose")]
    pub quiet: bool,
    /// Show the full certificate chain.
    #[arg(short, long, global = true)]
    pub verbose: bool,
    /// Selected subcommand.
    #[command(subcommand)]
    pub command: Command,
}

/// Available subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Connect to TLS endpoints and validate their certificates.
    Check {
        /// Targets as HOST[:PORT] (default port 443).
        targets: Vec<String>,
        /// Read additional targets from FILE (one per line, `#` comments; `-` for stdin).
        #[arg(short, long)]
        file: Option<PathBuf>,
        /// Server name to send (SNI) and validate against, instead of the target host.
        #[arg(long)]
        sni: Option<String>,
        /// Additional PEM file of trusted CA certificates.
        #[arg(long, value_name = "PEM")]
        ca_file: Option<PathBuf>,
        /// Trust only --ca-file, ignoring the platform trust store.
        #[arg(long, requires = "ca_file")]
        no_system_roots: bool,
        /// Deadline per target.
        #[arg(short, long, default_value = "5s", value_parser = parse_duration)]
        timeout: Duration,
        /// Maximum targets checked concurrently.
        #[arg(short = 'j', long, default_value_t = 20, value_parser = clap::value_parser!(u16).range(1..=1024))]
        concurrency: u16,
        /// Expiry thresholds.
        #[command(flatten)]
        policy: PolicyArgs,
    },
    /// Inspect local certificate files (PEM bundle or DER).
    Inspect {
        /// Certificate files.
        #[arg(required = true)]
        files: Vec<PathBuf>,
        /// Expiry thresholds.
        #[command(flatten)]
        policy: PolicyArgs,
    },
}

/// Expiry threshold options shared by `check` and `inspect`.
#[derive(Debug, Clone, Args)]
pub struct PolicyArgs {
    /// Warn when a certificate expires within this many days.
    #[arg(short, long, default_value_t = 30)]
    pub warn_days: i64,
    /// Fail when a certificate expires within this many days.
    #[arg(short = 'C', long, default_value_t = 7)]
    pub crit_days: i64,
}
