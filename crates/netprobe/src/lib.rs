//! NetProbe: multi-protocol network diagnostics.
//!
//! The binary is a thin CLI over this library so probes can be exercised
//! directly by integration tests and benchmarks.

pub mod batch;
pub mod cli;
pub mod output;
pub mod probe;
pub mod runner;
pub mod stats;
/// Endpoint parsing, shared with other rust-netutils binaries.
pub use net_common::target;
pub mod url;
