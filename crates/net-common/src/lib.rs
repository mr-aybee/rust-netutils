//! Shared, dependency-free helpers for rust-netutils binaries.
//!
//! This crate is private (`publish = false`). It holds only conventions that
//! every utility must apply identically: exit codes and duration parsing.

pub mod target;
pub mod time;

use std::fmt;
use std::time::Duration;

/// Process exit statuses shared by all utilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    /// Every requested operation succeeded.
    Ok = 0,
    /// At least one operation failed (refused, timed out, invalid response...).
    Failure = 1,
    /// Invalid command-line usage or configuration.
    Usage = 2,
    /// No failure, but at least one result could not be determined.
    Inconclusive = 3,
    /// No failure, but at least one check needs attention soon (e.g. certificate expiring).
    Warning = 4,
}

impl Status {
    /// Combine two statuses, keeping the most severe one.
    /// Severity: Usage > Failure > Warning > Inconclusive > Ok.
    #[must_use]
    pub fn worst(self, other: Status) -> Status {
        fn rank(s: Status) -> u8 {
            match s {
                Status::Ok => 0,
                Status::Inconclusive => 1,
                Status::Warning => 2,
                Status::Failure => 3,
                Status::Usage => 4,
            }
        }

        if rank(other) > rank(self) {
            other
        } else {
            self
        }
    }

    /// Numeric process exit code.
    #[must_use]
    pub fn code(self) -> u8 {
        self as u8
    }
}

/// Error returned by [`parse_duration`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurationError(String);

impl fmt::Display for DurationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DurationError {}

/// Parse a human duration such as `250ms`, `3s`, `1.5s`, `2m`, `1h`.
/// A bare number is interpreted as seconds. Zero and negative values are rejected.
pub fn parse_duration(input: &str) -> Result<Duration, DurationError> {
    let s = input.trim();
    let split = s
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    if num.is_empty() {
        return Err(DurationError(format!(
            "invalid duration '{input}': missing number"
        )));
    }

    let value: f64 = num
        .parse()
        .map_err(|_| DurationError(format!("invalid duration '{input}': bad number")))?;

    let secs = match unit {
        "" | "s" => value,
        "ms" => value / 1_000.0,
        "us" | "µs" => value / 1_000_000.0,
        "m" => value * 60.0,
        "h" => value * 3_600.0,
        _ => {
            return Err(DurationError(format!(
                "invalid duration '{input}': unknown unit '{unit}'"
            )));
        }
    };

    // Cap at one week to keep arithmetic and timers well-defined.
    if !secs.is_finite() || secs <= 0.0 || secs > 604_800.0 {
        return Err(DurationError(format!(
            "invalid duration '{input}': must be > 0 and <= 7 days"
        )));
    }

    Ok(Duration::from_secs_f64(secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_units() {
        assert_eq!(parse_duration("250ms"), Ok(Duration::from_millis(250)));
        assert_eq!(parse_duration("3s"), Ok(Duration::from_secs(3)));
        assert_eq!(parse_duration("3"), Ok(Duration::from_secs(3)));
        assert_eq!(parse_duration("1.5s"), Ok(Duration::from_millis(1500)));
        assert_eq!(parse_duration("2m"), Ok(Duration::from_secs(120)));
        assert_eq!(parse_duration("1h"), Ok(Duration::from_secs(3600)));
    }

    #[test]
    fn rejects_invalid() {
        for bad in ["", "s", "0", "0ms", "-1s", "1x", "1..2s", "8d", "1000h"] {
            assert!(parse_duration(bad).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn worst_status() {
        use Status::*;
        assert_eq!(Ok.worst(Inconclusive), Inconclusive);
        assert_eq!(Failure.worst(Inconclusive), Failure);
        assert_eq!(Ok.worst(Ok), Ok);
        assert_eq!(Usage.worst(Failure), Usage);
        assert_eq!(Warning.worst(Inconclusive), Warning);
        assert_eq!(Warning.worst(Failure), Failure);
    }
}
