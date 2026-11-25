//! Parsing of `host:port` endpoints, including bracketed IPv6 literals.

use std::fmt;
use std::net::IpAddr;

/// A host (name or IP literal) and port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

/// Parse `host:port`, `[v6]:port`, or `host` when `default_port` is given.
pub fn parse_endpoint(input: &str, default_port: Option<u16>) -> Result<Endpoint, String> {
    let s = input.trim();
    if s.is_empty() {
        return Err("empty target".into());
    }

    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| format!("invalid target '{input}': missing ']'"))?;
        let host = &rest[..end];
        let after = &rest[end + 1..];
        let port = match after.strip_prefix(':') {
            Some(p) => Some(p),
            None if after.is_empty() => None,
            None => return Err(format!("invalid target '{input}'")),
        };

        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(format!("invalid IPv6 literal '{host}'"));
        }

        (host, port)
    } else if s.parse::<IpAddr>().is_ok() {
        // Bare IPv4 or unbracketed IPv6 literal with no port.
        (s, None)
    } else {
        match s.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (s, None),
        }
    };

    validate_host(host).map_err(|e| format!("invalid target '{input}': {e}"))?;

    let port = match port {
        Some(p) => parse_port(p)?,
        None => default_port.ok_or_else(|| format!("invalid target '{input}': missing port"))?,
    };

    Ok(Endpoint {
        host: host.to_string(),
        port,
    })
}

fn parse_port(p: &str) -> Result<u16, String> {
    match p.parse::<u16>() {
        Ok(0) | Err(_) => Err(format!("invalid port '{p}' (expected 1-65535)")),
        Ok(n) => Ok(n),
    }
}

/// Accept IP literals and RFC 1123 host names (letters, digits, '-', '_', '.').
pub fn validate_host(host: &str) -> Result<(), String> {
    if host.parse::<IpAddr>().is_ok() {
        return Ok(());
    }

    if host.is_empty() || host.len() > 253 {
        return Err("host name length must be 1-253".into());
    }

    for label in host.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err("host name labels must be 1-63 characters".into());
        }

        if label.starts_with('-') || label.ends_with('-') {
            return Err("host name labels must not start or end with '-'".into());
        }

        if !label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err("host name contains invalid characters".into());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(h: &str, p: u16) -> Endpoint {
        Endpoint {
            host: h.into(),
            port: p,
        }
    }

    #[test]
    fn parses_forms() {
        assert_eq!(
            parse_endpoint("example.com:443", None),
            Ok(ep("example.com", 443))
        );
        assert_eq!(
            parse_endpoint("127.0.0.1:80", None),
            Ok(ep("127.0.0.1", 80))
        );
        assert_eq!(parse_endpoint("[::1]:8080", None), Ok(ep("::1", 8080)));
        assert_eq!(parse_endpoint("::1", Some(53)), Ok(ep("::1", 53)));
        assert_eq!(parse_endpoint("host", Some(22)), Ok(ep("host", 22)));
        assert_eq!(parse_endpoint("[::1]", Some(1)), Ok(ep("::1", 1)));
    }

    #[test]
    fn rejects_bad() {
        for bad in [
            "",
            "host",
            "host:0",
            "host:70000",
            "[::1",
            "[zz]:1",
            "a b:1",
            "-x.com:1",
            "x..y:1",
            "host:abc",
        ] {
            assert!(parse_endpoint(bad, None).is_err(), "{bad}");
        }
    }

    #[test]
    fn display_roundtrip() {
        assert_eq!(ep("::1", 1).to_string(), "[::1]:1");
        assert_eq!(ep("a.b", 2).to_string(), "a.b:2");
    }

    proptest::proptest! {
        #[test]
        fn never_panics(s in "\\PC{0,64}") {
            let _ = parse_endpoint(&s, Some(1));
        }

        #[test]
        fn ipv4_roundtrip(a: u8, b: u8, c: u8, d: u8, p in 1u16..) {
            let s = format!("{a}.{b}.{c}.{d}:{p}");
            let e = parse_endpoint(&s, None).unwrap();
            proptest::prop_assert_eq!(e.to_string(), s);
        }
    }
}
