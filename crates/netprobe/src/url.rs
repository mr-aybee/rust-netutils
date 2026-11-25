//! Minimal, strict URL parsing for the HTTP probe (http/https only).

use crate::target::validate_host;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpUrl {
    pub tls: bool,
    pub host: String,
    pub port: u16,
    /// Path and query, always starting with '/'.
    pub path: String,
}

impl HttpUrl {
    /// Value for the Host header (port omitted when default).
    pub fn host_header(&self) -> String {
        let h = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };

        let default = if self.tls { 443 } else { 80 };
        if self.port == default {
            h
        } else {
            format!("{h}:{}", self.port)
        }
    }

    pub fn display(&self) -> String {
        format!(
            "{}://{}{}",
            if self.tls { "https" } else { "http" },
            self.host_header(),
            self.path
        )
    }
}

pub fn parse_url(input: &str) -> Result<HttpUrl, String> {
    let s = input.trim();
    let (tls, rest) = if let Some(r) = s.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = s.strip_prefix("http://") {
        (false, r)
    } else {
        return Err(format!(
            "invalid URL '{input}': scheme must be http:// or https://"
        ));
    };

    // Fragments are never sent to the server.
    let rest = rest.split('#').next().unwrap_or_default();
    let (authority, path) = match rest.find(['/', '?']) {
        Some(i) if rest.as_bytes()[i] == b'?' => (&rest[..i], format!("/{}", &rest[i..])),
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };

    if authority.contains('@') {
        return Err(format!(
            "invalid URL '{input}': credentials in URLs are not supported"
        ));
    }

    if path.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return Err(format!(
            "invalid URL '{input}': path contains whitespace or control characters"
        ));
    }

    let default_port = if tls { 443 } else { 80 };
    let ep = crate::target::parse_endpoint(authority, Some(default_port))
        .map_err(|e| format!("invalid URL '{input}': {e}"))?;
    validate_host(&ep.host)?;
    Ok(HttpUrl {
        tls,
        host: ep.host,
        port: ep.port,
        path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses() {
        let u = parse_url("https://example.com").unwrap();
        assert_eq!(
            (u.tls, u.host.as_str(), u.port, u.path.as_str()),
            (true, "example.com", 443, "/")
        );
        let u = parse_url("http://[::1]:8080/a/b?c=d#frag").unwrap();
        assert_eq!(
            (u.host.as_str(), u.port, u.path.as_str()),
            ("::1", 8080, "/a/b?c=d")
        );
        assert_eq!(u.host_header(), "[::1]:8080");
        let u = parse_url("http://h?x=1").unwrap();
        assert_eq!(u.path, "/?x=1");
        assert_eq!(parse_url("https://a.b:443/x").unwrap().host_header(), "a.b");
    }

    #[test]
    fn rejects() {
        for bad in [
            "ftp://x",
            "example.com",
            "http://",
            "http://u:p@h/",
            "http://h:0/",
            "http://h/a b",
            "http://h/\r\nX: y",
        ] {
            assert!(parse_url(bad).is_err(), "{bad}");
        }
    }

    proptest::proptest! {
        #[test]
        fn never_panics(s in "\\PC{0,80}") {
            let _ = parse_url(&s);
            let _ = parse_url(&format!("http://{s}"));
        }
    }
}
