//! HTTP/1.1 probe over plain TCP or rustls.
//!
//! Deliberately minimal: one request, response head only (body not read),
//! `Connection: close`, no redirect following. Timing phases are reported
//! separately (DNS, connect, TLS handshake, time to first byte).

use super::{Outcome, ProbeResult, describe_io, ms, tcp};
use crate::url::HttpUrl;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{
    CryptoProvider, WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum response head size accepted; larger heads are reported as errors.
const MAX_HEAD: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Head,
}

impl Method {
    fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Head => "HEAD",
        }
    }
}

#[derive(Debug, Clone)]
pub struct HttpOptions {
    pub method: Method,
    /// Accepted status codes; empty means 200-399.
    pub expect: Vec<u16>,
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Build the TLS client configuration.
///
/// Trust anchors are the platform's native roots plus any certificates in
/// `ca_file`. With `insecure`, certificate chain and hostname checks are
/// skipped (handshake signatures are still verified).
pub fn client_config(ca_file: Option<&Path>, insecure: bool) -> Result<Arc<ClientConfig>, String> {
    let builder = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS configuration error: {e}"))?;
    let config = if insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertVerification(
                provider().signature_verification_algorithms,
            )))
            .with_no_client_auth()
    } else {
        let mut roots = RootCertStore::empty();
        let native = rustls_native_certs::load_native_certs();
        roots.add_parsable_certificates(native.certs);
        if let Some(path) = ca_file {
            let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(path)
                .map_err(|e| format!("cannot read CA file {}: {e}", path.display()))?
                .collect::<Result<_, _>>()
                .map_err(|e| format!("invalid PEM in {}: {e}", path.display()))?;
            if certs.is_empty() {
                return Err(format!("no certificates found in {}", path.display()));
            }
            let (_, bad) = roots.add_parsable_certificates(certs);
            if bad > 0 {
                return Err(format!(
                    "{bad} unusable certificate(s) in {}",
                    path.display()
                ));
            }
        }
        if roots.is_empty() {
            return Err("no trusted root certificates found on this system; use --ca-file".into());
        }
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    Ok(Arc::new(config))
}

/// Accepts any certificate chain. Only used with explicit `--insecure`.
#[derive(Debug)]
struct NoCertVerification(WebPkiSupportedAlgorithms);

impl ServerCertVerifier for NoCertVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.0)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.0)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_schemes()
    }
}

/// Parsed response status line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusLine {
    pub code: u16,
    pub reason: String,
}

/// Parse `HTTP/1.x NNN reason` from the start of a response head.
pub fn parse_status_line(head: &[u8]) -> Result<StatusLine, String> {
    let end = head.iter().position(|&b| b == b'\n').unwrap_or(head.len());
    let line = std::str::from_utf8(&head[..end])
        .map_err(|_| "non-UTF-8 status line".to_string())?
        .trim_end_matches('\r');
    let mut parts = line.splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    if !(version == "HTTP/1.1" || version == "HTTP/1.0") {
        return Err(format!(
            "not an HTTP/1.x response: '{}'",
            truncate(line, 60)
        ));
    }
    let code = parts
        .next()
        .filter(|c| c.len() == 3)
        .and_then(|c| c.parse::<u16>().ok())
        .filter(|c| (100..=599).contains(c))
        .ok_or_else(|| format!("invalid status line: '{}'", truncate(line, 60)))?;
    Ok(StatusLine {
        code,
        reason: parts.next().unwrap_or_default().to_string(),
    })
}

fn truncate(s: &str, n: usize) -> &str {
    match s.char_indices().nth(n) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

/// Find a header value (case-insensitive name) in a response head.
fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

/// Send the request and read the response head. Returns (head, time-to-first-byte).
async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    request: &[u8],
) -> io::Result<(Vec<u8>, std::time::Duration)> {
    let sent = Instant::now();
    stream.write_all(request).await?;
    stream.flush().await?;
    let mut head = Vec::with_capacity(1024);
    let mut buf = [0u8; 4096];
    let mut ttfb = None;
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            if head.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed before response",
                ));
            }
            break;
        }
        ttfb.get_or_insert_with(|| sent.elapsed());
        // Only rescan the overlap region for the terminator.
        let scan_from = head.len().saturating_sub(3);
        head.extend_from_slice(&buf[..n]);
        if let Some(pos) = head[scan_from..].windows(4).position(|w| w == b"\r\n\r\n") {
            head.truncate(scan_from + pos + 4);
            break;
        }
        if head.len() > MAX_HEAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("response head exceeds {MAX_HEAD} bytes"),
            ));
        }
    }
    Ok((head, ttfb.unwrap_or_default()))
}

pub fn build_request(url: &HttpUrl, method: Method) -> Vec<u8> {
    format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: netprobe/{}\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        method.as_str(),
        url.path,
        url.host_header(),
        env!("CARGO_PKG_VERSION")
    )
    .into_bytes()
}

pub async fn probe(
    url: &HttpUrl,
    tls: Option<&Arc<ClientConfig>>,
    opts: &HttpOptions,
    seq: u32,
) -> ProbeResult {
    let mut r = ProbeResult::new("http", url.display(), seq);
    let start = Instant::now();
    let result = run(url, tls, opts, &mut r).await;
    if let Err(e) = result {
        r.outcome = Outcome::Failed;
        r.error = Some(e);
    }
    r.elapsed_ms = ms(start.elapsed());
    r
}

async fn run(
    url: &HttpUrl,
    tls: Option<&Arc<ClientConfig>>,
    opts: &HttpOptions,
    r: &mut ProbeResult,
) -> Result<(), String> {
    let ep = crate::target::Endpoint {
        host: url.host.clone(),
        port: url.port,
    };
    let t = Instant::now();
    let addrs = tcp::resolve(&ep)
        .await
        .map_err(|e| format!("resolve failed: {}", describe_io(&e)))?;
    r.timings.dns_ms = Some(ms(t.elapsed()));
    let t = Instant::now();
    let (stream, addr) = tcp::connect(&addrs).await.map_err(|e| describe_io(&e))?;
    r.timings.connect_ms = Some(ms(t.elapsed()));
    r.address = Some(addr);
    let request = build_request(url, opts.method);

    let (head, ttfb, tls_info) = if url.tls {
        let config = tls.ok_or("internal error: TLS configuration missing")?;
        let name = ServerName::try_from(url.host.clone())
            .map_err(|e| format!("invalid TLS server name: {e}"))?;
        let t = Instant::now();
        let mut s = tokio_rustls::TlsConnector::from(Arc::clone(config))
            .connect(name, stream)
            .await
            .map_err(|e| format!("TLS handshake failed: {}", tls_error(&e)))?;
        r.timings.tls_ms = Some(ms(t.elapsed()));
        let version = s
            .get_ref()
            .1
            .protocol_version()
            .map(|v| format!("{v:?}"))
            .unwrap_or_default();
        let (h, ttfb) = exchange(&mut s, &request)
            .await
            .map_err(|e| describe_io(&e))?;
        (h, ttfb, Some(version))
    } else {
        let mut s = stream;
        let (h, ttfb) = exchange(&mut s, &request)
            .await
            .map_err(|e| describe_io(&e))?;
        (h, ttfb, None)
    };
    r.timings.first_byte_ms = Some(ms(ttfb));

    let status = parse_status_line(&head)?;
    let head_str = String::from_utf8_lossy(&head);
    let mut detail = format!("HTTP {} {}", status.code, status.reason)
        .trim_end()
        .to_string();
    if let Some(v) = tls_info {
        detail.push_str(&format!(" tls={}", v.replace("TLSv1_", "1.")));
    }
    if (300..400).contains(&status.code)
        && let Some(loc) = header(&head_str, "location")
    {
        detail.push_str(&format!(" location={}", truncate(loc, 200)));
    }
    r.detail = Some(detail);
    let accepted = if opts.expect.is_empty() {
        (200..400).contains(&status.code)
    } else {
        opts.expect.contains(&status.code)
    };
    if accepted {
        r.outcome = Outcome::Ok;
        Ok(())
    } else {
        Err(format!("unexpected status {}", status.code))
    }
}

/// Unwrap rustls errors carried inside io::Error for a clearer message.
fn tls_error(e: &io::Error) -> String {
    match e
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
    {
        Some(tls) => tls.to_string(),
        None => describe_io(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_lines() {
        assert_eq!(
            parse_status_line(b"HTTP/1.1 200 OK\r\n").unwrap(),
            StatusLine {
                code: 200,
                reason: "OK".into()
            }
        );
        assert_eq!(parse_status_line(b"HTTP/1.0 404\r\n").unwrap().code, 404);
        for bad in [
            &b"SSH-2.0-OpenSSH\r\n"[..],
            b"HTTP/1.1 20 OK",
            b"HTTP/1.1 999 X",
            b"HTTP/2 200",
            b"",
        ] {
            assert!(parse_status_line(bad).is_err());
        }
    }

    #[test]
    fn headers() {
        let h = "HTTP/1.1 301 Moved\r\nLocation: https://x/\r\nX-A: b\r\n\r\n";
        assert_eq!(header(h, "location"), Some("https://x/"));
        assert_eq!(header(h, "missing"), None);
    }

    #[test]
    fn request_format() {
        let u = crate::url::parse_url("http://example.com:8080/p?q=1").unwrap();
        let req = String::from_utf8(build_request(&u, Method::Head)).unwrap();
        assert!(req.starts_with("HEAD /p?q=1 HTTP/1.1\r\nHost: example.com:8080\r\n"));
        assert!(req.ends_with("\r\n\r\n"));
    }

    proptest::proptest! {
        #[test]
        fn status_never_panics(b in proptest::collection::vec(proptest::num::u8::ANY, 0..100)) {
            let _ = parse_status_line(&b);
        }
    }
}
