//! TLS connection that records the presented chain and the real verification verdict.
//!
//! The handshake is allowed to complete even when verification fails so the
//! chain can be inspected. Nothing is ever sent over the connection: it is
//! closed immediately after the handshake. A failed verification is always
//! reported as a failure; it is never hidden.

use std::path::Path;
use std::sync::{Arc, Mutex};

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};

/// The *ring* crypto provider used for all TLS operations.
pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Build the shared WebPKI verifier from native roots plus optional extra CAs.
pub fn webpki_verifier(
    ca_file: Option<&Path>,
    include_native: bool,
) -> Result<Arc<WebPkiServerVerifier>, String> {
    let mut roots = RootCertStore::empty();

    if include_native {
        roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
    }

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
        return Err("no trusted root certificates available; use --ca-file".into());
    }

    WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider())
        .build()
        .map_err(|e| format!("cannot build certificate verifier: {e}"))
}

/// Wraps the real verifier and records its verdict instead of aborting.
#[derive(Debug)]
pub struct RecordingVerifier {
    inner: Arc<WebPkiServerVerifier>,
    verdict: Mutex<Option<Result<(), rustls::Error>>>,
}

impl RecordingVerifier {
    /// Wrap `inner`; the verdict is recorded on the first certificate verification.
    pub fn new(inner: Arc<WebPkiServerVerifier>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            verdict: Mutex::new(None),
        })
    }

    /// The verification verdict, if the server presented a certificate.
    pub fn verdict(&self) -> Option<Result<(), rustls::Error>> {
        self.verdict.lock().map(|g| g.clone()).unwrap_or(None)
    }

    /// Client configuration that verifies through this recorder.
    pub fn client_config(self: &Arc<Self>) -> Result<Arc<ClientConfig>, String> {
        let cfg = ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("TLS configuration error: {e}"))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::clone(self) as Arc<dyn ServerCertVerifier>)
            .with_no_client_auth();
        Ok(Arc::new(cfg))
    }
}

impl ServerCertVerifier for RecordingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let result = self
            .inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp, now)
            .map(|_| ());

        if let Ok(mut g) = self.verdict.lock() {
            *g = Some(result);
        }

        Ok(ServerCertVerified::assertion())
    }

    // Handshake signatures are always checked for real.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Classify a verification error into a stable category and message.
pub fn classify(err: &rustls::Error) -> (&'static str, String) {
    use rustls::CertificateError as C;

    match err {
        rustls::Error::InvalidCertificate(c) => {
            let kind = match c {
                C::Expired | C::ExpiredContext { .. } => "expired",
                C::NotValidYet | C::NotValidYetContext { .. } => "not_yet_valid",
                C::NotValidForName | C::NotValidForNameContext { .. } => "hostname_mismatch",
                C::UnknownIssuer => "untrusted",
                C::Revoked => "revoked",
                C::BadSignature | C::UnsupportedSignatureAlgorithmContext { .. } => "bad_signature",
                _ => "invalid",
            };

            let msg = match c {
                C::UnknownIssuer => {
                    "untrusted: unknown issuer (incomplete chain, private CA, or self-signed)"
                        .to_string()
                }
                _ => err.to_string(),
            };

            (kind, msg)
        }
        other => ("invalid", other.to_string()),
    }
}
