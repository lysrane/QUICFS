//! TOFU server-certificate verifier (the client side of `known_hosts`).
//!
//! QuicFS has no CA, so we cannot use rustls' WebPKI server verification.
//! Instead this verifier:
//!
//! 1. Still cryptographically verifies the TLS 1.3 handshake signature, proving
//!    the server holds the private key for the cert it presented. (This is NOT
//!    bypassed - skipping it would be security theater.)
//! 2. Pins the server's *public-key* fingerprint:
//!    - **Enforce** mode: the fingerprint MUST equal the one we have on file
//!      (`known_hosts`). Mismatch → hard failure (the ssh "HOST KEY CHANGED"
//!      scenario).
//!    - **Capture** mode: used only on first contact with an unknown host. We
//!      record the fingerprint so the caller can prompt the user, then accept
//!      this handshake. This is the inherent, well-understood TOFU window.
//!
//! Signature verification is delegated to the active rustls `CryptoProvider`,
//! so we are not reimplementing any crypto.

use std::sync::{Arc, Mutex};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};

use quicfs_common::trust::cert_fingerprint;

/// How the verifier treats the server's presented key.
#[derive(Clone)]
pub enum PinMode {
    /// First contact: accept any key but record its fingerprint here.
    Capture(Arc<Mutex<Option<String>>>),
    /// Known host: require an exact fingerprint match.
    Enforce(String),
}

#[derive(Clone)]
pub struct PinningServerVerifier {
    mode: PinMode,
    provider: Arc<CryptoProvider>,
}

impl std::fmt::Debug for PinningServerVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinningServerVerifier").finish()
    }
}

impl PinningServerVerifier {
    pub fn capture(sink: Arc<Mutex<Option<String>>>) -> Self {
        Self {
            mode: PinMode::Capture(sink),
            provider: provider(),
        }
    }

    pub fn enforce(fingerprint: String) -> Self {
        Self {
            mode: PinMode::Enforce(fingerprint),
            provider: provider(),
        }
    }
}

fn provider() -> Arc<CryptoProvider> {
    // The process installs the ring provider in main(); fall back to it here so
    // the verifier works even if called before install (e.g. in tests).
    CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()))
}

impl ServerCertVerifier for PinningServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let fp = cert_fingerprint(end_entity)
            .map_err(|e| TlsError::General(format!("fingerprint server cert: {e}")))?;

        match &self.mode {
            PinMode::Capture(sink) => {
                *sink.lock().unwrap() = Some(fp);
                Ok(ServerCertVerified::assertion())
            }
            PinMode::Enforce(expected) => {
                if &fp == expected {
                    Ok(ServerCertVerified::assertion())
                } else {
                    Err(TlsError::General(format!(
                        "server key fingerprint mismatch: expected {expected}, got {fp}"
                    )))
                }
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
