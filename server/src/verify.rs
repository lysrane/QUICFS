//! Client-certificate verifier (the server side of `authorized_keys`).
//!
//! Like the client's TOFU verifier, this does NOT use a CA. It:
//!
//! 1. Cryptographically verifies the client's TLS handshake signature (proving
//!    the client holds the private key) - delegated to the rustls
//!    `CryptoProvider`, never skipped.
//! 2. Authorizes the client's *public-key* fingerprint against `authorized_keys`,
//!    exactly like `~/.ssh/authorized_keys`:
//!    - If the authorized set is non-empty, the client's fingerprint MUST be in
//!      it, otherwise the handshake is rejected (ssh "Permission denied").
//!    - If the set is empty AND `allow_any_client` is true, any key is accepted
//!      (single-user / trusted-network mode). This is an explicit opt-in, never
//!      the silent default - an empty set with `allow_any_client=false` rejects
//!      everyone and logs the fingerprint the admin needs to authorize.
//!
//! Every rejected/observed client fingerprint is logged so an admin can run
//! `quicfs-server authorize <fp>` to allow it.

use std::sync::Arc;

use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error as TlsError, SignatureScheme};
use tracing::{info, warn};

use quicfs_common::trust::{cert_fingerprint, AuthorizedKeys};

pub struct AuthorizedKeysVerifier {
    authorized: AuthorizedKeys,
    allow_any: bool,
    provider: Arc<CryptoProvider>,
}

impl std::fmt::Debug for AuthorizedKeysVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorizedKeysVerifier")
            .field("allow_any", &self.allow_any)
            .finish()
    }
}

impl AuthorizedKeysVerifier {
    pub fn new(authorized: AuthorizedKeys, allow_any: bool) -> Arc<Self> {
        let provider = CryptoProvider::get_default()
            .cloned()
            .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()));
        if authorized.is_empty() && allow_any {
            warn!("authorized_keys is empty and allow_any_client=true: ACCEPTING ANY CLIENT KEY");
        }
        Arc::new(Self {
            authorized,
            allow_any,
            provider,
        })
    }
}

impl ClientCertVerifier for AuthorizedKeysVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        // No CA → no subject hints to send.
        &[]
    }

    fn client_auth_mandatory(&self) -> bool {
        // A client certificate is REQUIRED. We authorize by key fingerprint, so
        // a connection with no client cert must be rejected outright (never fall
        // through to an unauthenticated session). Stated explicitly rather than
        // relying on the trait default.
        true
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        let fp = cert_fingerprint(end_entity)
            .map_err(|e| TlsError::General(format!("fingerprint client cert: {e}")))?;

        if self.authorized.contains(&fp) {
            info!(fingerprint = %fp, "client key authorized");
            return Ok(ClientCertVerified::assertion());
        }

        if self.authorized.is_empty() && self.allow_any {
            info!(fingerprint = %fp, "accepting client key (allow_any_client)");
            return Ok(ClientCertVerified::assertion());
        }

        warn!(
            fingerprint = %fp,
            "rejected unauthorized client key - run `quicfs-server authorize {}` to allow it",
            fp
        );
        Err(TlsError::General("client key not authorized".into()))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, TlsError> {
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
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, TlsError> {
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
