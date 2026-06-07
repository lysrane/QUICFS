//! Client identity.
//!
//! QuicFS authenticates clients solely by their TLS key, authorized via
//! fingerprint in `authorized_keys` (see [`crate::verify`]). There is no token
//! auth and no application-layer cryptography here - the only trusted identity
//! is the client's key fingerprint, established by the TLS handshake.

/// Resolved client identity after key authentication.
#[derive(Debug, Clone)]
pub struct ClientIdentity {
    /// The client's key fingerprint (`SHA256:...`) - the value `authorized_keys`
    /// authorized. Used for logging and session attribution.
    pub subject: String,
}

/// Construct an identity from the client's key fingerprint.
pub fn from_mtls_fingerprint(fingerprint: &str) -> ClientIdentity {
    ClientIdentity {
        subject: fingerprint.to_owned(),
    }
}
