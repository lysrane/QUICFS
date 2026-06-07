//! Persistent self-signed identity (a long-lived keypair + self-signed cert).
//!
//! Both the server and the client have one of these. There is no CA. The cert
//! exists only to carry the public key over TLS 1.3 (which mandates certs); the
//! *key* is the identity, fingerprinted and pinned via [`crate::trust`].
//!
//! Keys are generated once and reused. The cert is given an absurdly long
//! validity because expiry is meaningless under key-pinning (our custom
//! verifiers don't check it), and re-issuing must not change the pinned key.

use std::path::Path;

use anyhow::{Context, Result};
use rcgen::{date_time_ymd, CertificateParams, DnType, KeyPair};

use crate::trust::{cert_fingerprint, ensure_dir};

/// A loaded identity: PEM cert + PEM private key + its key fingerprint.
#[derive(Clone)]
pub struct Identity {
    pub cert_pem: String,
    pub key_pem: String,
    pub fingerprint: String,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material.
        f.debug_struct("Identity")
            .field("fingerprint", &self.fingerprint)
            .finish()
    }
}

impl Identity {
    /// Load the identity at `<dir>/<name>.crt` + `<dir>/<name>.key`, generating
    /// a fresh self-signed identity (CN = `common_name`) if either file is absent.
    ///
    /// This is what makes `quicfs user@host /mnt` work with zero setup: the
    /// client mints its own key on first run, just like ssh would create one.
    pub fn load_or_generate(dir: &Path, name: &str, common_name: &str) -> Result<Self> {
        let cert_path = dir.join(format!("{name}.crt"));
        let key_path = dir.join(format!("{name}.key"));
        Self::load_or_generate_at(&cert_path, &key_path, common_name)
    }

    /// Like [`load_or_generate`](Self::load_or_generate) but with explicit cert
    /// and key paths (used when the server config points at specific files).
    pub fn load_or_generate_at(
        cert_path: &Path,
        key_path: &Path,
        common_name: &str,
    ) -> Result<Self> {
        if cert_path.exists() && key_path.exists() {
            let cert_pem = std::fs::read_to_string(cert_path)
                .with_context(|| format!("read cert: {}", cert_path.display()))?;
            let key_pem = std::fs::read_to_string(key_path)
                .with_context(|| format!("read key: {}", key_path.display()))?;
            let fingerprint = fingerprint_of_pem(&cert_pem)?;
            return Ok(Self {
                cert_pem,
                key_pem,
                fingerprint,
            });
        }

        let id = Self::generate(common_name)?;
        if let Some(parent) = cert_path.parent() {
            ensure_dir(parent)?;
        }
        if let Some(parent) = key_path.parent() {
            ensure_dir(parent)?;
        }
        std::fs::write(cert_path, &id.cert_pem)
            .with_context(|| format!("write cert: {}", cert_path.display()))?;
        write_key(key_path, &id.key_pem)
            .with_context(|| format!("write key: {}", key_path.display()))?;
        Ok(id)
    }

    /// Generate a fresh in-memory self-signed identity (does not touch disk).
    pub fn generate(common_name: &str) -> Result<Self> {
        let key = KeyPair::generate().context("generate keypair")?;
        // SAN must be a valid DNS name; fall back to "quicfs" if the CN isn't.
        let san = if common_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        {
            common_name.to_owned()
        } else {
            "quicfs".to_owned()
        };
        let mut params = CertificateParams::new(vec![san]).context("build cert params")?;
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.not_before = date_time_ymd(2020, 1, 1);
        params.not_after = date_time_ymd(4096, 1, 1);

        let cert = params.self_signed(&key).context("self-sign cert")?;
        let cert_pem = cert.pem();
        let key_pem = key.serialize_pem();
        let fingerprint = fingerprint_of_pem(&cert_pem)?;
        Ok(Self {
            cert_pem,
            key_pem,
            fingerprint,
        })
    }
}

/// Compute the key fingerprint of the first certificate in a PEM string.
pub fn fingerprint_of_pem(cert_pem: &str) -> Result<String> {
    let der = rustls_pemfile_first_cert(cert_pem)?;
    cert_fingerprint(&der)
}

/// Minimal PEM cert extractor (avoids a hard dep on rustls in `common`).
fn rustls_pemfile_first_cert(pem: &str) -> Result<Vec<u8>> {
    // Find the first CERTIFICATE block and base64-decode it.
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let start = pem
        .find(BEGIN)
        .ok_or_else(|| anyhow::anyhow!("no CERTIFICATE block in PEM"))?;
    let after = start + BEGIN.len();
    let end = pem[after..]
        .find(END)
        .ok_or_else(|| anyhow::anyhow!("unterminated CERTIFICATE block"))?;
    let b64: String = pem[after..after + end].split_whitespace().collect();
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .context("base64-decode certificate")
}

/// Write the private key so it is owner-only (0600) BEFORE any key bytes hit
/// disk - avoiding the umask-default-then-chmod window that would briefly expose
/// the key on a shared host. A failure to lock down the permissions is surfaced
/// (the `?`), not swallowed, so the key is never left wider than 0600.
fn write_key(path: &Path, pem: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        // `mode()` applies only when the file is created; enforce 0600 for a
        // pre-existing file too, and do it BEFORE writing the key bytes.
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        f.write_all(pem.as_bytes())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, pem)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_pinnable_identity() {
        let id = Identity::generate("test-host").unwrap();
        assert!(id.fingerprint.starts_with("SHA256:"));
        assert!(id.cert_pem.contains("BEGIN CERTIFICATE"));
        // The fingerprint of the emitted cert PEM matches the stored one.
        assert_eq!(id.fingerprint, fingerprint_of_pem(&id.cert_pem).unwrap());
    }
}
