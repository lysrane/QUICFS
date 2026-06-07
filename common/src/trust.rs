//! Trust-on-first-use (TOFU) key pinning - the SSHFS `known_hosts` model.
//!
//! QuicFS does not use a CA. Instead, each peer has a long-lived self-signed
//! certificate wrapping a stable public key. Identity is the SHA-256 fingerprint
//! of that key (the cert's SubjectPublicKeyInfo), formatted exactly like an
//! OpenSSH key fingerprint: `SHA256:<base64-no-pad>`.
//!
//! - The **client** pins each server's fingerprint in `known_hosts` on first
//!   connect (prompting the user, like ssh) and refuses to connect if it ever
//!   changes - this is the host-key-changed warning you know from ssh.
//! - The **server** authorizes client keys via `authorized_keys`, exactly like
//!   `~/.ssh/authorized_keys`.
//!
//! Pinning the *public key* (not the whole cert) means a peer can renew its
//! certificate's metadata/expiry without breaking trust, as long as the key is
//! unchanged - identical semantics to SSH host keys.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use base64::Engine;
use sha2::{Digest, Sha256};

/// Compute the SSH-style fingerprint of an X.509 certificate's public key.
///
/// Returns `SHA256:<base64-no-pad>` over the DER-encoded SubjectPublicKeyInfo -
/// the same value `ssh-keygen -lf` prints for a host key.
pub fn cert_fingerprint(cert_der: &[u8]) -> Result<String> {
    use x509_parser::prelude::*;
    let (_, cert) =
        X509Certificate::from_der(cert_der).map_err(|e| anyhow::anyhow!("parse cert: {e}"))?;
    // `subject_pki.raw` is the full SubjectPublicKeyInfo DER - the stable key identity.
    Ok(fingerprint_of_spki(cert.tbs_certificate.subject_pki.raw))
}

/// Fingerprint a raw SubjectPublicKeyInfo DER blob.
pub fn fingerprint_of_spki(spki_der: &[u8]) -> String {
    let digest = Sha256::digest(spki_der);
    format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest)
    )
}

/// The directory QuicFS stores per-user state in (`~/.config/quicfs` on Linux).
///
/// Honors `$QUICFS_HOME` if set (useful for tests and multi-profile setups).
pub fn config_dir() -> Result<PathBuf> {
    if let Ok(custom) = std::env::var("QUICFS_HOME") {
        return Ok(PathBuf::from(custom));
    }
    let base = dirs::config_dir()
        .or_else(dirs::home_dir)
        .ok_or_else(|| anyhow::anyhow!("cannot determine config directory"))?;
    Ok(base.join("quicfs"))
}

/// Ensure `dir` exists (created with user-only perms where supported).
pub fn ensure_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("create dir: {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

// ── known_hosts (client side: pinned server keys) ────────────────────────────

/// A `known_hosts` file mapping `host:port` → pinned fingerprint.
///
/// Line format (comments with `#` and blank lines ignored):
/// ```text
/// host:port SHA256:base64fingerprint
/// ```
#[derive(Debug, Default)]
pub struct KnownHosts {
    path: PathBuf,
    entries: BTreeMap<String, String>,
}

impl KnownHosts {
    /// Default location: `<config_dir>/known_hosts`.
    pub fn default_path() -> Result<PathBuf> {
        Ok(config_dir()?.join("known_hosts"))
    }

    /// Load from `path`, returning an empty set if the file does not exist.
    pub fn load(path: &Path) -> Result<Self> {
        let mut entries = BTreeMap::new();
        if path.exists() {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("read known_hosts: {}", path.display()))?;
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let mut parts = line.split_whitespace();
                if let (Some(host), Some(fp)) = (parts.next(), parts.next()) {
                    entries.insert(host.to_owned(), fp.to_owned());
                }
            }
        }
        Ok(Self {
            path: path.to_owned(),
            entries,
        })
    }

    /// The pinned fingerprint for `host:port`, if any.
    pub fn get(&self, hostport: &str) -> Option<&str> {
        self.entries.get(hostport).map(|s| s.as_str())
    }

    /// Pin a fingerprint for `host:port` in memory.
    pub fn insert(&mut self, hostport: &str, fingerprint: &str) {
        self.entries
            .insert(hostport.to_owned(), fingerprint.to_owned());
    }

    /// Persist the file (parent dir created, key file restricted to the user).
    pub fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            ensure_dir(parent)?;
        }
        let mut out = String::from("# QuicFS known hosts - managed by quicfs, edit with care\n");
        for (host, fp) in &self.entries {
            out.push_str(host);
            out.push(' ');
            out.push_str(fp);
            out.push('\n');
        }
        std::fs::write(&self.path, out)
            .with_context(|| format!("write known_hosts: {}", self.path.display()))?;
        restrict_file(&self.path);
        Ok(())
    }
}

// ── authorized_keys (server side: permitted client keys) ─────────────────────

/// An `authorized_keys` set of permitted client key fingerprints.
///
/// Line format (comment after the fingerprint is preserved on disk but ignored
/// for matching):
/// ```text
/// SHA256:base64fingerprint  alice@laptop
/// ```
#[derive(Debug, Default)]
pub struct AuthorizedKeys {
    path: PathBuf,
    fingerprints: BTreeMap<String, String>, // fp -> comment
}

impl AuthorizedKeys {
    pub fn load(path: &Path) -> Result<Self> {
        let mut fingerprints = BTreeMap::new();
        if path.exists() {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("read authorized_keys: {}", path.display()))?;
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let mut parts = line.splitn(2, char::is_whitespace);
                if let Some(fp) = parts.next() {
                    let comment = parts.next().unwrap_or("").trim().to_owned();
                    fingerprints.insert(fp.to_owned(), comment);
                }
            }
        }
        Ok(Self {
            path: path.to_owned(),
            fingerprints,
        })
    }

    pub fn default_path() -> Result<PathBuf> {
        Ok(config_dir()?.join("authorized_keys"))
    }

    /// True if no keys are authorized (server is unconfigured for mTLS).
    pub fn is_empty(&self) -> bool {
        self.fingerprints.is_empty()
    }

    /// Whether `fingerprint` is authorized.
    pub fn contains(&self, fingerprint: &str) -> bool {
        self.fingerprints.contains_key(fingerprint)
    }

    /// Add a fingerprint with an optional comment and persist.
    pub fn authorize(&mut self, fingerprint: &str, comment: &str) -> Result<()> {
        self.fingerprints
            .insert(fingerprint.to_owned(), comment.to_owned());
        self.save()
    }

    pub fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            ensure_dir(parent)?;
        }
        let mut out = String::from("# QuicFS authorized client keys\n");
        for (fp, comment) in &self.fingerprints {
            out.push_str(fp);
            if !comment.is_empty() {
                out.push(' ');
                out.push_str(comment);
            }
            out.push('\n');
        }
        std::fs::write(&self.path, out)
            .with_context(|| format!("write authorized_keys: {}", self.path.display()))?;
        // authorized_keys holds only public-key fingerprints (not secrets) and
        // must be readable by the server's service account even when written by
        // a different user (e.g. `sudo quicfs-server authorize`). Use 0644, like
        // ssh's own authorized_keys is readable by the daemon that consults it.
        set_mode(&self.path, 0o644);
        Ok(())
    }
}

/// Validate that a string looks like a `SHA256:...` fingerprint.
pub fn parse_fingerprint(s: &str) -> Result<String> {
    let s = s.trim();
    if !s.starts_with("SHA256:") || s.len() < "SHA256:".len() + 10 {
        bail!("not a valid SHA256 fingerprint: {s:?}");
    }
    Ok(s.to_owned())
}

fn restrict_file(path: &Path) {
    set_mode(path, 0o600);
}

fn set_mode(path: &Path, _mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(_mode));
    }
    #[cfg(not(unix))]
    {
        let _ = path; // best-effort only on non-Unix
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_stable_and_formatted() {
        let fp = fingerprint_of_spki(b"some-spki-bytes");
        assert!(fp.starts_with("SHA256:"));
        // deterministic
        assert_eq!(fp, fingerprint_of_spki(b"some-spki-bytes"));
        assert_ne!(fp, fingerprint_of_spki(b"other-bytes"));
    }

    #[test]
    fn known_hosts_roundtrip() {
        let dir = std::env::temp_dir().join(format!("quicfs-test-kh-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("known_hosts");
        let mut kh = KnownHosts::load(&path).unwrap();
        assert!(kh.get("h:9001").is_none());
        kh.insert("h:9001", "SHA256:abcdef0123456789");
        kh.save().unwrap();
        let kh2 = KnownHosts::load(&path).unwrap();
        assert_eq!(kh2.get("h:9001"), Some("SHA256:abcdef0123456789"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
