use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use quinn::{Endpoint, ServerConfig, TransportConfig, VarInt};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::danger::ClientCertVerifier;

use crate::config::QuicSection;

/// Parse one or more certificates from a PEM string.
pub fn certs_from_pem(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    rustls_pemfile::certs(&mut pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .context("parse cert PEM")
}

/// Parse a private key from a PEM string.
pub fn key_from_pem(pem: &str) -> Result<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut pem.as_bytes())
        .context("parse key PEM")?
        .ok_or_else(|| anyhow::anyhow!("no private key found in PEM"))
}

pub fn build_transport(cfg: &QuicSection) -> Arc<TransportConfig> {
    let mut t = TransportConfig::default();

    t.max_concurrent_bidi_streams(VarInt::from_u32(cfg.max_concurrent_bidi_streams));
    t.keep_alive_interval(Some(Duration::from_millis(cfg.keep_alive_interval_ms)));

    if let Ok(timeout) = VarInt::from_u64(cfg.idle_timeout_ms) {
        t.max_idle_timeout(Some(timeout.into()));
    }

    t.stream_receive_window(VarInt::from_u32(cfg.stream_receive_window));

    if let Ok(window) = VarInt::from_u64(cfg.connection_receive_window) {
        t.receive_window(window);
    }

    Arc::new(t)
}

/// Build a QUIC server endpoint using TOFU key auth.
///
/// `server_cert_pem` / `server_key_pem` are the server's self-signed identity
/// (no CA). `client_verifier` enforces the `authorized_keys` policy. `migration`
/// enables QUIC connection migration so a client that changes IP (Wi-Fi → LTE)
/// keeps its session.
pub fn make_server_endpoint(
    server_cert_pem: &str,
    server_key_pem: &str,
    client_verifier: Arc<dyn ClientCertVerifier>,
    listen_addr: SocketAddr,
    transport: Arc<TransportConfig>,
    migration: bool,
) -> Result<Endpoint> {
    let server_certs = certs_from_pem(server_cert_pem)?;
    let server_key = key_from_pem(server_key_pem)?;

    let mut rustls_cfg = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(server_certs, server_key)
        .context("build rustls ServerConfig")?;
    // Require the QuicFS ALPN. A QUIC peer that does not offer it fails the TLS
    // handshake before reaching the app handshake.
    rustls_cfg.alpn_protocols = vec![quicfs_common::frames::ALPN_PROTOCOL.to_vec()];

    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_cfg)
        .map_err(|e| anyhow::anyhow!("build QuicServerConfig: {e}"))?;

    let mut server_config = ServerConfig::with_crypto(Arc::new(quic_crypto));
    server_config.transport_config(transport);
    // Connection migration: allow a peer to keep its connection when its
    // address changes. This is QuicFS's headline advantage over SSHFS/NFS.
    server_config.migration(migration);

    Endpoint::server(server_config, listen_addr).context("bind QUIC endpoint")
}
