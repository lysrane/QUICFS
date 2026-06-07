pub mod auth;
pub mod config;
pub mod dispatch;
pub mod endpoint;
pub mod handles;
pub mod ops;
pub mod sanitize;
pub mod session;
pub mod verify;
pub mod writelock;

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tracing::{info, warn};

use crate::session::ClientSession;

/// Maximum time a peer may take to complete the handshake phase (open the first
/// stream and finish the app handshake) before its connection, and the
/// connection slot it holds, is dropped. Independent of and much shorter than
/// the per-RPC timeout and the QUIC idle timeout.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Per-connection configuration derived from the server's config sections.
#[derive(Clone)]
pub struct ConnLimits {
    /// Maximum open file handles per session.
    pub max_open_handles: u32,
    /// Hard wall-clock deadline for each RPC stream.
    pub rpc_timeout: Duration,
    /// fsync each file when its handle is released (durability vs throughput).
    pub sync_on_close: bool,
    /// fsync the parent directory after a namespace mutation so the directory
    /// entry survives a crash (durability vs throughput on metadata ops).
    pub sync_metadata: bool,
}

impl Default for ConnLimits {
    fn default() -> Self {
        Self {
            max_open_handles: 8192,
            rpc_timeout: Duration::from_secs(30),
            sync_on_close: false,
            sync_metadata: false,
        }
    }
}

impl ConnLimits {
    /// Build from the full server config.
    pub fn from_config(cfg: &config::Config) -> Self {
        Self {
            max_open_handles: cfg.limits.max_open_handles,
            rpc_timeout: Duration::from_millis(cfg.limits.rpc_timeout_ms),
            sync_on_close: cfg.durability.sync_on_close,
            sync_metadata: cfg.durability.sync_metadata,
        }
    }
}

/// Accept a single QUIC connection and drive it to completion.
///
/// This is the shared entry-point used by both the server binary and the
/// test harness.  `limits` controls per-session resource caps.
pub async fn handle_connection(
    incoming: quinn::Incoming,
    export_root: Arc<Path>,
    server_id: String,
    limits: ConnLimits,
) -> Result<()> {
    let conn = incoming.await.context("accept connection")?;
    let remote = conn.remote_address();
    info!(remote = %remote, "new connection");

    // The whole handshake phase (accept the first stream + run the app handshake)
    // is bounded by a short timeout. Without it a peer that completes the TLS
    // handshake but then stalls (never opens the stream, or dribbles a partial
    // length-prefixed frame) would pin its max_clients connection slot until the
    // much longer QUIC idle timeout, a slow-loris against the accept path.
    let identity = match tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let (mut send, mut recv) = conn.accept_bi().await.context("accept handshake stream")?;
        ops::ctrl::handle_handshake(&mut send, &mut recv, &conn, &export_root, &server_id).await
    })
    .await
    {
        Ok(Ok(id)) => id,
        Ok(Err(e)) => {
            warn!(remote = %remote, "handshake failed: {e:#}");
            return Err(e);
        }
        Err(_) => {
            warn!(remote = %remote, "handshake timed out");
            anyhow::bail!("handshake timed out");
        }
    };

    // The handshake handler returns the negotiated features in the response
    // we sent; rebuild the list from what we know we support (they are the
    // same because handle_handshake does the intersection internally).
    // For now features are stored in the session for future reference.
    let features: Vec<String> = vec![]; // Phase 6: populate from handshake resp

    info!(remote = %remote, subject = %identity.subject, "handshake complete");
    let session = ClientSession::new(
        identity,
        conn.clone(),
        features,
        limits.max_open_handles,
        limits.sync_on_close,
        limits.sync_metadata,
    );

    let rpc_timeout = limits.rpc_timeout;

    loop {
        match conn.accept_bi().await {
            Ok((send, recv)) => {
                let session = Arc::clone(&session);
                let root = Arc::clone(&export_root);
                tokio::spawn(dispatch::dispatch_stream(
                    send,
                    recv,
                    session,
                    root,
                    rpc_timeout,
                ));
            }
            Err(quinn::ConnectionError::ApplicationClosed(_))
            | Err(quinn::ConnectionError::LocallyClosed) => {
                info!(
                    remote = %remote,
                    subject = %session.identity.subject,
                    open_handles = session.handles.len(),
                    rx_bytes = session.rx_bytes.load(std::sync::atomic::Ordering::Relaxed),
                    tx_bytes = session.tx_bytes.load(std::sync::atomic::Ordering::Relaxed),
                    "connection closed"
                );
                break;
            }
            Err(e) => {
                warn!(remote = %remote, "connection error: {e:#}");
                break;
            }
        }
    }
    Ok(())
}
