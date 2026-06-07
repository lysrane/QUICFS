use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use uuid::Uuid;

use crate::auth::ClientIdentity;
use crate::handles::HandleTable;

/// State held for the lifetime of one accepted QUIC connection.
pub struct ClientSession {
    pub id: Uuid,
    pub identity: ClientIdentity,
    pub conn: quinn::Connection,
    pub handles: HandleTable,
    pub rx_bytes: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub connected_at: Instant,
    /// Features negotiated during handshake (intersection of client request
    /// and server support).
    pub features: Vec<String>,
    /// fsync a file when its handle is released (from server durability config).
    pub sync_on_close: bool,
    /// fsync the parent directory after a namespace mutation (from server
    /// durability config) so the directory entry is crash-durable.
    pub sync_metadata: bool,
}

impl ClientSession {
    /// Create a new session.
    ///
    /// `max_handles` sets the per-session open-handle limit; passing
    /// `u32::MAX` disables it (not recommended on public servers).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        identity: ClientIdentity,
        conn: quinn::Connection,
        features: Vec<String>,
        max_handles: u32,
        sync_on_close: bool,
        sync_metadata: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            id: Uuid::new_v4(),
            identity,
            conn,
            handles: HandleTable::with_limit(max_handles),
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            connected_at: Instant::now(),
            features,
            sync_on_close,
            sync_metadata,
        })
    }

    pub fn record_rx(&self, n: u64) {
        self.rx_bytes.fetch_add(n, Ordering::Relaxed);
    }

    pub fn record_tx(&self, n: u64) {
        self.tx_bytes.fetch_add(n, Ordering::Relaxed);
    }
}
