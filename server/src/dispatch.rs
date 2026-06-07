use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tracing::{debug, warn};

use quicfs_common::{
    frames::*,
    io::{decode, encode, read_frame, write_frame},
    status::Status,
};

use crate::{ops, session::ClientSession};

/// Dispatch one incoming bidirectional stream to the correct handler.
///
/// `rpc_timeout` is the maximum wall-clock time allowed for a single RPC.
/// Handlers that exceed it receive a SIGKILL-equivalent (the future is
/// dropped) and the client receives no response for that stream - their
/// connection will see a QUIC stream reset.  This prevents a slow or
/// misbehaving filesystem from tying up server worker threads indefinitely.
pub async fn dispatch_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    session: Arc<ClientSession>,
    root: Arc<Path>,
    rpc_timeout: Duration,
) {
    let result = tokio::time::timeout(
        rpc_timeout,
        dispatch_inner(&mut send, &mut recv, &session, &root),
    )
    .await;

    match result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            warn!(session_id = %session.id, "stream error: {e:#}");
        }
        Err(_elapsed) => {
            warn!(
                session_id = %session.id,
                timeout_ms = rpc_timeout.as_millis(),
                "RPC timed out - dropping stream"
            );
        }
    }
}

async fn dispatch_inner(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    session: &Arc<ClientSession>,
    root: &Arc<Path>,
) -> Result<()> {
    let raw = read_frame(recv).await?;
    session.record_rx(raw.len() as u64);

    let env: Envelope = decode(&raw)?;
    debug!(op = format!("0x{:02X}", env.op), seq = env.seq, session = %session.id, "dispatch");

    match env.op {
        // ── Control ───────────────────────────────────────────────────────────
        OP_PING => ops::ctrl::handle_ping(send, recv, &raw, session).await,

        // ── Metadata ──────────────────────────────────────────────────────────
        OP_GET_ATTR => ops::meta::handle_getattr(send, &raw, session, root).await,
        OP_SET_ATTR => ops::meta::handle_setattr(send, &raw, session, root).await,
        OP_READ_DIR => ops::meta::handle_readdir(send, &raw, session, root).await,
        OP_MKDIR => ops::meta::handle_mkdir(send, &raw, session, root).await,
        OP_RMDIR => ops::meta::handle_rmdir(send, &raw, session, root).await,
        OP_UNLINK => ops::meta::handle_unlink(send, &raw, session, root).await,
        OP_RENAME => ops::meta::handle_rename(send, &raw, session, root).await,
        OP_SYMLINK => ops::meta::handle_symlink(send, &raw, session, root).await,
        OP_READLINK => ops::meta::handle_readlink(send, &raw, session, root).await,
        OP_LINK => ops::meta::handle_link(send, &raw, session, root).await,
        OP_STAT_FS => ops::meta::handle_statfs(send, &raw, session, root).await,
        OP_OPEN => ops::meta::handle_open(send, &raw, session, root).await,
        OP_RELEASE => ops::meta::handle_release(send, &raw, session).await,

        // ── Data ──────────────────────────────────────────────────────────────
        OP_READ => ops::data::handle_read(send, &raw, session).await,
        OP_WRITE => ops::data::handle_write(send, recv, &raw, session).await,
        OP_CREATE => ops::data::handle_create(send, &raw, session, root).await,
        OP_FSYNC => ops::data::handle_fsync(send, &raw, session).await,

        unknown => {
            warn!(session_id = %session.id, "unhandled op 0x{unknown:02X}");
            let resp = StatusResponse {
                op: unknown,
                seq: env.seq,
                status: Status::InvalidArg as u8,
            };
            write_frame(send, &encode(&resp)?).await?;
            send.finish()?;
            Ok(())
        }
    }
}
