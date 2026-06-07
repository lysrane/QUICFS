use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use tracing::{debug, warn};

use quicfs_common::{
    frames::{
        Envelope, HandshakeRequest, HandshakeResponse, PingRequest, PingResponse, OP_HANDSHAKE,
        OP_PING,
    },
    io::{decode, encode, read_frame, write_frame},
    status::Status,
};

use crate::{auth::ClientIdentity, session::ClientSession};

/// Maximum chunk_size the server will accept from a client.
const MAX_CHUNK_SIZE: u32 = 4 * 1024 * 1024; // 4 MiB

/// Handle the mandatory Handshake stream (must be the first stream opened).
///
/// Identity is the client's TLS key fingerprint (authorized in `authorized_keys`
/// at the TLS layer); this negotiates feature flags + chunk size and returns the
/// identity.  Any failure sends an error response to the client before returning
/// `Err`, so the caller does not need to send a second error.
pub async fn handle_handshake(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    conn: &quinn::Connection,
    export_root: &Path,
    server_id: &str,
) -> Result<ClientIdentity> {
    let raw = read_frame(recv).await?;
    let env: Envelope = decode(&raw)?;

    if env.op != OP_HANDSHAKE {
        anyhow::bail!("expected Handshake (0xF0), got 0x{:02X}", env.op);
    }

    let req: HandshakeRequest = decode(&raw)?;
    debug!(seq = req.seq, client_id = %req.client_id, auth_type = %req.auth_type, "handshake");

    // ── chunk_size validation ─────────────────────────────────────────────────
    if req.chunk_size > MAX_CHUNK_SIZE {
        warn!(
            chunk_size = req.chunk_size,
            max = MAX_CHUNK_SIZE,
            "client requested oversized chunk_size"
        );
        send_handshake_error(send, req.seq, Status::InvalidArg).await?;
        anyhow::bail!(
            "chunk_size {} exceeds maximum {}",
            req.chunk_size,
            MAX_CHUNK_SIZE
        );
    }
    let chunk_size = req.chunk_size.min(MAX_CHUNK_SIZE);

    // ── Authentication ────────────────────────────────────────────────────────
    // The client is already authenticated at the TLS layer by its key fingerprint
    // (AuthorizedKeysVerifier). Identity == that fingerprint. The cert CN is
    // attacker-chosen and must never be trusted; we log it for diagnostics only.
    if req.auth_type != "mtls" {
        warn!(
            "unsupported auth_type '{}' from client '{}'",
            req.auth_type, req.client_id
        );
        send_handshake_error(send, req.seq, Status::Permission).await?;
        anyhow::bail!("unsupported auth_type: {}", req.auth_type);
    }
    let fingerprint = extract_mtls_fingerprint(conn).unwrap_or_else(|| {
        warn!("mTLS: failed to fingerprint peer certificate; using 'unknown'");
        "unknown".to_string()
    });
    debug!(fingerprint = %fingerprint, "client authenticated by key");
    let identity = crate::auth::from_mtls_fingerprint(&fingerprint);

    // ── Feature negotiation ───────────────────────────────────────────────────
    // Only advertise features that are actually implemented.
    let supported = supported_features();
    let negotiated: Vec<String> = req
        .features
        .iter()
        .filter(|f| supported.contains(&f.as_str()))
        .cloned()
        .collect();

    // ── Build and send response ───────────────────────────────────────────────
    let resp = HandshakeResponse {
        op: OP_HANDSHAKE,
        seq: req.seq,
        status: Status::Ok as u8,
        version: 1,
        features: negotiated,
        chunk_size,
        server_id: server_id.to_owned(),
        export_root: export_root
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("export")
            .to_owned(),
    };

    let encoded = encode(&resp)?;
    write_frame(send, &encoded).await?;
    send.finish()?;
    Ok(identity)
}

/// Handle a Ping request.
pub async fn handle_ping(
    send: &mut quinn::SendStream,
    _recv: &mut quinn::RecvStream,
    raw: &[u8],
    session: &Arc<ClientSession>,
) -> Result<()> {
    let req: PingRequest = decode(raw)?;
    let resp = PingResponse {
        op: OP_PING,
        seq: req.seq,
        status: Status::Ok as u8,
    };
    let encoded = encode(&resp)?;
    write_frame(send, &encoded).await?;
    send.finish()?;
    session.record_tx(encoded.len() as u64);
    Ok(())
}

/// Features this server actually implements.
///
/// Only list features here that have complete handler implementations.
/// Advertising an unimplemented feature causes clients to send requests
/// the server cannot answer correctly.
fn supported_features() -> &'static [&'static str] {
    // xattr is defined in the protocol (opcodes 0x30-0x33) but not yet
    // implemented server-side.  It will be added in Phase 6.
    &[]
}

async fn send_handshake_error(
    send: &mut quinn::SendStream,
    seq: u64,
    status: Status,
) -> Result<()> {
    let resp = HandshakeResponse {
        op: OP_HANDSHAKE,
        seq,
        status: status as u8,
        version: 1,
        features: vec![],
        chunk_size: 0,
        server_id: String::new(),
        export_root: String::new(),
    };
    write_frame(send, &encode(&resp)?).await?;
    send.finish()?;
    Ok(())
}

/// Compute the client's key fingerprint (SHA256 of the cert SPKI) from the mTLS
/// peer certificate. This is the authoritative identity - it matches what the
/// server's `authorized_keys` policy authorizes.
fn extract_mtls_fingerprint(conn: &quinn::Connection) -> Option<String> {
    let identity = conn.peer_identity()?;
    let certs = identity.downcast_ref::<Vec<rustls::pki_types::CertificateDer<'static>>>()?;
    let cert_der = certs.first()?;
    quicfs_common::trust::cert_fingerprint(cert_der).ok()
}
