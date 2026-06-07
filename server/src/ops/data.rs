use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Arc;

use anyhow::Result;

use quicfs_common::{
    frames::*,
    io::{decode, encode, read_frame, write_frame},
    status::Status,
};

use crate::ops::meta::metadata_to_stat;
use crate::sanitize;
use crate::session::ClientSession;

/// Maximum bytes read from disk in one `file.read()` call.
/// Bounds the per-call allocation regardless of what the client requests.
const CHUNK: usize = 256 * 1024; // 256 KiB

/// Maximum bytes a client may request in a single Read RPC.
/// Prevents memory exhaustion from a client requesting a huge single read.
/// Clients that need more data must issue multiple Read RPCs.
const MAX_READ_REQUEST: u32 = 16 * 1024 * 1024; // 16 MiB

// ── Read ──────────────────────────────────────────────────────────────────────

pub async fn handle_read(
    send: &mut quinn::SendStream,
    raw: &[u8],
    session: &Arc<ClientSession>,
) -> Result<()> {
    let req: ReadRequest = decode(raw)?;

    // Reject oversized read requests to prevent memory exhaustion.
    if req.length > MAX_READ_REQUEST {
        return send_read_err(send, req.seq, req.offset, Status::InvalidArg).await;
    }

    // Use the RETAINED fd (opened at Open/Create), never reopen by path.
    let file = match session.handles.get_file(req.handle) {
        Some(f) => f,
        None => return send_read_err(send, req.seq, req.offset, Status::Stale).await,
    };

    let mut remaining = req.length as usize;
    let mut offset = req.offset;

    while remaining > 0 {
        let to_read = remaining.min(CHUNK);
        let mut buf = vec![0u8; to_read];
        // Seek+read under the lock, then release it before the async send so we
        // never hold a std Mutex across an .await.
        let read_result = {
            let mut f = file.lock().unwrap_or_else(|e| e.into_inner());
            f.seek(SeekFrom::Start(offset))
                .and_then(|_| f.read(&mut buf))
        };
        let n = match read_result {
            Ok(n) => n,
            Err(e) => return send_read_err(send, req.seq, offset, Status::from(e)).await,
        };
        buf.truncate(n);
        // n == 0 is the canonical EOF signal from std::io::Read.
        let eof = n == 0;
        remaining = remaining.saturating_sub(n);
        let last_frame = eof || remaining == 0;

        let resp = ReadResponse {
            op: OP_READ,
            seq: req.seq,
            status: Status::Ok as u8,
            offset,
            data: buf,
            eof: last_frame,
        };
        let encoded = encode(&resp)?;
        write_frame(send, &encoded).await?;
        session.record_tx(encoded.len() as u64);

        if eof {
            break;
        }
        offset += n as u64;
    }

    send.finish()?;
    Ok(())
}

// ── Write ─────────────────────────────────────────────────────────────────────

pub async fn handle_write(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    raw: &[u8],
    session: &Arc<ClientSession>,
) -> Result<()> {
    let first: WriteRequest = decode(raw)?;
    let seq = first.seq;

    // Use the RETAINED fd (opened at Open/Create), never reopen by path. Also
    // pull the open flags (to honor O_APPEND) and the inode key (to take the
    // per-inode write-serialization stripe).
    let (file, flags, ino_key) = match session.handles.get_write_ctx(first.handle) {
        Some(t) => t,
        None => {
            let resp = WriteResponse {
                op: OP_WRITE,
                seq,
                status: Status::Stale as u8,
                written: 0,
            };
            write_frame(send, &encode(&resp)?).await?;
            send.finish()?;
            return Ok(());
        }
    };
    let append = flags & 0x400 != 0; // O_APPEND

    // Serialize all writes to THIS physical file (across handles and sessions)
    // for the whole RPC, so a multi-frame write lands as one contiguous unit and
    // cannot be torn byte-for-byte by a concurrent writer. The guard is held
    // across the inter-frame network reads; a slow writer can therefore stall
    // other writers to the same file, bounded by the per-RPC timeout. Reads are
    // unaffected (they take only the per-handle fd lock). See crate::writelock.
    let _write_guard = crate::writelock::stripe_for(ino_key).lock().await;

    // Use u64 accumulator to avoid integer overflow on large writes.
    let mut total: u64 = 0;
    let mut done = first.done;

    // Each chunk is seek+write under the lock (released before the next .await).
    let first_w = {
        let mut f = file.lock().unwrap_or_else(|e| e.into_inner());
        write_at(&mut f, first.offset, &first.data, &mut total, append)
    };
    if let Err(e) = first_w {
        let resp = WriteResponse {
            op: OP_WRITE,
            seq,
            status: Status::from(e) as u8,
            written: total,
        };
        write_frame(send, &encode(&resp)?).await?;
        send.finish()?;
        return Ok(());
    }

    while !done {
        let chunk_raw = read_frame(recv).await?;
        session.record_rx(chunk_raw.len() as u64);
        let chunk: WriteRequest = decode(&chunk_raw)?;
        done = chunk.done;
        let w = {
            let mut f = file.lock().unwrap_or_else(|e| e.into_inner());
            write_at(&mut f, chunk.offset, &chunk.data, &mut total, append)
        };
        if let Err(e) = w {
            let resp = WriteResponse {
                op: OP_WRITE,
                seq,
                status: Status::from(e) as u8,
                written: total,
            };
            write_frame(send, &encode(&resp)?).await?;
            send.finish()?;
            return Ok(());
        }
    }

    let resp = WriteResponse {
        op: OP_WRITE,
        seq,
        status: Status::Ok as u8,
        written: total,
    };
    let encoded = encode(&resp)?;
    write_frame(send, &encoded).await?;
    send.finish()?;
    session.record_tx(encoded.len() as u64);
    Ok(())
}

// ── Create ────────────────────────────────────────────────────────────────────

pub async fn handle_create(
    send: &mut quinn::SendStream,
    raw: &[u8],
    session: &Arc<ClientSession>,
    root: &Path,
) -> Result<()> {
    let req: CreateRequest = decode(raw)?;
    let resolved = match sanitize::resolve(root, &req.path) {
        Ok(p) => p,
        Err(_) => {
            let resp = OpenResponse {
                op: OP_CREATE,
                seq: req.seq,
                status: Status::Permission as u8,
                handle: 0,
                stat: None,
            };
            write_frame(send, &encode(&resp)?).await?;
            send.finish()?;
            return Ok(());
        }
    };

    // Open the new file confined beneath the export root.
    //
    // SECURITY: never create a file THROUGH a symlink at the final component.
    // A client can plant `<root>/x -> /outside/path` (handle_symlink stores the
    // target verbatim); if that target does not exist yet, sanitize::resolve()
    // cannot catch it - `Path::exists()` follows the symlink, so a dangling target
    // reads as "absent" and the canonicalize escape-check is skipped. O_NOFOLLOW
    // makes the kernel fail with ELOOP if the leaf is a symlink, and on Linux
    // sanitize::open_confined adds openat2(RESOLVE_BENEATH) so an intermediate
    // component swapped to a symlink after resolve() ran also cannot escape.
    #[cfg(unix)]
    let opened: std::io::Result<std::fs::File> = {
        let mut flags = libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW;
        if req.flags & 0x80 != 0 {
            flags |= libc::O_EXCL;
        } // O_EXCL
        if req.flags & 0x200 != 0 {
            flags |= libc::O_TRUNC;
        } // O_TRUNC
        if req.flags & 0x400 != 0 {
            flags |= libc::O_APPEND;
        } // O_APPEND
        sanitize::open_confined(root, &resolved, flags, (req.mode & 0o777) as libc::mode_t)
    };
    #[cfg(not(unix))]
    let opened: std::io::Result<std::fs::File> = {
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true).write(true);
        if req.flags & 0x80 != 0 {
            opts.create_new(true);
        } else {
            opts.create(true);
        }
        if req.flags & 0x200 != 0 {
            opts.truncate(true);
        }
        if req.flags & 0x400 != 0 {
            opts.append(true);
        }
        opts.open(&resolved)
    };

    let (status, stat, handle) = match opened {
        Err(e) => (Status::from(e), None, 0u64),
        Ok(f) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                // Mask to permission bits only: never let a client set
                // setuid/setgid/sticky on a file it creates on the server host.
                let _ = f.set_permissions(std::fs::Permissions::from_mode(req.mode & 0o777));
            }
            // Stat from the open fd (race-free), then retain the fd in the handle
            // so Read/Write/Fsync never reopen this path by name.
            let stat = f.metadata().ok().map(|m| metadata_to_stat(&m, &resolved));
            match session.handles.try_insert(resolved.clone(), req.flags, f) {
                Ok(handle) => {
                    // Durability: make the new directory entry survive a crash.
                    // Best effort and AFTER the handle is retained - a fsync
                    // failure is logged, never reported as a create failure (the
                    // file already exists and the client holds a valid handle;
                    // see crate::ops::sync_parent_dir).
                    if session.sync_metadata {
                        crate::ops::sync_parent_dir(root, &resolved);
                    }
                    (Status::Ok, stat, handle)
                }
                Err(_) => (Status::NoSpace, None, 0),
            }
        }
    };

    let resp = OpenResponse {
        op: OP_CREATE,
        seq: req.seq,
        status: status as u8,
        handle,
        stat,
    };
    let encoded = encode(&resp)?;
    write_frame(send, &encoded).await?;
    send.finish()?;
    session.record_tx(encoded.len() as u64);
    Ok(())
}

// ── Fsync ─────────────────────────────────────────────────────────────────────

pub async fn handle_fsync(
    send: &mut quinn::SendStream,
    raw: &[u8],
    session: &Arc<ClientSession>,
) -> Result<()> {
    let req: FsyncRequest = decode(raw)?;
    // Sync the RETAINED fd, never reopen by path.
    let file = match session.handles.get_file(req.handle) {
        Some(f) => f,
        None => {
            let resp = StatusResponse {
                op: OP_FSYNC,
                seq: req.seq,
                status: Status::Stale as u8,
            };
            let encoded = encode(&resp)?;
            write_frame(send, &encoded).await?;
            send.finish()?;
            return Ok(());
        }
    };
    let status = {
        let f = file.lock().unwrap_or_else(|e| e.into_inner());
        if req.datasync {
            f.sync_data()
        } else {
            f.sync_all()
        }
    }
    .map(|_| Status::Ok)
    .unwrap_or_else(Status::from);

    let resp = StatusResponse {
        op: OP_FSYNC,
        seq: req.seq,
        status: status as u8,
    };
    let encoded = encode(&resp)?;
    write_frame(send, &encoded).await?;
    send.finish()?;
    session.record_tx(encoded.len() as u64);
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Write `data` at `offset` into `f`, accumulating total bytes into `total`.
///
/// Uses a u64 accumulator to avoid the integer overflow that would occur with
/// u32 after writing ≥ 4 GiB across multiple Write frames in one RPC.
///
/// When `append` is set the handle was opened O_APPEND: the kernel writes every
/// `write(2)` at the current EOF atomically regardless of the file offset, so we
/// skip the (ineffective) seek and let the client-supplied offset be ignored.
/// This is what makes concurrent appenders not clobber each other.
fn write_at(
    f: &mut std::fs::File,
    offset: u64,
    data: &[u8],
    total: &mut u64,
    append: bool,
) -> std::io::Result<()> {
    if !append {
        f.seek(SeekFrom::Start(offset))?;
    }
    f.write_all(data)?;
    *total = total.saturating_add(data.len() as u64);
    Ok(())
}

async fn send_read_err(
    send: &mut quinn::SendStream,
    seq: u64,
    offset: u64,
    status: Status,
) -> Result<()> {
    let resp = ReadResponse {
        op: OP_READ,
        seq,
        status: status as u8,
        offset,
        data: vec![],
        eof: true,
    };
    let encoded = encode(&resp)?;
    write_frame(send, &encoded).await?;
    send.finish()?;
    Ok(())
}
