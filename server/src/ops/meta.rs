use std::path::Path;
use std::sync::Arc;
use std::time::UNIX_EPOCH;

use anyhow::Result;

use quicfs_common::{
    frames::*,
    io::{decode, encode, write_frame},
    stat::{DirEntry, Stat, StatFs},
    status::Status,
};

use crate::sanitize;
use crate::session::ClientSession;

// ── GetAttr ───────────────────────────────────────────────────────────────────

pub async fn handle_getattr(
    send: &mut quinn::SendStream,
    raw: &[u8],
    session: &Arc<ClientSession>,
    root: &Path,
) -> Result<()> {
    let req: GetAttrRequest = decode(raw)?;
    let resolved = match sanitize::resolve(root, &req.path) {
        Ok(p) => p,
        Err(_) => {
            return send_stat_resp(send, OP_GET_ATTR, req.seq, Status::Permission, None).await
        }
    };
    let (status, stat) = match std::fs::metadata(&resolved) {
        Ok(m) => (Status::Ok, Some(metadata_to_stat(&m, &resolved))),
        Err(e) => (Status::from(e), None),
    };
    send_stat_resp(send, OP_GET_ATTR, req.seq, status, stat).await?;
    session.record_tx(0);
    Ok(())
}

// ── SetAttr ───────────────────────────────────────────────────────────────────

pub async fn handle_setattr(
    send: &mut quinn::SendStream,
    raw: &[u8],
    session: &Arc<ClientSession>,
    root: &Path,
) -> Result<()> {
    let req: SetAttrRequest = decode(raw)?;
    let resolved = match sanitize::resolve(root, &req.path) {
        Ok(p) => p,
        Err(_) => {
            let resp = SetAttrResponse {
                op: OP_SET_ATTR,
                seq: req.seq,
                status: Status::Permission as u8,
                stat: None,
            };
            write_frame(send, &encode(&resp)?).await?;
            send.finish()?;
            return Ok(());
        }
    };

    let mut err_status: Option<Status> = None;

    // SECURITY: every SetAttr sink must be confined exactly like the open/create/
    // truncate sinks. A plain path-based open / set_permissions / utimensat follows
    // symlinks and re-resolves the client path, so a final-component symlink (or an
    // intermediate component swapped to one after resolve() ran, a TOCTOU) would let
    // a client truncate/chmod/touch a file OUTSIDE the export root. We route through
    // sanitize::open_confined (openat2 RESOLVE_BENEATH on Linux): the kernel refuses
    // any resolution step that leaves the root and the returned fd pins the inode,
    // closing the race. Mode/times then operate on that fd via /proc/self/fd so they
    // never re-resolve the path.

    // Truncate (size) - O_WRONLY|O_NOFOLLOW so a final-component symlink is refused.
    #[cfg(unix)]
    if req.valid & 0x8 != 0 {
        let r = sanitize::open_confined(root, &resolved, libc::O_WRONLY | libc::O_NOFOLLOW, 0)
            .and_then(|f| f.set_len(req.size));
        if let Err(e) = r {
            err_status = Some(Status::from(e));
        }
    }
    #[cfg(not(unix))]
    if req.valid & 0x8 != 0 {
        if let Err(e) = set_file_len(&resolved, req.size) {
            err_status = Some(Status::from(e));
        }
    }

    // Mode and times via ONE confined O_PATH fd (it follows only within-root
    // symlinks to the real target; an escaping target is refused by RESOLVE_BENEATH).
    // Operating through /proc/self/fd/<n> hits the pinned inode without re-resolving
    // the path, so it is race-free.
    #[cfg(unix)]
    if err_status.is_none() && req.valid & (0x1 | 0x10 | 0x20) != 0 {
        use std::ffi::CString;
        use std::os::unix::io::AsRawFd;

        match sanitize::open_confined(root, &resolved, libc::O_PATH, 0) {
            Err(e) => err_status = Some(Status::from(e)),
            Ok(fd) => {
                let proc = CString::new(format!("/proc/self/fd/{}", fd.as_raw_fd())).ok();
                match proc {
                    None => err_status = Some(Status::InvalidArg),
                    Some(proc) => {
                        // Mode (masked to permission bits: never setuid/setgid/sticky).
                        if req.valid & 0x1 != 0 {
                            let rc = unsafe {
                                libc::fchmodat(
                                    libc::AT_FDCWD,
                                    proc.as_ptr(),
                                    (req.mode & 0o777) as libc::mode_t,
                                    0,
                                )
                            };
                            if rc != 0 {
                                err_status = Some(Status::from(std::io::Error::last_os_error()));
                            }
                        }
                        // Times (atime/mtime); UTIME_OMIT leaves an unset one alone.
                        if err_status.is_none() && (req.valid & 0x10 != 0 || req.valid & 0x20 != 0)
                        {
                            let ns_to_timespec = |ns: i64| -> libc::timespec {
                                libc::timespec {
                                    tv_sec: ns / 1_000_000_000,
                                    tv_nsec: ns % 1_000_000_000,
                                }
                            };
                            let utime_omit = libc::timespec {
                                tv_sec: 0,
                                tv_nsec: libc::UTIME_OMIT,
                            };
                            let times = [
                                if req.valid & 0x10 != 0 {
                                    ns_to_timespec(req.atime)
                                } else {
                                    utime_omit
                                },
                                if req.valid & 0x20 != 0 {
                                    ns_to_timespec(req.mtime)
                                } else {
                                    utime_omit
                                },
                            ];
                            let rc = unsafe {
                                libc::utimensat(libc::AT_FDCWD, proc.as_ptr(), times.as_ptr(), 0)
                            };
                            if rc != 0 {
                                err_status = Some(Status::from(std::io::Error::last_os_error()));
                            }
                        }
                    }
                }
            }
        }
    }

    let (status, stat) = match err_status {
        Some(s) => (s, None),
        None => match std::fs::metadata(&resolved) {
            Ok(m) => (Status::Ok, Some(metadata_to_stat(&m, &resolved))),
            Err(e) => (Status::from(e), None),
        },
    };

    let resp = SetAttrResponse {
        op: OP_SET_ATTR,
        seq: req.seq,
        status: status as u8,
        stat,
    };
    write_frame(send, &encode(&resp)?).await?;
    send.finish()?;
    session.record_tx(0);
    Ok(())
}

#[cfg(not(unix))]
fn set_file_len(path: &Path, len: u64) -> std::io::Result<()> {
    let f = std::fs::OpenOptions::new().write(true).open(path)?;
    f.set_len(len)
}

// ── ReadDir ───────────────────────────────────────────────────────────────────

pub async fn handle_readdir(
    send: &mut quinn::SendStream,
    raw: &[u8],
    session: &Arc<ClientSession>,
    root: &Path,
) -> Result<()> {
    let req: ReadDirRequest = decode(raw)?;
    let resolved = match sanitize::resolve(root, &req.path) {
        Ok(p) => p,
        Err(_) => {
            let resp = ReadDirResponse {
                op: OP_READ_DIR,
                seq: req.seq,
                status: Status::Permission as u8,
                entries: vec![],
                cursor: 0,
                eof: true,
            };
            write_frame(send, &encode(&resp)?).await?;
            send.finish()?;
            return Ok(());
        }
    };

    let (status, entries) = match std::fs::read_dir(&resolved) {
        Err(e) => (Status::from(e), vec![]),
        Ok(dir) => {
            let mut out: Vec<DirEntry> = vec![];
            let mut skip = req.cursor as usize;
            for entry in dir.flatten() {
                if skip > 0 {
                    skip -= 1;
                    continue;
                }
                let name = entry.file_name().to_string_lossy().into_owned();
                let (ino, mode) = entry
                    .metadata()
                    .map(|m| (inode_of(&m), mode_of(&m)))
                    .unwrap_or((0, 0));
                out.push(DirEntry { name, ino, mode });
                if out.len() >= 256 {
                    break;
                }
            }
            (Status::Ok, out)
        }
    };

    let eof = entries.len() < 256 || status != Status::Ok;
    let resp = ReadDirResponse {
        op: OP_READ_DIR,
        seq: req.seq,
        status: status as u8,
        cursor: req.cursor + entries.len() as u64,
        entries,
        eof,
    };
    write_frame(send, &encode(&resp)?).await?;
    send.finish()?;
    session.record_tx(0);
    Ok(())
}

// ── MkDir ─────────────────────────────────────────────────────────────────────

pub async fn handle_mkdir(
    send: &mut quinn::SendStream,
    raw: &[u8],
    session: &Arc<ClientSession>,
    root: &Path,
) -> Result<()> {
    let req: MkDirRequest = decode(raw)?;
    let resolved = match sanitize::resolve(root, &req.path) {
        Ok(p) => p,
        Err(_) => return send_stat_resp(send, OP_MKDIR, req.seq, Status::Permission, None).await,
    };

    // Confined mkdir (openat2 RESOLVE_BENEATH on the parent), then exact mode.
    #[cfg(unix)]
    let status = sanitize::mkdir_confined(root, &resolved, req.mode)
        .map(|_| Status::Ok)
        .unwrap_or_else(Status::from);
    #[cfg(not(unix))]
    let status = std::fs::create_dir(&resolved)
        .map(|_| Status::Ok)
        .unwrap_or_else(Status::from);

    // Durability: make the new directory entry survive a server crash. Best
    // effort - a fsync failure is logged, not reported as a mkdir failure (the
    // directory already exists; see crate::ops::sync_parent_dir).
    if status == Status::Ok && session.sync_metadata {
        crate::ops::sync_parent_dir(root, &resolved);
    }

    let stat = if status == Status::Ok {
        std::fs::metadata(&resolved)
            .ok()
            .map(|m| metadata_to_stat(&m, &resolved))
    } else {
        None
    };

    send_stat_resp(send, OP_MKDIR, req.seq, status, stat).await?;
    session.record_tx(0);
    Ok(())
}

// ── RmDir ─────────────────────────────────────────────────────────────────────

pub async fn handle_rmdir(
    send: &mut quinn::SendStream,
    raw: &[u8],
    session: &Arc<ClientSession>,
    root: &Path,
) -> Result<()> {
    let req: PathRequest = decode(raw)?;
    let resolved = match sanitize::resolve(root, &req.path) {
        Ok(p) => p,
        Err(_) => return send_status(send, OP_RMDIR, req.seq, Status::Permission).await,
    };
    #[cfg(unix)]
    let status = sanitize::remove_confined(root, &resolved, true)
        .map(|_| Status::Ok)
        .unwrap_or_else(Status::from);
    #[cfg(not(unix))]
    let status = std::fs::remove_dir(&resolved)
        .map(|_| Status::Ok)
        .unwrap_or_else(Status::from);
    // Durability: persist the removal so the entry stays gone across a crash.
    // Best effort - logged, never reported as an rmdir failure.
    if status == Status::Ok && session.sync_metadata {
        crate::ops::sync_parent_dir(root, &resolved);
    }
    send_status(send, OP_RMDIR, req.seq, status).await?;
    session.record_tx(0);
    Ok(())
}

// ── Unlink ────────────────────────────────────────────────────────────────────

pub async fn handle_unlink(
    send: &mut quinn::SendStream,
    raw: &[u8],
    session: &Arc<ClientSession>,
    root: &Path,
) -> Result<()> {
    let req: PathRequest = decode(raw)?;
    let resolved = match sanitize::resolve(root, &req.path) {
        Ok(p) => p,
        Err(_) => return send_status(send, OP_UNLINK, req.seq, Status::Permission).await,
    };
    #[cfg(unix)]
    let status = sanitize::remove_confined(root, &resolved, false)
        .map(|_| Status::Ok)
        .unwrap_or_else(Status::from);
    #[cfg(not(unix))]
    let status = std::fs::remove_file(&resolved)
        .map(|_| Status::Ok)
        .unwrap_or_else(Status::from);
    // Durability: persist the removal so the entry stays gone across a crash.
    // Best effort - logged, never reported as an unlink failure.
    if status == Status::Ok && session.sync_metadata {
        crate::ops::sync_parent_dir(root, &resolved);
    }
    send_status(send, OP_UNLINK, req.seq, status).await?;
    session.record_tx(0);
    Ok(())
}

// ── Rename ────────────────────────────────────────────────────────────────────

pub async fn handle_rename(
    send: &mut quinn::SendStream,
    raw: &[u8],
    session: &Arc<ClientSession>,
    root: &Path,
) -> Result<()> {
    let req: RenameRequest = decode(raw)?;
    let old = match sanitize::resolve(root, &req.old) {
        Ok(p) => p,
        Err(_) => return send_status(send, OP_RENAME, req.seq, Status::Permission).await,
    };
    let new = match sanitize::resolve(root, &req.new) {
        Ok(p) => p,
        Err(_) => return send_status(send, OP_RENAME, req.seq, Status::Permission).await,
    };
    #[cfg(unix)]
    let status = sanitize::rename_confined(root, &old, &new)
        .map(|_| Status::Ok)
        .unwrap_or_else(Status::from);
    #[cfg(not(unix))]
    let status = std::fs::rename(&old, &new)
        .map(|_| Status::Ok)
        .unwrap_or_else(Status::from);
    // Durability: fsync BOTH affected directories - the source (entry removed)
    // and the destination (entry added). This is the server half of the
    // crash-safe write-tmp, fsync, rename replace idiom. Dedup when both names
    // live in the same directory (one fsync covers the whole rename). Best
    // effort - a fsync failure is logged, NOT reported as a rename failure: the
    // rename already took effect, and telling the client it failed would leave
    // its inode map pointing at the old name (see crate::ops::sync_parent_dir).
    if status == Status::Ok && session.sync_metadata {
        crate::ops::sync_parent_dir(root, &old);
        if old.parent() != new.parent() {
            crate::ops::sync_parent_dir(root, &new);
        }
    }
    send_status(send, OP_RENAME, req.seq, status).await?;
    session.record_tx(0);
    Ok(())
}

// ── Symlink ───────────────────────────────────────────────────────────────────

/// Maximum byte length of a symlink target we will create.
/// Matches the Linux kernel limit for symlink targets.
const MAX_SYMLINK_TARGET_LEN: usize = 4096;

pub async fn handle_symlink(
    send: &mut quinn::SendStream,
    raw: &[u8],
    session: &Arc<ClientSession>,
    root: &Path,
) -> Result<()> {
    let req: SymlinkRequest = decode(raw)?;

    if req.target.len() > MAX_SYMLINK_TARGET_LEN {
        return send_stat_resp(send, OP_SYMLINK, req.seq, Status::InvalidArg, None).await;
    }

    let link_path = match sanitize::resolve(root, &req.link) {
        Ok(p) => p,
        Err(_) => return send_stat_resp(send, OP_SYMLINK, req.seq, Status::Permission, None).await,
    };

    #[cfg(unix)]
    let status = sanitize::symlink_confined(root, &link_path, &req.target)
        .map(|_| Status::Ok)
        .unwrap_or_else(Status::from);
    #[cfg(not(unix))]
    let status = create_symlink(&req.target, &link_path)
        .map(|_| Status::Ok)
        .unwrap_or_else(Status::from);

    // Durability: make the new symlink entry survive a server crash. Best effort
    // - logged, never reported as a symlink failure.
    if status == Status::Ok && session.sync_metadata {
        crate::ops::sync_parent_dir(root, &link_path);
    }

    let stat = if status == Status::Ok {
        std::fs::symlink_metadata(&link_path)
            .ok()
            .map(|m| metadata_to_stat(&m, &link_path))
    } else {
        None
    };

    send_stat_resp(send, OP_SYMLINK, req.seq, status, stat).await?;
    session.record_tx(0);
    Ok(())
}

#[cfg(not(unix))]
fn create_symlink(_target: &str, _link: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "symlink not supported on this platform",
    ))
}

// ── ReadLink ──────────────────────────────────────────────────────────────────

pub async fn handle_readlink(
    send: &mut quinn::SendStream,
    raw: &[u8],
    session: &Arc<ClientSession>,
    root: &Path,
) -> Result<()> {
    let req: PathRequest = decode(raw)?;
    let resolved = match sanitize::resolve(root, &req.path) {
        Ok(p) => p,
        Err(_) => {
            let resp = ReadLinkResponse {
                op: OP_READLINK,
                seq: req.seq,
                status: Status::Permission as u8,
                target: String::new(),
            };
            write_frame(send, &encode(&resp)?).await?;
            send.finish()?;
            return Ok(());
        }
    };
    // Read the raw symlink target string.  We return it as-is; the target
    // is a string, not an access grant.  Any future operation the client
    // attempts on that path still goes through resolve(), which prevents
    // escaping the export root.
    #[cfg(unix)]
    let read = sanitize::readlink_confined(root, &resolved);
    #[cfg(not(unix))]
    let read = std::fs::read_link(&resolved);
    let (status, target) = match read {
        Ok(t) => (Status::Ok, t.to_string_lossy().into_owned()),
        Err(e) => (Status::from(e), String::new()),
    };
    let resp = ReadLinkResponse {
        op: OP_READLINK,
        seq: req.seq,
        status: status as u8,
        target,
    };
    write_frame(send, &encode(&resp)?).await?;
    send.finish()?;
    session.record_tx(0);
    Ok(())
}

// ── Link (hard link) ──────────────────────────────────────────────────────────

pub async fn handle_link(
    send: &mut quinn::SendStream,
    raw: &[u8],
    session: &Arc<ClientSession>,
    root: &Path,
) -> Result<()> {
    let req: LinkRequest = decode(raw)?;
    let src = match sanitize::resolve(root, &req.path) {
        Ok(p) => p,
        Err(_) => return send_stat_resp(send, OP_LINK, req.seq, Status::Permission, None).await,
    };
    let dst = match sanitize::resolve(root, &req.link) {
        Ok(p) => p,
        Err(_) => return send_stat_resp(send, OP_LINK, req.seq, Status::Permission, None).await,
    };

    #[cfg(unix)]
    let status = sanitize::link_confined(root, &src, &dst)
        .map(|_| Status::Ok)
        .unwrap_or_else(Status::from);
    #[cfg(not(unix))]
    let status = create_hard_link(&src, &dst)
        .map(|_| Status::Ok)
        .unwrap_or_else(Status::from);
    // Durability: make the new hard-link entry survive a server crash. Best
    // effort - logged, never reported as a link failure. (The target inode's
    // nlink bump is finer-grained durability we do not force.)
    if status == Status::Ok && session.sync_metadata {
        crate::ops::sync_parent_dir(root, &dst);
    }
    let stat = if status == Status::Ok {
        std::fs::metadata(&dst)
            .ok()
            .map(|m| metadata_to_stat(&m, &dst))
    } else {
        None
    };

    send_stat_resp(send, OP_LINK, req.seq, status, stat).await?;
    session.record_tx(0);
    Ok(())
}

#[cfg(not(unix))]
fn create_hard_link(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::hard_link(src, dst)
}

// ── Open ──────────────────────────────────────────────────────────────────────

pub async fn handle_open(
    send: &mut quinn::SendStream,
    raw: &[u8],
    session: &Arc<ClientSession>,
    root: &Path,
) -> Result<()> {
    let req: OpenRequest = decode(raw)?;
    let resolved = match sanitize::resolve(root, &req.path) {
        Ok(p) => p,
        Err(_) => {
            let resp = OpenResponse {
                op: OP_OPEN,
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
    // Open the file now and RETAIN the descriptor in the handle. Read/Write/Fsync
    // use this fd (positioned I/O) and never reopen by path, which closes a
    // rename-based TOCTOU (an intermediate path component swapped to a symlink
    // between RPCs). On Linux the open itself is also confined with
    // openat2(RESOLVE_BENEATH): symlinks that stay beneath the export root are
    // followed (so within-root links keep working) and only escaping ones are
    // refused. Access mode follows the client's open flags.
    #[cfg(unix)]
    let opened: std::io::Result<std::fs::File> = {
        let access = match req.flags & 0x3 {
            1 => libc::O_WRONLY,
            2 => libc::O_RDWR,
            _ => libc::O_RDONLY,
        };
        // Honor O_APPEND on the retained fd so the kernel appends every write at
        // EOF atomically. Without this an existing file opened for append would
        // seek-and-write at the client-supplied offset, letting concurrent
        // appenders clobber each other. (handle_create already opens O_APPEND.)
        let mut oflags = access;
        if req.flags & 0x400 != 0 {
            oflags |= libc::O_APPEND;
        }
        sanitize::open_confined(root, &resolved, oflags, 0)
    };
    #[cfg(not(unix))]
    let opened: std::io::Result<std::fs::File> = {
        let mut opts = std::fs::OpenOptions::new();
        match req.flags & 0x3 {
            1 => {
                opts.write(true);
            }
            2 => {
                opts.read(true).write(true);
            }
            _ => {
                opts.read(true);
            }
        }
        if req.flags & 0x400 != 0 {
            opts.append(true);
        }
        opts.open(&resolved)
    };
    let file = match opened {
        Ok(f) => f,
        Err(e) => {
            let resp = OpenResponse {
                op: OP_OPEN,
                seq: req.seq,
                status: Status::from(e) as u8,
                handle: 0,
                stat: None,
            };
            write_frame(send, &encode(&resp)?).await?;
            send.finish()?;
            return Ok(());
        }
    };
    let stat = file
        .metadata()
        .ok()
        .map(|m| metadata_to_stat(&m, &resolved));
    let handle = match session
        .handles
        .try_insert(resolved.clone(), req.flags, file)
    {
        Ok(h) => h,
        Err(_) => {
            let resp = OpenResponse {
                op: OP_OPEN,
                seq: req.seq,
                status: Status::NoSpace as u8,
                handle: 0,
                stat: None,
            };
            write_frame(send, &encode(&resp)?).await?;
            send.finish()?;
            return Ok(());
        }
    };
    let resp = OpenResponse {
        op: OP_OPEN,
        seq: req.seq,
        status: Status::Ok as u8,
        handle,
        stat,
    };
    write_frame(send, &encode(&resp)?).await?;
    send.finish()?;
    session.record_tx(0);
    Ok(())
}

// ── Release ───────────────────────────────────────────────────────────────────

pub async fn handle_release(
    send: &mut quinn::SendStream,
    raw: &[u8],
    session: &Arc<ClientSession>,
) -> Result<()> {
    let req: ReleaseRequest = decode(raw)?;
    let removed = session.handles.remove(req.handle);
    // Optional durability: fsync the file to stable storage on close. The bytes
    // already reached the server (and its page cache) via Write RPCs; this forces
    // them to disk so a server-host crash right after close cannot lose them.
    let status = if session.sync_on_close {
        match &removed {
            Some(h) => {
                let f = h.file.lock().unwrap_or_else(|e| e.into_inner());
                match f.sync_all() {
                    Ok(()) => Status::Ok,
                    Err(e) => Status::from(e),
                }
            }
            None => Status::Ok, // already gone (double release / stale): nothing to sync
        }
    } else {
        Status::Ok
    };
    let resp = ReleaseResponse {
        op: OP_RELEASE,
        seq: req.seq,
        status: status as u8,
    };
    write_frame(send, &encode(&resp)?).await?;
    send.finish()?;
    Ok(())
}

// ── StatFS ────────────────────────────────────────────────────────────────────

pub async fn handle_statfs(
    send: &mut quinn::SendStream,
    raw: &[u8],
    session: &Arc<ClientSession>,
    root: &Path,
) -> Result<()> {
    let req: PathRequest = decode(raw)?;
    let resolved = match sanitize::resolve(root, &req.path) {
        Ok(p) => p,
        Err(_) => return send_statfs_resp(send, req.seq, Status::Permission, None).await,
    };
    let fs = query_statfs(&resolved);
    send_statfs_resp(send, req.seq, Status::Ok, Some(fs)).await?;
    session.record_tx(0);
    Ok(())
}

#[cfg(unix)]
fn query_statfs(path: &Path) -> StatFs {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let Ok(p) = CString::new(path.as_os_str().as_bytes()) else {
        return StatFs::default();
    };
    unsafe {
        let mut s: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(p.as_ptr(), &mut s) == 0 {
            return StatFs {
                blocks: s.f_blocks,
                bfree: s.f_bfree,
                bavail: s.f_bavail,
                files: s.f_files,
                ffree: s.f_ffree,
                bsize: s.f_bsize as u32,
                namelen: s.f_namemax as u32,
                frsize: s.f_frsize as u32,
            };
        }
    }
    StatFs::default()
}

#[cfg(not(unix))]
fn query_statfs(_path: &Path) -> StatFs {
    StatFs {
        blocks: 1_000_000,
        bfree: 500_000,
        bavail: 500_000,
        files: 100_000,
        ffree: 90_000,
        bsize: 4096,
        namelen: 255,
        frsize: 4096,
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

pub fn metadata_to_stat(m: &std::fs::Metadata, _path: &Path) -> Stat {
    let ns = |t: std::io::Result<std::time::SystemTime>| -> i64 {
        t.ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0)
    };
    Stat {
        ino: inode_of(m),
        mode: mode_of(m),
        nlink: nlink_of(m),
        uid: uid_of(m),
        gid: gid_of(m),
        size: m.len(),
        atime: ns(m.accessed()),
        mtime: ns(m.modified()),
        ctime: ns(m.modified()),
        blksz: 4096,
        blocks: (m.len() + 511) / 512,
    }
}

#[cfg(unix)]
fn inode_of(m: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    m.ino()
}
#[cfg(not(unix))]
fn inode_of(_m: &std::fs::Metadata) -> u64 {
    0
}

#[cfg(unix)]
fn mode_of(m: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    m.mode()
}
#[cfg(not(unix))]
fn mode_of(m: &std::fs::Metadata) -> u32 {
    if m.is_dir() {
        0o040755
    } else {
        0o100644
    }
}

#[cfg(unix)]
fn uid_of(m: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    m.uid()
}
#[cfg(not(unix))]
fn uid_of(_m: &std::fs::Metadata) -> u32 {
    0
}

#[cfg(unix)]
fn gid_of(m: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    m.gid()
}
#[cfg(not(unix))]
fn gid_of(_m: &std::fs::Metadata) -> u32 {
    0
}

#[cfg(unix)]
fn nlink_of(m: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    m.nlink().min(u32::MAX as u64) as u32
}
#[cfg(not(unix))]
fn nlink_of(_m: &std::fs::Metadata) -> u32 {
    1
}

async fn send_stat_resp(
    send: &mut quinn::SendStream,
    op: u8,
    seq: u64,
    status: Status,
    stat: Option<Stat>,
) -> Result<()> {
    let resp = GetAttrResponse {
        op,
        seq,
        status: status as u8,
        stat,
    };
    write_frame(send, &encode(&resp)?).await?;
    send.finish()?;
    Ok(())
}

async fn send_status(send: &mut quinn::SendStream, op: u8, seq: u64, status: Status) -> Result<()> {
    let resp = StatusResponse {
        op,
        seq,
        status: status as u8,
    };
    write_frame(send, &encode(&resp)?).await?;
    send.finish()?;
    Ok(())
}

async fn send_statfs_resp(
    send: &mut quinn::SendStream,
    seq: u64,
    status: Status,
    fs: Option<StatFs>,
) -> Result<()> {
    let resp = StatFsResponse {
        op: OP_STAT_FS,
        seq,
        status: status as u8,
        statfs: fs,
    };
    write_frame(send, &encode(&resp)?).await?;
    send.finish()?;
    Ok(())
}
