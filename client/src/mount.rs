//! FUSE mount lifecycle (Linux only).

use std::path::Path;

use anyhow::{Context, Result};
use fuser::MountOption;
use tokio::runtime::Handle;
use tracing::{info, warn};

use crate::cache::CacheConfig;
use crate::conn::{ConnManager, MountConfig};
use crate::fuse_ops::{QuicFs, WriteBufConfig};

/// Options forwarded from the CLI to the FUSE mount.
pub struct FuseOptions {
    pub allow_other: bool,
    pub readonly: bool,
    pub cache_ttl_ms: u64,
    /// Override all file uid attributes with this value.
    /// Useful when the server runs as a different user (e.g. root in a
    /// container) and the client wants to see all files as locally owned.
    pub uid_override: Option<u32>,
    /// Override all file gid attributes with this value.
    pub gid_override: Option<u32>,
    /// Max bytes buffered per file handle before forcing a network flush.
    pub write_buf_per_handle: usize,
    /// Max total bytes buffered across all handles.
    pub write_buf_total: usize,
    /// Coalesce window in milliseconds.
    pub coalesce_ms: u64,
    /// Remote subtree this mount is rooted at (e.g. "/" or "/projects").
    pub remote_root: String,
}

/// Connect to the QuicFS server, then block until the filesystem is unmounted.
///
/// Handles SIGINT and SIGTERM - either signal triggers a clean unmount.
/// If the mountpoint already has a stale FUSE mount, it is automatically
/// cleaned up before mounting (same behaviour as `fusermount3 -u` first).
pub async fn run_mount(cfg: MountConfig, mountpoint: &Path, opts: FuseOptions) -> Result<()> {
    // Clear any stale mount left by a previous killed process.
    clear_stale_mount(mountpoint);

    info!(server = %cfg.server_addr, mountpoint = %mountpoint.display(), "connecting");

    let conn = ConnManager::connect(cfg)
        .await
        .context("connect to server")?;

    info!("connected, mounting at {}", mountpoint.display());

    let cache_cfg = CacheConfig {
        max_entries: 8192,
        pos_ttl: std::time::Duration::from_millis(opts.cache_ttl_ms),
        neg_ttl: std::time::Duration::from_millis(opts.cache_ttl_ms / 4),
        dir_ttl: std::time::Duration::from_millis(opts.cache_ttl_ms / 2),
    };

    let wbuf_cfg = WriteBufConfig {
        max_per_handle_bytes: opts.write_buf_per_handle,
        max_total_bytes: opts.write_buf_total,
        window_ms: opts.coalesce_ms,
    };

    let rt = Handle::current();
    let fs = QuicFs::new(
        conn,
        cache_cfg,
        rt,
        wbuf_cfg,
        opts.uid_override,
        opts.gid_override,
        &opts.remote_root,
    );

    let mut mount_opts = vec![
        MountOption::FSName("quicfs".to_owned()),
        MountOption::DefaultPermissions,
    ];
    if opts.allow_other {
        mount_opts.push(MountOption::AllowOther);
    }
    if opts.readonly {
        mount_opts.push(MountOption::RO);
    }

    // `spawn_mount2` hands the filesystem to a background thread and returns
    // a `BackgroundSession` guard.  Dropping the guard calls fusermount3 -u.
    let write_buf_bg = std::sync::Arc::clone(&fs.write_buf);
    let write_errors_bg = std::sync::Arc::clone(&fs.write_errors);
    let open_files_bg = std::sync::Arc::clone(&fs.open_files);
    let conn_bg = fs.conn.clone();
    let coalesce_ms = opts.coalesce_ms;

    // Clones kept for the shutdown path: on a clean unmount we drain any writes
    // still buffered for open handles before tearing the session down.
    let write_buf_final = std::sync::Arc::clone(&fs.write_buf);
    let write_errors_final = std::sync::Arc::clone(&fs.write_errors);
    let open_files_final = std::sync::Arc::clone(&fs.open_files);
    let conn_final = fs.conn.clone();

    let _session = fuser::spawn_mount2(fs, mountpoint, &mount_opts).context("spawn FUSE mount")?;

    // Background write-window flush task.
    //
    // Any writes whose coalesce window has expired but whose handle hasn't
    // been closed (no flush()/release()) are flushed here.  This handles
    // long-lived writes (e.g. append-only log files) where the VFS doesn't
    // issue a flush promptly.  The task ticks at window/2 so no chunk waits
    // longer than 1.5× the configured window.
    tokio::spawn(async move {
        let tick = std::time::Duration::from_millis(coalesce_ms.max(1) / 2 + 1);
        let mut interval = tokio::time::interval(tick);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            // Age-drop: app-acknowledged writes that have sat unacked past the max
            // age (the server is unreachable) are dropped with a loud sticky error,
            // bounding how long an idle-but-open handle can pin buffer memory.
            let too_old: Vec<u64> = write_buf_bg
                .lock()
                .unwrap()
                .older_than(crate::fuse_ops::MAX_UNACKED_AGE);
            for fh in too_old {
                let dropped = write_buf_bg.lock().unwrap().drop_handle(fh);
                if dropped > 0 {
                    write_errors_bg.lock().unwrap().insert(fh);
                    tracing::warn!(
                        fh,
                        dropped,
                        "background: unacked writes exceeded max age; dropped (close will report EIO)"
                    );
                }
            }
            // Flush handles whose coalesce window expired. allow_reopen=false: the
            // background task never reopens a stale handle (the FUSE-op path does),
            // so the two never race on a reopen under the single-threaded session.
            // flush_one keeps chunks until acked and marks the handle sticky on a
            // real send failure, so a window flush can never silently drop a chunk.
            let expired: Vec<u64> = write_buf_bg.lock().unwrap().expired_handles();
            for fh in expired {
                let _ = crate::fuse_ops::flush_one(
                    &open_files_bg,
                    &write_buf_bg,
                    &write_errors_bg,
                    &conn_bg,
                    fh,
                    false,
                )
                .await;
            }
        }
    });

    info!(
        "mounted - press Ctrl-C or send SIGTERM to unmount {}",
        mountpoint.display()
    );

    // Block until something tells us to stop: a signal, or the mountpoint
    // disappearing because someone ran `fusermount3 -u` from another shell.
    match wait_for_shutdown(mountpoint).await {
        Shutdown::Signal => {
            info!("unmounting {}", mountpoint.display());
            // Flush writes still buffered for open handles BEFORE dropping the
            // session, so data the app already wrote (and we acknowledged) is not
            // lost on a clean shutdown. allow_reopen=true: a handle left stale by a
            // just-completed reconnect is reopened and its positioned writes
            // replayed on the way out; flush_one records a failure sticky.
            let handles: Vec<u64> = write_buf_final.lock().unwrap().handles();
            for fh in handles {
                if let Err(e) = crate::fuse_ops::flush_one(
                    &open_files_final,
                    &write_buf_final,
                    &write_errors_final,
                    &conn_final,
                    fh,
                    true,
                )
                .await
                {
                    tracing::warn!(fh, "flush on unmount: {e}");
                }
            }
            // _session is dropped here → fuser calls fusermount3 -u automatically.
        }
        Shutdown::Unmounted => {
            // The FUSE session already ended (the kernel dropped /dev/fuse when
            // the external unmount happened). Exit so we don't linger forever
            // holding the QUIC connection open; dropping _session is a no-op.
            info!("{} unmounted externally, exiting", mountpoint.display());
        }
    }
    Ok(())
}

enum Shutdown {
    /// SIGINT/SIGTERM - we still own the mount and must unmount it.
    Signal,
    /// The mountpoint vanished from /proc/mounts (external `fusermount3 -u`).
    Unmounted,
}

/// Detect and remove a stale FUSE mount at `mountpoint`.
///
/// When a quicfs process is killed (SIGKILL or crash), the kernel retains the
/// FUSE mountpoint as dead.  We detect this via /proc/mounts and run
/// `fusermount3 -u` so the subsequent mount attempt doesn't get EPERM.
fn clear_stale_mount(mountpoint: &Path) {
    let path_str = mountpoint.to_string_lossy();
    let is_mounted = std::fs::read_to_string("/proc/mounts")
        .map(|m| {
            m.lines().any(|l| {
                // Each line: device mountpoint fstype options dump pass
                l.split_whitespace()
                    .nth(1)
                    .map_or(false, |mp| mp == path_str.as_ref())
            })
        })
        .unwrap_or(false);

    if is_mounted {
        warn!(
            "stale mount detected at {}, clearing with fusermount3 -u",
            path_str
        );
        let status = std::process::Command::new("fusermount3")
            .args(["-u", &*path_str])
            .status();
        match status {
            Ok(s) if s.success() => info!("stale mount cleared"),
            Ok(s) => warn!("fusermount3 -u exited {s}; trying lazy unmount"),
            Err(e) => warn!("fusermount3 not found: {e}; trying umount -l"),
        }
        // Fallback: lazy unmount (detaches immediately, cleans up when last fd closes).
        if !is_fuse_mount_gone(mountpoint) {
            let _ = std::process::Command::new("umount")
                .args(["-l", &*path_str])
                .status();
        }
    }
}

fn is_fuse_mount_gone(mountpoint: &Path) -> bool {
    let path_str = mountpoint.to_string_lossy();
    std::fs::read_to_string("/proc/mounts")
        .map(|m| {
            !m.lines().any(|l| {
                l.split_whitespace()
                    .nth(1)
                    .map_or(false, |mp| mp == path_str.as_ref())
            })
        })
        .unwrap_or(true)
}

/// Block until SIGINT (Ctrl-C), SIGTERM (kill / systemd stop), or the mount
/// being removed externally (`fusermount3 -u` / `umount` from another shell).
///
/// The external-unmount case is detected by polling /proc/mounts: fuser's
/// background session thread exits silently when the kernel drops /dev/fuse,
/// and `BackgroundSession` (0.14) exposes no awaitable join handle without
/// consuming the guard we need to keep for the signal path - so a 1s poll is
/// the simplest reliable trigger and reuses the existing /proc/mounts parser.
async fn wait_for_shutdown(mountpoint: &Path) -> Shutdown {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigterm = signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
    let mut sigint = signal(SignalKind::interrupt()).expect("failed to install SIGINT handler");

    let mut poll = tokio::time::interval(std::time::Duration::from_secs(1));
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    poll.tick().await; // consume the immediate first tick

    loop {
        tokio::select! {
            _ = sigterm.recv() => { info!("received SIGTERM"); return Shutdown::Signal; }
            _ = sigint.recv()  => { info!("received SIGINT");  return Shutdown::Signal; }
            _ = poll.tick() => {
                if is_fuse_mount_gone(mountpoint) {
                    return Shutdown::Unmounted;
                }
            }
        }
    }
}
