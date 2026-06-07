//! FUSE filesystem implementation for QuicFS.
//!
//! Each `fuser::Filesystem` callback is sync; QUIC is async.
//! We bridge them with `Handle::block_on()` - safe because fuser
//! drives callbacks from its own OS thread, not a tokio thread.
//!
//! Compiled only on Linux where the FUSE kernel module is available.

use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, Request, TimeOrNow,
};
use tokio::runtime::Handle;
use tracing::warn;

use quicfs_common::stat::Stat;

use crate::cache::{CacheConfig, MetaCache};
use crate::conn::ConnManager;
use crate::writebuf::{PushDecision, WriteBuffer};

/// O_APPEND flag bit (Linux). An append handle is never replayed across a
/// reconnect (the kernel ignores the offset and appends at EOF, so a re-send
/// could double-append); positioned writes ARE replayed because they overwrite
/// idempotently.
const O_APPEND: u32 = 0x400;

/// How long an app-acknowledged write may sit unacked (server unreachable) before
/// the background task drops it and reports a loud sticky error, bounding how long
/// an idle-but-open handle can pin buffer memory.
pub(crate) const MAX_UNACKED_AGE: Duration = Duration::from_secs(120);

/// FUSE kernel attribute-cache TTL.
///
/// We return TTL=0 to the kernel for all FUSE replies.  This tells the kernel
/// to ALWAYS call back into our daemon for fresh attributes rather than caching
/// them itself.  Our daemon then serves requests from MetaCache (which has its
/// own TTL, default 2 s), so the actual network round-trip cost is low.
///
/// Why TTL=0 at the FUSE layer?
/// - Mutations (link, rename, unlink, write) invalidate our MetaCache
///   immediately.  If the kernel held its OWN copy for several seconds, the
///   caller would see stale nlink / size / mtime despite our cache being
///   correct.
/// - SSHFS uses the same approach by default.
/// - The overhead is one mutex-guarded HashMap lookup per VFS attr access,
///   which is negligible compared to any remote I/O.
fn fuse_ttl_from_cache_ms(_ms: u64) -> Duration {
    // 1 ms is long enough for the kernel to reuse an entry within the same
    // syscall chain (mkdir -p, open-write-close), but short enough that
    // mutations (link, unlink, rename) are visible on the very next stat.
    Duration::from_millis(1)
}

// ── Inode table ───────────────────────────────────────────────────────────────

const ROOT_INO: u64 = fuser::FUSE_ROOT_ID; // = 1

/// Bidirectional mapping between FUSE inode numbers and remote paths.
///
/// Design note: we do NOT remove entries when the kernel calls `forget()`.
/// With FUSE_TTL=0, the kernel calls `forget` aggressively (after every
/// lookup that immediately expires), which would prematurely remove entries
/// and cause ENOENT on subsequent `getattr` calls for paths that are still
/// alive.  Instead, entries are only removed by explicit filesystem mutations:
/// `unlink`, `rmdir`, and `rename`.  The table grows monotonically but is
/// bounded by the number of distinct paths accessed in the mount lifetime.
struct InodeTable {
    ino_to_path: HashMap<u64, PathBuf>,
    path_to_ino: HashMap<PathBuf, u64>,
    next: u64,
}

impl InodeTable {
    /// `root` is the remote path the mount is rooted at (e.g. "/" or "/projects").
    /// All FUSE paths are derived from it, so every server RPC is automatically
    /// scoped to the requested subtree - no per-call prefixing needed.
    fn new(root: &str) -> Self {
        let root = normalize_root(root);
        let mut t = Self {
            ino_to_path: HashMap::new(),
            path_to_ino: HashMap::new(),
            next: ROOT_INO + 1,
        };
        t.ino_to_path.insert(ROOT_INO, PathBuf::from(&root));
        t.path_to_ino.insert(PathBuf::from(&root), ROOT_INO);
        t
    }

    /// Return (or allocate) a stable FUSE inode number for `path`.
    ///
    /// Once allocated, the ino→path mapping persists until the path is
    /// explicitly removed via `remove_path` (called on unlink/rmdir).
    fn get_or_alloc(&mut self, path: PathBuf) -> u64 {
        if let Some(&ino) = self.path_to_ino.get(&path) {
            return ino;
        }
        let ino = self.next;
        self.next += 1;
        self.ino_to_path.insert(ino, path.clone());
        self.path_to_ino.insert(path, ino);
        ino
    }

    fn path_of(&self, ino: u64) -> Option<&Path> {
        self.ino_to_path.get(&ino).map(|p| p.as_path())
    }

    /// Remove a path that no longer exists (called on unlink/rmdir).
    fn remove_path(&mut self, path: &Path) {
        if let Some(ino) = self.path_to_ino.remove(path) {
            self.ino_to_path.remove(&ino);
        }
    }

    /// Update path when a file is renamed.
    fn rename_ino(&mut self, old: &Path, new: PathBuf) {
        if let Some(ino) = self.path_to_ino.remove(old) {
            self.ino_to_path.insert(ino, new.clone());
            self.path_to_ino.insert(new, ino);
        }
    }
}

/// Normalize a remote root: ensure a leading '/', strip a trailing '/'
/// (except for the bare root "/").
fn normalize_root(root: &str) -> String {
    let r = root.trim();
    let r = if r.is_empty() { "/" } else { r };
    let with_lead = if r.starts_with('/') {
        r.to_owned()
    } else {
        format!("/{r}")
    };
    let trimmed = with_lead.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_owned()
    } else {
        trimmed.to_owned()
    }
}

// ── QuicFs ───────────────────────────────────────────────────────────────────

/// Configuration for the write coalescing buffer.
pub struct WriteBufConfig {
    /// Maximum bytes buffered per file handle before a flush is forced.
    /// Default: 4 MiB.
    pub max_per_handle_bytes: usize,
    /// Maximum bytes buffered across ALL handles combined.
    /// Prevents memory exhaustion when many files are open for writing.
    /// Default: 32 MiB.
    pub max_total_bytes: usize,
    /// Coalesce window: data older than this is force-flushed by the background
    /// task even if neither per-handle nor global limits have been hit.
    /// Default: 10 ms (matches spec §7.5 `coalesce_window_ms`).
    pub window_ms: u64,
}

impl Default for WriteBufConfig {
    fn default() -> Self {
        Self {
            max_per_handle_bytes: 4 * 1024 * 1024,
            max_total_bytes: 32 * 1024 * 1024,
            window_ms: 10,
        }
    }
}

/// Decide what flush()/fsync() should reply, given whether the synchronous flush
/// failed (`flush_err = Some(errno)`) and whether a sticky write-error was set by
/// an earlier (e.g. background) flush. The invariant this encodes: **if buffered
/// data failed to reach the server by any path, the reply is an error** - close()
/// and fsync() never report success over silently-lost data. A direct flush error
/// takes precedence (more specific errno); otherwise a sticky error reports EIO.
fn flush_reply(flush_err: Option<i32>, had_sticky: bool) -> Result<(), i32> {
    match flush_err {
        Some(errno) => Err(errno),
        None if had_sticky => Err(libc::EIO),
        None => Ok(()),
    }
}

// ── fh-remap: client handle <-> server handle ──────────────────────────────────

/// What the client tracks per open file, so a reconnect can transparently swap a
/// fresh server handle in behind the kernel's stable client-side fh.
pub(crate) struct OpenFile {
    /// Remote path, for reopening after a reconnect.
    path: String,
    /// Original open flags (access mode + O_APPEND used on reopen; O_CREAT/
    /// O_EXCL/O_TRUNC are stripped so a reopen never re-creates or re-truncates).
    flags: u32,
    /// The CURRENT server-side handle id (changes on every reconnect/reopen).
    server_handle: u64,
    /// The reconnect generation at which `server_handle` was obtained. A mismatch
    /// with `conn.reconnect_gen()` means the handle is stale and must be reopened.
    opened_gen: u64,
    /// O_APPEND: such handles are not replayed across a reconnect.
    is_append: bool,
}

pub(crate) type OpenFiles = std::sync::Arc<Mutex<HashMap<u64, OpenFile>>>;

/// Resolve the live server handle for `client_fh`, reopening by path if the
/// connection has reconnected since the handle was opened.
///
/// `allow_reopen=false` (the background task) returns `None` for a stale handle
/// instead of reopening, leaving the reopen to the next FUSE op so the background
/// task and the FUSE thread never race on a reopen under the single-threaded
/// session. On a successful reopen of an O_APPEND handle, its unacked buffer is
/// DROPPED and the handle marked sticky (no append replay - see DESIGN).
async fn ensure_live(
    open_files: &OpenFiles,
    write_buf: &std::sync::Arc<Mutex<WriteBuffer>>,
    write_errors: &std::sync::Arc<Mutex<HashSet<u64>>>,
    conn: &ConnManager,
    client_fh: u64,
    allow_reopen: bool,
) -> Option<u64> {
    let cur = conn.reconnect_gen();
    let (sh, gen, path, flags, is_append) = {
        let files = open_files.lock().unwrap();
        let of = files.get(&client_fh)?;
        (
            of.server_handle,
            of.opened_gen,
            of.path.clone(),
            of.flags,
            of.is_append,
        )
    };
    if gen == cur {
        return Some(sh);
    }
    if !allow_reopen {
        return None;
    }
    // Reopen with stripped flags: keep the access mode and O_APPEND, drop the
    // one-shot creation flags so a replay never re-creates or re-truncates.
    let reopen_flags = (flags & 0x3) | (flags & O_APPEND);
    match conn.open(&path, reopen_flags).await {
        Ok((new_handle, _stat)) => {
            // Stamp the gen read BEFORE the reopen (`cur`), not a fresh read: the
            // new handle is valid for a gen >= cur, so `cur` can never mark a
            // stale handle live (at worst it forces one extra reopen). A fresh
            // post-open read could be a gen the handle is not yet valid for if a
            // concurrent background-task reconnect bumped it, opening a
            // stale-as-live window.
            if let Some(of) = open_files.lock().unwrap().get_mut(&client_fh) {
                of.server_handle = new_handle;
                of.opened_gen = cur;
            }
            if is_append && write_buf.lock().unwrap().has_buffered(client_fh) {
                let dropped = write_buf.lock().unwrap().drop_handle(client_fh);
                if dropped > 0 {
                    write_errors.lock().unwrap().insert(client_fh);
                    warn!(
                        fh = client_fh,
                        dropped, "append handle reconnected: unacked appends dropped (not replayed); close will report EIO"
                    );
                }
            }
            Some(new_handle)
        }
        Err(e) => {
            warn!(fh = client_fh, "reopen after reconnect failed: {e}");
            None
        }
    }
}

/// Flush one handle's buffered writes against its current (reopened if needed)
/// server handle, removing chunks only on a Status::Ok ack. A failed send leaves
/// the chunks buffered for a later retry and marks the handle sticky. Used by the
/// FUSE thread (via block_on) and the background/unmount paths (via await).
pub(crate) async fn flush_one(
    open_files: &OpenFiles,
    write_buf: &std::sync::Arc<Mutex<WriteBuffer>>,
    write_errors: &std::sync::Arc<Mutex<HashSet<u64>>>,
    conn: &ConnManager,
    client_fh: u64,
    allow_reopen: bool,
) -> anyhow::Result<()> {
    // Up to two attempts. A flush can fail because the connection reconnected
    // *during* the send (conn.write's internal reconnect): the bytes went to the
    // now-stale handle and were rejected, but the positioned chunks are still
    // buffered. In that case we reopen (ensure_live, now at the new gen) and
    // re-send them idempotently, so an active write transparently survives a brief
    // outage. A second failure, a failure with NO intervening reconnect (server
    // genuinely down), or an O_APPEND handle is loud (sticky EIO).
    let mut last_err: Option<anyhow::Error> = None;
    for _attempt in 0..2 {
        let server_handle = match ensure_live(
            open_files,
            write_buf,
            write_errors,
            conn,
            client_fh,
            allow_reopen,
        )
        .await
        {
            Some(h) => h,
            None => {
                // Could not get a live handle (server unreachable). If data is
                // buffered it is RETAINED for a later replay, not lost - so we do
                // NOT set sticky here; we return an error so a synchronous caller
                // (flush()/fsync()) can report a genuine current failure via its
                // own direct error, while a best-effort caller (write-back forced
                // flush, background) just leaves the data buffered.
                if write_buf.lock().unwrap().has_buffered(client_fh) {
                    anyhow::bail!("handle {client_fh} not live for flush");
                }
                return Ok(());
            }
        };
        let batch = match write_buf.lock().unwrap().begin_flush(client_fh) {
            Some(b) => b,
            None => return Ok(()),
        };
        let gen_before = conn.reconnect_gen();
        let mut send_err: Option<anyhow::Error> = None;
        for (offset, data) in &batch.chunks {
            if let Err(e) = conn.write(server_handle, *offset, data).await {
                send_err = Some(e);
                break;
            }
        }
        let Some(e) = send_err else {
            write_buf
                .lock()
                .unwrap()
                .ack_flush(client_fh, batch.sent_count);
            return Ok(());
        };
        // The send failed. An O_APPEND handle must NEVER re-send: the server
        // appends each frame at EOF as it streams in, so a partially-applied
        // append RPC re-sent would double-apply (corruption). Drop it loudly.
        let is_append = open_files
            .lock()
            .unwrap()
            .get(&client_fh)
            .map(|of| of.is_append)
            .unwrap_or(false);
        if is_append {
            write_buf.lock().unwrap().drop_handle(client_fh);
            write_errors.lock().unwrap().insert(client_fh);
            return Err(e);
        }
        // Positioned: keep the chunks (idempotent re-send). NEVER set sticky here:
        // the data is retained write-back and will replay on reconnect, so a
        // sticky would surface a SPURIOUS EIO at a later fsync/close over data
        // that actually lands. The genuine lost-data signals are the hard-cap
        // reject, the background age-drop, and a synchronous caller's OWN direct
        // error (flush()/fsync()/release() see this Err return). We return Err so
        // those callers can report a real current failure.
        write_buf.lock().unwrap().fail_flush(client_fh);
        last_err = Some(e);
        // Retry once if a reconnect happened mid-send and we may reopen: the next
        // ensure_live reopens at the new gen and replays against the fresh handle.
        if allow_reopen && conn.reconnect_gen() != gen_before {
            continue;
        }
        return Err(last_err.unwrap());
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("flush failed for {client_fh}")))
}

/// The FUSE filesystem handle.  Held alive for the mount lifetime.
pub struct QuicFs {
    pub conn: ConnManager,
    cache: Mutex<MetaCache>,
    inodes: Mutex<InodeTable>,
    rt: Handle,
    /// FUSE kernel attribute-cache TTL (derived from `--cache-ttl`).
    fuse_ttl: Duration,
    /// Coalescing write buffer - accumulates small FUSE writes before sending.
    pub write_buf: std::sync::Arc<Mutex<WriteBuffer>>,
    /// Handles whose buffered writes failed to reach the server. A "sticky"
    /// per-handle error: set by any failed flush (inline OR the background task),
    /// and reported - then cleared - by the next flush()/fsync()/release() so an
    /// application never sees a successful close() while data silently vanished.
    /// Shared (Arc) so the background flush task can set it too.
    pub write_errors: std::sync::Arc<Mutex<HashSet<u64>>>,
    /// fh-remap registry: the kernel-facing client fh -> the current OpenFile
    /// (path, flags, current server handle, the gen it was opened at). Lets a
    /// reconnect reopen the file and swap in a fresh server handle without the
    /// kernel ever seeing the change. Shared (Arc) with the background task.
    pub(crate) open_files: OpenFiles,
    /// Monotonic allocator for client fh values (never reset within a process).
    next_client_fh: AtomicU64,
    /// uid/gid to report for all files regardless of what the server returns.
    /// Used when the server runs as a different user than the FUSE client.
    pub uid_override: Option<u32>,
    pub gid_override: Option<u32>,
    /// Last observed reconnect generation.  We use an AtomicU64 because
    /// `get_stat` takes &self - we need interior mutability for the update.
    last_reconnect_gen: AtomicU64,
}

impl QuicFs {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        conn: ConnManager,
        cache_cfg: CacheConfig,
        rt: Handle,
        wbuf_cfg: WriteBufConfig,
        uid_override: Option<u32>,
        gid_override: Option<u32>,
        remote_root: &str,
    ) -> Self {
        let fuse_ttl = fuse_ttl_from_cache_ms(cache_cfg.pos_ttl.as_millis() as u64);
        let write_buf = std::sync::Arc::new(Mutex::new(WriteBuffer::new(
            wbuf_cfg.max_per_handle_bytes,
            wbuf_cfg.max_total_bytes,
            wbuf_cfg.window_ms,
        )));
        let init_gen = conn.reconnect_gen();
        Self {
            last_reconnect_gen: AtomicU64::new(init_gen),
            conn,
            cache: Mutex::new(MetaCache::new(cache_cfg)),
            inodes: Mutex::new(InodeTable::new(remote_root)),
            rt,
            fuse_ttl,
            write_buf,
            write_errors: std::sync::Arc::new(Mutex::new(HashSet::new())),
            open_files: std::sync::Arc::new(Mutex::new(HashMap::new())),
            next_client_fh: AtomicU64::new(1),
            uid_override,
            gid_override,
        }
    }

    /// Register a freshly opened file and return its kernel-facing client fh.
    fn register_open(&self, path: String, flags: u32, server_handle: u64) -> u64 {
        let client_fh = self.next_client_fh.fetch_add(1, Ordering::Relaxed);
        let opened_gen = self.conn.reconnect_gen();
        self.open_files.lock().unwrap().insert(
            client_fh,
            OpenFile {
                path,
                flags,
                server_handle,
                opened_gen,
                is_append: flags & O_APPEND != 0,
            },
        );
        client_fh
    }

    // ── helpers ──────────────────────────────────────────────────────────

    fn path_for(&self, ino: u64) -> Option<String> {
        self.inodes
            .lock()
            .unwrap()
            .path_of(ino)
            .map(|p| p.to_string_lossy().into_owned())
    }

    fn child_path(parent: &Path, name: &OsStr) -> PathBuf {
        if parent == Path::new("/") {
            PathBuf::from(format!("/{}", name.to_string_lossy()))
        } else {
            parent.join(name)
        }
    }

    fn make_file_attr(&self, path: PathBuf, stat: &Stat) -> FileAttr {
        let ino = self.inodes.lock().unwrap().get_or_alloc(path);
        let mut attr = stat_to_file_attr(stat, ino);
        if let Some(uid) = self.uid_override {
            attr.uid = uid;
        }
        if let Some(gid) = self.gid_override {
            attr.gid = gid;
        }
        attr
    }

    /// Flush all buffered writes for `client_fh` to the server synchronously,
    /// reopening the handle first if the connection reconnected. Chunks are kept
    /// until acked, so a failed send leaves them for a later retry and marks the
    /// handle sticky. Safe to call when nothing is buffered (no-op).
    fn flush_handle(&self, client_fh: u64) -> anyhow::Result<()> {
        self.rt.block_on(flush_one(
            &self.open_files,
            &self.write_buf,
            &self.write_errors,
            &self.conn,
            client_fh,
            true,
        ))
    }

    /// Flush a handle until its buffer is fully drained - for TERMINAL flushes
    /// (close/fsync), which must not return success while data is still buffered.
    ///
    /// A single `flush_handle` can be a no-op when the background task currently
    /// holds the per-handle send guard (`begin_flush` returns None): it would
    /// report Ok while bytes remain, and `release()` would then drop those bytes.
    /// Here we re-flush, waiting out the in-flight background flush, until the
    /// buffer is empty or a genuine send error occurs. Bounded so a wedged server
    /// surfaces a loud error rather than spinning forever.
    fn flush_handle_drain(&self, client_fh: u64) -> anyhow::Result<()> {
        // ~2.5s ceiling: the background drains at link rate, so a full buffer
        // empties well within this; past it the server is wedged -> loud error.
        for _ in 0..500 {
            self.flush_handle(client_fh)?; // a genuine send error propagates
            if !self.write_buf.lock().unwrap().has_buffered(client_fh) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        anyhow::bail!("flush did not drain handle {client_fh} (server wedged?)")
    }

    /// Resolve the live server handle for `client_fh`, reopening on a reconnect.
    /// `None` means the handle is unknown or the reopen failed (server down).
    fn live_handle(&self, client_fh: u64) -> Option<u64> {
        self.rt.block_on(ensure_live(
            &self.open_files,
            &self.write_buf,
            &self.write_errors,
            &self.conn,
            client_fh,
            true,
        ))
    }

    /// Flush buffered writes for every open handle. Used where we must order ALL
    /// pending writes before another operation (truncate, unmount). Returns the
    /// first error. `flush_one` keeps chunks until acked and marks the handle
    /// sticky on failure, so we keep going across a failing handle: every handle
    /// is either flushed or left buffered-and-sticky, never silently dropped.
    fn flush_all_handles(&self) -> anyhow::Result<()> {
        let handles = self.write_buf.lock().unwrap().handles();
        let mut first_err: Option<anyhow::Error> = None;
        for fh in handles {
            if let Err(e) = self.flush_handle(fh) {
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Fence buffered writes before a truncating open/create.
    ///
    /// An open or create that carries `O_TRUNC` truncates the file on the server.
    /// A write still sitting in the coalesce buffer for that file would, if it
    /// flushed AFTER the truncate, re-grow the file with bytes the truncate was
    /// meant to clear - the same hazard the setattr(size) path already fences.
    /// The buffer is keyed by handle, not path, and a create/open does not yet
    /// have the target handle, so we conservatively flush ALL buffered writes
    /// before the truncating op. This is a no-op when nothing is buffered (the
    /// overwhelmingly common case - a fresh create pays nothing), so it does not
    /// touch the hot write path. On a flush error we surface it so the caller can
    /// fail the op rather than truncate over data it could not persist.
    fn fence_truncating_open(&self, flags: i32) -> anyhow::Result<()> {
        const O_TRUNC: i32 = 0x200;
        if flags & O_TRUNC == 0 {
            return Ok(());
        }
        if self.write_buf.lock().unwrap().total_bytes() == 0 {
            return Ok(());
        }
        self.flush_all_handles()
    }

    /// Clear the MetaCache if the server has been reconnected since we last
    /// checked.  One atomic load per call - called from `get_stat` so every
    /// cache-miss path sees a fresh check.
    fn check_reconnect(&self) {
        let current = self.conn.reconnect_gen();
        let last = self.last_reconnect_gen.load(Ordering::Relaxed);
        if current != last {
            tracing::info!(
                gen_before = last,
                gen_after = current,
                "server reconnected - clearing metadata cache"
            );
            self.cache.lock().unwrap().clear();
            self.last_reconnect_gen.store(current, Ordering::Relaxed);
        }
    }

    fn cached_getattr(&self, path: &str) -> Option<Result<Stat, ()>> {
        self.cache.lock().unwrap().get(path)
    }

    fn cache_stat(&self, path: &str, stat: &Stat) {
        let is_dir = (stat.mode >> 12) & 0xF == 0x4;
        self.cache
            .lock()
            .unwrap()
            .insert(path.to_owned(), stat.clone(), is_dir);
    }

    fn cache_negative(&self, path: &str) {
        self.cache.lock().unwrap().insert_negative(path.to_owned());
    }

    fn invalidate_cache(&self, path: &str) {
        self.cache.lock().unwrap().invalidate(path);
    }

    fn get_stat(&self, path: &str) -> std::io::Result<Stat> {
        // Detect server restarts: if the generation advanced, wipe stale data.
        self.check_reconnect();
        // If we hold buffered writes, the server's metadata (size, mtime) does not
        // reflect them yet. A getattr that returned the stale server size would
        // clobber the kernel's i_size, so a following read sees EOF over data we
        // have only buffered locally (write-then-stat / read-your-writes). Flush
        // pending writes first so getattr is consistent. Cheap no-op when nothing
        // is buffered, which is the common read/stat path.
        // Track whether the pre-flush actually landed. If it did not (transient
        // outage, data still buffered), the server's stat is stale-short and must
        // NOT be cached - otherwise a stat() reports a too-small size that would
        // persist for the cache TTL even after the data lands. We still return the
        // (uncached) server stat so the next stat re-checks.
        let flush_ok = if self.write_buf.lock().unwrap().total_bytes() > 0 {
            self.flush_all_handles().is_ok()
        } else {
            true
        };
        // Check cache first.
        if let Some(r) = self.cached_getattr(path) {
            return r.map_err(|_| not_found_err(path));
        }
        // RPC.
        match self.rt.block_on(self.conn.getattr(path)) {
            Ok(s) => {
                if flush_ok {
                    self.cache_stat(path, &s);
                }
                Ok(s)
            }
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("NotFound") {
                    self.cache_negative(path);
                    Err(not_found_err(path))
                } else {
                    Err(std::io::Error::other(e))
                }
            }
        }
    }
}

fn not_found_err(path: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::NotFound, path.to_owned())
}

// ── fuser::Filesystem ─────────────────────────────────────────────────────────

impl Filesystem for QuicFs {
    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let parent_path = match self.path_for(parent) {
            Some(p) => PathBuf::from(p),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };
        let child = Self::child_path(&parent_path, name);
        let path_str = child.to_string_lossy().into_owned();

        match self.get_stat(&path_str) {
            Ok(stat) => {
                let attr = self.make_file_attr(child, &stat);
                reply.entry(&self.fuse_ttl, &attr, 0);
            }
            Err(e) => reply.error(io_to_errno(e)),
        }
    }

    fn forget(&mut self, _req: &Request<'_>, ino: u64, nlookup: u64) {
        // No-op: we don't prune the InodeTable on forget (see design note).
        let _ = (ino, nlookup);
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyAttr) {
        let path = match self.path_for(ino) {
            Some(p) => p,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };
        match self.get_stat(&path) {
            Ok(stat) => {
                let path_buf = PathBuf::from(&path);
                let attr = self.make_file_attr(path_buf, &stat);
                reply.attr(&self.fuse_ttl, &attr);
            }
            Err(e) => reply.error(io_to_errno(e)),
        }
    }

    fn setattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        let path = match self.path_for(ino) {
            Some(p) => p,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        // A size change (truncate) must be ordered AFTER any buffered writes for
        // this file. Otherwise a write still sitting in the coalesce buffer would
        // flush to the server after the truncate and re-grow the file with the
        // bytes the application discarded. Flush first; if that fails, fail the
        // truncate rather than truncating over data we could not persist.
        if size.is_some() {
            let flushed = match _fh {
                Some(fh) => self.flush_handle(fh),
                None => self.flush_all_handles(),
            };
            if let Err(e) = flushed {
                warn!("setattr: flush before truncate failed: {e}");
                reply.error(rpc_to_errno(&e));
                return;
            }
        }

        let mut valid: u32 = 0;
        if mode.is_some() {
            valid |= 0x1;
        }
        if uid.is_some() {
            valid |= 0x2;
        }
        if gid.is_some() {
            valid |= 0x4;
        }
        if size.is_some() {
            valid |= 0x8;
        }
        if atime.is_some() {
            valid |= 0x10;
        }
        if mtime.is_some() {
            valid |= 0x20;
        }

        let ns_of = |t: TimeOrNow| -> i64 {
            let st = match t {
                TimeOrNow::SpecificTime(s) => s,
                TimeOrNow::Now => SystemTime::now(),
            };
            st.duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as i64)
                .unwrap_or(0)
        };

        match self.rt.block_on(self.conn.setattr(
            &path,
            valid,
            mode.unwrap_or(0),
            uid.unwrap_or(0),
            gid.unwrap_or(0),
            size.unwrap_or(0),
            atime.map(ns_of).unwrap_or(0),
            mtime.map(ns_of).unwrap_or(0),
        )) {
            Ok(stat) => {
                self.invalidate_cache(&path);
                let attr = self.make_file_attr(PathBuf::from(&path), &stat);
                reply.attr(&self.fuse_ttl, &attr);
            }
            Err(e) => reply.error(rpc_to_errno(&e)),
        }
    }

    fn readlink(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyData) {
        let path = match self.path_for(ino) {
            Some(p) => p,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };
        match self.rt.block_on(self.conn.readlink(&path)) {
            Ok(target) => reply.data(target.as_bytes()),
            Err(e) => reply.error(rpc_to_errno(&e)),
        }
    }

    fn mkdir(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let parent_path = match self.path_for(parent) {
            Some(p) => PathBuf::from(p),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };
        let child = Self::child_path(&parent_path, name);
        let path_str = child.to_string_lossy().into_owned();
        self.invalidate_cache(parent_path.to_str().unwrap_or("/"));
        match self.rt.block_on(self.conn.mkdir(&path_str, mode)) {
            Ok(stat) => {
                self.cache_stat(&path_str, &stat);
                let attr = self.make_file_attr(child, &stat);
                reply.entry(&self.fuse_ttl, &attr, 0);
            }
            Err(e) => reply.error(rpc_to_errno(&e)),
        }
    }

    fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let parent_path = match self.path_for(parent) {
            Some(p) => PathBuf::from(p),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };
        let child = Self::child_path(&parent_path, name);
        let path_str = child.to_string_lossy().into_owned();
        self.invalidate_cache(&path_str);
        match self.rt.block_on(self.conn.unlink(&path_str)) {
            Ok(()) => {
                self.inodes.lock().unwrap().remove_path(&child);
                reply.ok();
            }
            Err(e) => reply.error(rpc_to_errno(&e)),
        }
    }

    fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let parent_path = match self.path_for(parent) {
            Some(p) => PathBuf::from(p),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };
        let child = Self::child_path(&parent_path, name);
        let path_str = child.to_string_lossy().into_owned();
        self.invalidate_cache(&path_str);
        match self.rt.block_on(self.conn.rmdir(&path_str)) {
            Ok(()) => {
                self.inodes.lock().unwrap().remove_path(&child);
                reply.ok();
            }
            Err(e) => reply.error(rpc_to_errno(&e)),
        }
    }

    fn symlink(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        link_name: &OsStr,
        target: &Path,
        reply: ReplyEntry,
    ) {
        let parent_path = match self.path_for(parent) {
            Some(p) => PathBuf::from(p),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };
        let link_path = Self::child_path(&parent_path, link_name);
        let link_str = link_path.to_string_lossy().into_owned();
        let target_str = target.to_string_lossy().into_owned();
        match self.rt.block_on(self.conn.symlink(&target_str, &link_str)) {
            Ok(stat) => {
                self.cache_stat(&link_str, &stat);
                let attr = self.make_file_attr(link_path, &stat);
                reply.entry(&self.fuse_ttl, &attr, 0);
            }
            Err(e) => reply.error(rpc_to_errno(&e)),
        }
    }

    fn rename(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        new_parent: u64,
        new_name: &OsStr,
        flags: u32,
        reply: ReplyEmpty,
    ) {
        let old_parent = match self.path_for(parent) {
            Some(p) => PathBuf::from(p),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };
        let new_par = match self.path_for(new_parent) {
            Some(p) => PathBuf::from(p),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };
        let old_path = Self::child_path(&old_parent, name);
        let new_path = Self::child_path(&new_par, new_name);
        let old_str = old_path.to_string_lossy().into_owned();
        let new_str = new_path.to_string_lossy().into_owned();
        match self
            .rt
            .block_on(self.conn.rename(&old_str, &new_str, flags))
        {
            Ok(()) => {
                self.invalidate_cache(&old_str);
                // Also invalidate the destination: if it had a negative cache
                // entry (from a previous LOOKUP that returned ENOENT), that
                // entry would hide the just-renamed file from subsequent stats.
                self.invalidate_cache(&new_str);
                // Invalidate destination parent so its readdir listing refreshes.
                if let Some(p) = new_path.parent() {
                    self.invalidate_cache(&p.to_string_lossy());
                }
                self.inodes.lock().unwrap().rename_ino(&old_path, new_path);
                reply.ok();
            }
            Err(e) => reply.error(rpc_to_errno(&e)),
        }
    }

    fn link(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        new_parent: u64,
        new_name: &OsStr,
        reply: ReplyEntry,
    ) {
        let src_path = match self.path_for(ino) {
            Some(p) => p,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };
        let new_par = match self.path_for(new_parent) {
            Some(p) => PathBuf::from(p),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };
        let new_path = Self::child_path(&new_par, new_name);
        let new_str = new_path.to_string_lossy().into_owned();
        match self.rt.block_on(self.conn.link(&src_path, &new_str)) {
            Ok(stat) => {
                // Invalidate src's MetaCache so next getattr returns nlink=2.
                self.invalidate_cache(&src_path);
                // Cache the updated stat for src too (nlink is shared).
                self.cache_stat(&src_path, &stat);
                // Invalidate dst: ln first does a LOOKUP which caches ENOENT;
                // that negative entry would hide the just-created link when the
                // kernel re-lookups with TTL=0.
                self.invalidate_cache(&new_str);
                // Cache dst's stat so the re-lookup is served from cache.
                self.cache_stat(&new_str, &stat);
                let attr = self.make_file_attr(new_path, &stat);
                // 1ms TTL forces the kernel to re-ask almost immediately, so
                // both src and dst reflect nlink=2 without waiting for the
                // full cache TTL.  Duration::ZERO causes entry-expiry before
                // the calling process can re-stat, which breaks some tools.
                reply.entry(&Duration::from_millis(1), &attr, 0);
            }
            Err(e) => reply.error(rpc_to_errno(&e)),
        }
    }

    fn open(&mut self, _req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        let path = match self.path_for(ino) {
            Some(p) => p,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };
        // Order any buffered writes for this file BEFORE a truncating open, so a
        // late flush cannot re-grow what O_TRUNC clears.
        if let Err(e) = self.fence_truncating_open(flags) {
            warn!("open: flush before O_TRUNC failed: {e}");
            reply.error(rpc_to_errno(&e));
            return;
        }
        match self.rt.block_on(self.conn.open(&path, flags as u32)) {
            // Return the kernel a stable CLIENT fh, not the server handle, so a
            // reconnect can swap a fresh server handle in transparently.
            Ok((server_handle, _stat)) => {
                let client_fh = self.register_open(path, flags as u32, server_handle);
                reply.opened(client_fh, 0)
            }
            Err(e) => reply.error(rpc_to_errno(&e)),
        }
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock: Option<u64>,
        reply: ReplyData,
    ) {
        // Read-your-writes: a read on a handle that still has buffered (not yet
        // sent) writes must observe them. Flush this handle's coalesced writes to
        // the server first; otherwise the server, which has not received those
        // bytes, would return stale or short data for a region we just wrote.
        if let Err(e) = self.flush_handle(fh) {
            warn!(fh, "read: flush of buffered writes before read failed: {e}");
            reply.error(rpc_to_errno(&e));
            return;
        }
        // Resolve the live server handle (flush_handle already reopened it if the
        // connection had reconnected).
        let server_handle = match self.live_handle(fh) {
            Some(h) => h,
            None => {
                reply.error(libc::ESTALE);
                return;
            }
        };
        match self
            .rt
            .block_on(self.conn.read(server_handle, offset as u64, size))
        {
            Ok(data) => reply.data(&data),
            Err(e) => reply.error(rpc_to_errno(&e)),
        }
    }

    fn write(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock: Option<u64>,
        reply: ReplyWrite,
    ) {
        // Invalidate cached size for this file; it will be refreshed after flush.
        if let Some(path) = self.path_for(ino) {
            self.invalidate_cache(&path);
        }
        // Refresh the handle on a reconnect (reopen; for an O_APPEND handle this
        // also drops its un-replayable buffer) BEFORE buffering the new bytes. A
        // reopen failure (server down) is fine here: we still buffer and deliver
        // on the next reconnect (keep-until-acked).
        let _ = self.live_handle(fh);
        let n = data.len() as u32;
        let decision = self
            .write_buf
            .lock()
            .unwrap()
            .push(fh, offset as u64, data.to_vec());

        match decision {
            PushDecision::Buffered => {
                // Data queued; tell the kernel we accepted all bytes.
                reply.written(n);
            }
            PushDecision::FlushThis(h) | PushDecision::FlushOther(h) => {
                // A soft limit was hit - flush that handle to reclaim memory. This
                // is best-effort write-back: the bytes are already buffered
                // (keep-until-ack), so if the flush fails (transient outage) we
                // keep them for replay and STILL acknowledge the write. The data
                // is not lost - the hard-cap Reject below and the background
                // age-drop bound it loudly, and close()/fsync() report a genuine
                // failure via their own flush. Surfacing EIO here would defeat the
                // whole keep-buffered-across-reconnect guarantee.
                let _ = self.flush_handle(h);
                reply.written(n);
            }
            PushDecision::Reject => {
                // The hard memory bound would be exceeded and the chunk was NOT
                // buffered (the server is likely unreachable and unacked data has
                // piled up). Fail loudly rather than silently drop or grow toward
                // OOM; the sticky error also makes close()/fsync() report it.
                self.write_errors.lock().unwrap().insert(fh);
                warn!(
                    fh,
                    "write buffer hard cap reached (server unreachable?); failing write with EIO"
                );
                reply.error(libc::EIO);
            }
        }
    }

    /// Called by the kernel for each `close(2)` on a file descriptor.
    /// Flush any buffered writes; if the flush fails, return EIO so the
    /// application knows the write didn't reach the server.
    fn flush(&mut self, _req: &Request<'_>, _ino: u64, fh: u64, _lock: u64, reply: ReplyEmpty) {
        let flush_err = self.flush_handle_drain(fh).err().map(|e| rpc_to_errno(&e));
        // Consume (report-once) any sticky error - including one set earlier by the
        // background flush task - so close() can never succeed while a buffered
        // write silently failed to reach the server.
        let had_sticky = self.write_errors.lock().unwrap().remove(&fh);
        match flush_reply(flush_err, had_sticky) {
            Ok(()) => reply.ok(),
            Err(errno) => {
                warn!(fh, errno, "flush: buffered write did not reach the server");
                reply.error(errno);
            }
        }
    }

    /// Called when the last file descriptor for this handle is closed.
    /// Flush, then release the server-side handle.
    fn release(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        _flags: i32,
        _lock: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        if let Err(e) = self.flush_handle_drain(fh) {
            warn!(fh, "release flush: {e}");
        }
        // Clear any sticky error so it can't leak onto a future handle. close()'s
        // flush() is the surface point that reports it to the app; the kernel
        // ignores release()'s result.
        if self.write_errors.lock().unwrap().remove(&fh) {
            warn!(
                fh,
                "release: buffered writes for this handle failed to reach the server"
            );
        }
        // Resolve the current server handle (flush_handle reopened it if needed),
        // drop the fh-remap entry and any residual buffered chunks, then release
        // the server-side handle.
        let server_handle = self
            .open_files
            .lock()
            .unwrap()
            .remove(&fh)
            .map(|of| of.server_handle);
        self.write_buf.lock().unwrap().drop_handle(fh);
        match server_handle {
            Some(sh) => match self.rt.block_on(self.conn.release(sh)) {
                Ok(()) => reply.ok(),
                Err(e) => {
                    warn!("release fh={fh} (server handle {sh}): {e}");
                    reply.ok();
                }
            },
            None => reply.ok(),
        }
    }

    fn fsync(&mut self, _req: &Request<'_>, _ino: u64, fh: u64, datasync: bool, reply: ReplyEmpty) {
        // Durability is fsync()'s contract: a failed flush OR a sticky error from a
        // prior (e.g. background) flush must make fsync() fail, never silently pass.
        let flush_err = self.flush_handle_drain(fh).err().map(|e| rpc_to_errno(&e));
        let had_sticky = self.write_errors.lock().unwrap().remove(&fh);
        if let Err(errno) = flush_reply(flush_err, had_sticky) {
            warn!(fh, errno, "fsync: buffered write did not reach the server");
            reply.error(errno);
            return;
        }
        let server_handle = match self.live_handle(fh) {
            Some(h) => h,
            None => {
                reply.error(libc::ESTALE);
                return;
            }
        };
        match self.rt.block_on(self.conn.fsync(server_handle, datasync)) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(rpc_to_errno(&e)),
        }
    }

    fn opendir(&mut self, _req: &Request<'_>, _ino: u64, _flags: i32, reply: ReplyOpen) {
        // No server-side state for open directories - use ino as fh.
        reply.opened(0, 0);
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let path = match self.path_for(ino) {
            Some(p) => p,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };
        let entries = match self.rt.block_on(self.conn.readdir(&path)) {
            Ok(e) => e,
            Err(e) => {
                reply.error(rpc_to_errno(&e));
                return;
            }
        };

        // FUSE offset: entries before `offset` (0-based) are skipped.
        for (i, entry) in entries.iter().enumerate().skip(offset as usize) {
            let kind = mode_to_file_type(entry.mode);
            let child = PathBuf::from(format!("{}/{}", path.trim_end_matches('/'), entry.name));
            let child_ino = self.inodes.lock().unwrap().get_or_alloc(child);
            // If the reply buffer is full, stop (FUSE will call again with higher offset).
            if reply.add(child_ino, (i + 1) as i64, kind, &entry.name) {
                break;
            }
        }
        reply.ok();
    }

    fn releasedir(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _flags: i32,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    fn statfs(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyStatfs) {
        let path = self.path_for(ino).unwrap_or_else(|| "/".to_owned());
        match self.rt.block_on(self.conn.statfs(&path)) {
            Ok(fs) => reply.statfs(
                fs.blocks, fs.bfree, fs.bavail, fs.files, fs.ffree, fs.bsize, fs.namelen, fs.frsize,
            ),
            Err(e) => reply.error(rpc_to_errno(&e)),
        }
    }

    fn create(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        let parent_path = match self.path_for(parent) {
            Some(p) => PathBuf::from(p),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };
        let child = Self::child_path(&parent_path, name);
        let path_str = child.to_string_lossy().into_owned();
        // A create carrying O_TRUNC truncates an existing file on the server;
        // fence buffered writes first so a late flush cannot re-grow it.
        if let Err(e) = self.fence_truncating_open(flags) {
            warn!("create: flush before O_TRUNC failed: {e}");
            reply.error(rpc_to_errno(&e));
            return;
        }
        self.invalidate_cache(parent_path.to_str().unwrap_or("/"));
        self.invalidate_cache(&path_str);
        match self
            .rt
            .block_on(self.conn.create(&path_str, flags as u32, mode))
        {
            Ok((server_handle, stat)) => {
                self.cache_stat(&path_str, &stat);
                let client_fh = self.register_open(path_str, flags as u32, server_handle);
                let attr = self.make_file_attr(child, &stat);
                reply.created(&self.fuse_ttl, &attr, 0, client_fh, 0);
            }
            Err(e) => reply.error(rpc_to_errno(&e)),
        }
    }
}

// ── Conversion helpers ────────────────────────────────────────────────────────

fn stat_to_file_attr(stat: &Stat, ino: u64) -> FileAttr {
    let ns_to_st = |ns: i64| -> SystemTime {
        if ns >= 0 {
            UNIX_EPOCH + Duration::from_nanos(ns as u64)
        } else {
            UNIX_EPOCH
                .checked_sub(Duration::from_nanos((-ns) as u64))
                .unwrap_or(UNIX_EPOCH)
        }
    };

    FileAttr {
        ino,
        size: stat.size,
        blocks: stat.blocks,
        atime: ns_to_st(stat.atime),
        mtime: ns_to_st(stat.mtime),
        ctime: ns_to_st(stat.ctime),
        crtime: ns_to_st(stat.ctime),
        kind: mode_to_file_type(stat.mode),
        perm: (stat.mode & 0xFFF) as u16,
        nlink: stat.nlink,
        uid: stat.uid,
        gid: stat.gid,
        rdev: 0,
        blksize: stat.blksz,
        flags: 0,
    }
}

fn mode_to_file_type(mode: u32) -> FileType {
    match (mode >> 12) & 0xF {
        0x4 => FileType::Directory,
        0x8 => FileType::RegularFile,
        0xA => FileType::Symlink,
        0x1 => FileType::NamedPipe,
        0x2 => FileType::CharDevice,
        0x6 => FileType::BlockDevice,
        0xC => FileType::Socket,
        _ => FileType::RegularFile,
    }
}

fn io_to_errno(e: std::io::Error) -> libc::c_int {
    use std::io::ErrorKind::*;
    match e.kind() {
        NotFound => libc::ENOENT,
        PermissionDenied => libc::EACCES,
        AlreadyExists => libc::EEXIST,
        DirectoryNotEmpty => libc::ENOTEMPTY,
        InvalidInput | InvalidData => libc::EINVAL,
        _ => libc::EIO,
    }
}

fn rpc_to_errno(e: &anyhow::Error) -> libc::c_int {
    let msg = e.to_string();
    if msg.contains("NotFound") {
        return libc::ENOENT;
    }
    if msg.contains("Permission") {
        return libc::EACCES;
    }
    if msg.contains("Exists") {
        return libc::EEXIST;
    }
    if msg.contains("NotEmpty") {
        return libc::ENOTEMPTY;
    }
    if msg.contains("NotDir") {
        return libc::ENOTDIR;
    }
    if msg.contains("IsDir") {
        return libc::EISDIR;
    }
    if msg.contains("NoSpace") {
        return libc::ENOSPC;
    }
    if msg.contains("Stale") {
        return libc::ESTALE;
    }
    libc::EIO
}

#[cfg(test)]
mod tests {
    use super::flush_reply;

    // The durability invariant: close()/fsync() must report an error whenever
    // buffered data failed to reach the server - never a silent success.
    #[test]
    fn flush_reply_never_silently_succeeds_on_failure() {
        // Clean flush, no sticky error -> success.
        assert_eq!(flush_reply(None, false), Ok(()));
        // Sticky error from an earlier (e.g. background) flush -> EIO, NOT ok.
        assert_eq!(flush_reply(None, true), Err(libc::EIO));
        // Direct flush failure -> that specific errno.
        assert_eq!(flush_reply(Some(libc::ENOENT), false), Err(libc::ENOENT));
        // Both: the direct (more specific) errno wins, still an error.
        assert_eq!(flush_reply(Some(libc::EACCES), true), Err(libc::EACCES));
    }
}
