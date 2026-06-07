use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use anyhow::{bail, Result};

/// An open file handle tracked by the server.
///
/// The handle retains the open `File` itself, not just a path. Read/Write/Fsync
/// operate on this retained descriptor (positioned `read_at`/`write_at`), so they
/// never reopen by path. That closes a rename-based TOCTOU: a client could
/// otherwise replace an intermediate directory of the stored path with a symlink
/// between RPCs and make a later reopen-by-name follow it outside the export
/// root. A retained fd refers to the inode opened at Open/Create time, immune to
/// later namespace changes. The `Arc<File>` is shared safely across concurrent
/// ops on the same handle because positioned I/O does not touch a shared cursor.
pub struct OpenHandle {
    pub path: PathBuf,
    pub flags: u32,
    pub file: std::sync::Arc<Mutex<std::fs::File>>,
    /// Stable identifier of the underlying file (`dev << 64 | ino` on unix),
    /// captured at open time. Used to serialize concurrent writes to the same
    /// physical file across handles/sessions (see `crate::writelock`). Two
    /// handles to the same inode share this key even via different path strings.
    pub ino_key: u128,
}

/// Per-session table of open file handles.
///
/// Handle IDs are namespaced per session: the high 32 bits hold a random epoch
/// chosen when the table is created, the low 32 bits a monotonic counter. The
/// table is per-QUIC-connection, so on a reconnect a fresh table (new epoch)
/// is created. This matters for correctness: a client that keeps using a handle
/// issued before a reconnect must NOT have that stale ID collide with a handle
/// the new session hands out for a different file. Without the epoch the counter
/// restarted at 1 every session, so a stale `fh` could resolve to the wrong file
/// and a buffered write would land there silently. With distinct epochs a stale
/// handle simply misses the table and the op fails Stale (surfaced as an error),
/// never a wrong-file write. The low 32 bits give 4 billion handles per session,
/// far above `max_handles` (bounded to prevent handle-exhaustion DoS), so the
/// counter never carries into the epoch.
pub struct HandleTable {
    counter: AtomicU64,
    max_handles: u32,
    inner: Mutex<HashMap<u64, OpenHandle>>,
}

impl HandleTable {
    /// Create a handle table that allows at most `max_handles` simultaneous
    /// open handles.  Pass `u32::MAX` to disable the limit (not recommended
    /// for public-facing servers).
    pub fn with_limit(max_handles: u32) -> Self {
        // Random per-session epoch in the high 32 bits so handle IDs from a
        // prior connection cannot collide with this session's (see struct doc).
        let epoch = (uuid::Uuid::new_v4().as_u128() as u64) & 0xFFFF_FFFF;
        Self {
            counter: AtomicU64::new((epoch << 32) | 1),
            max_handles,
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Attempt to insert a new handle.
    ///
    /// Returns the new handle ID on success, or an error if the table is at
    /// capacity.  Callers must map the error to `Status::NoSpace` or similar.
    pub fn try_insert(&self, path: PathBuf, flags: u32, file: std::fs::File) -> Result<u64> {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() >= self.max_handles as usize {
            bail!("too many open handles (limit: {})", self.max_handles);
        }
        let ino_key = ino_key_of(&file, &path);
        let id = self.counter.fetch_add(1, Ordering::Relaxed);
        map.insert(
            id,
            OpenHandle {
                path,
                flags,
                file: std::sync::Arc::new(Mutex::new(file)),
                ino_key,
            },
        );
        Ok(id)
    }

    /// Remove and return the handle, or `None` if it was never opened (or
    /// already released).
    pub fn remove(&self, id: u64) -> Option<OpenHandle> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&id)
    }

    /// Return the retained open file for `id`, or `None` for stale handles.
    /// Read/Write/Fsync use this so they never reopen by path.
    pub fn get_file(&self, id: u64) -> Option<std::sync::Arc<Mutex<std::fs::File>>> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&id)
            .map(|h| std::sync::Arc::clone(&h.file))
    }

    /// Return everything the write path needs for `id`: the retained file, the
    /// open flags (so it can honor O_APPEND), and the inode key (so it can take
    /// the right per-inode write-serialization stripe). `None` for stale handles.
    #[allow(clippy::type_complexity)]
    pub fn get_write_ctx(
        &self,
        id: u64,
    ) -> Option<(std::sync::Arc<Mutex<std::fs::File>>, u32, u128)> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&id)
            .map(|h| (std::sync::Arc::clone(&h.file), h.flags, h.ino_key))
    }

    /// Return the path associated with `id`, or `None` for stale handles.
    pub fn get_path(&self, id: u64) -> Option<PathBuf> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&id)
            .map(|h| h.path.clone())
    }

    /// Number of currently open handles.
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// `true` if no handles are open.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Compute the inode key (`dev << 64 | ino` on unix) used to serialize writes to
/// the same physical file. Two handles to one inode produce the same key even if
/// opened via different path strings, which a path hash would miss. On a metadata
/// error (or non-unix) we fall back to a hash of the path: still serializes the
/// common case (repeat opens of one path) and only over-serializes otherwise.
#[cfg(unix)]
fn ino_key_of(file: &std::fs::File, path: &std::path::Path) -> u128 {
    use std::os::unix::fs::MetadataExt;
    match file.metadata() {
        Ok(m) => ((m.dev() as u128) << 64) | (m.ino() as u128),
        Err(_) => path_hash_key(path),
    }
}

#[cfg(not(unix))]
fn ino_key_of(_file: &std::fs::File, path: &std::path::Path) -> u128 {
    path_hash_key(path)
}

/// Fallback inode key derived from the path, used only when the real (dev, ino)
/// is unavailable. The high bit is set so it can never collide with a real unix
/// key whose top byte is the device major (in practice 0 for the common case).
fn path_hash_key(path: &std::path::Path) -> u128 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    path.hash(&mut h);
    (1u128 << 127) | (h.finish() as u128)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Handle IDs must be namespaced per session so a stale handle from a prior
    // connection cannot resolve to a different file's handle in a new session.
    #[test]
    fn handle_ids_are_session_namespaced() {
        let f = || std::fs::File::open("/dev/null").unwrap();
        let a = HandleTable::with_limit(8192);
        let b = HandleTable::with_limit(8192);
        let a1 = a.try_insert("/x".into(), 0, f()).unwrap();
        let b1 = b.try_insert("/y".into(), 0, f()).unwrap();
        // Not the old "starts at 1" scheme.
        assert_ne!(a1, 1, "first handle must carry a session epoch, not be 1");
        // Two independent sessions allocate disjoint id ranges (different epochs).
        assert_ne!(a1 >> 32, b1 >> 32, "sessions must have distinct epochs");
        // A first-allocated handle from session A must not equal one from B.
        assert_ne!(a1, b1);
        // A stale id from session B does not resolve in session A.
        assert!(
            a.get_path(b1).is_none(),
            "stale cross-session handle must miss"
        );
    }
}
