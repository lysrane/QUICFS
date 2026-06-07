pub mod ctrl;
pub mod data;
pub mod meta;

use std::path::Path;

/// fsync the parent directory of `resolved` (confined beneath `root`) so a
/// namespace mutation that just touched it is crash-durable. Best-effort: a
/// failure is logged, never turned into the op's status. Callers gate this on
/// `session.sync_metadata`.
///
/// Why best-effort and not a failure status: the VFS mutation (create, rename,
/// unlink, ...) has ALREADY taken effect by the time we get here; it is visible
/// on the server. Reporting an error for it would tell the client an op that
/// physically happened did not, diverging client state (e.g. a rename the client
/// then refuses to apply to its inode map, so the moved file vanishes from view).
/// POSIX does not promise durability without an explicit fsync, so success is the
/// correct answer; a directory-fsync failure is a server-host device problem the
/// operator must see in the log, not a per-op error the client can act on.
///
/// `resolved` is the entry that changed; its parent is the directory whose entry
/// list changed. The export root itself (whose parent is out of our scope) and a
/// path with no parent are no-ops.
pub(crate) fn sync_parent_dir(root: &Path, resolved: &Path) {
    if resolved == root {
        return;
    }
    let Some(parent) = resolved.parent() else {
        return;
    };
    #[cfg(unix)]
    {
        if let Err(e) = crate::sanitize::fsync_dir_confined(root, parent) {
            tracing::error!(
                dir = %parent.display(),
                "metadata durability: parent-directory fsync failed (the entry is \
                 present but may not survive a crash): {e}"
            );
        }
    }
    #[cfg(not(unix))]
    {
        let _ = parent;
    }
}
