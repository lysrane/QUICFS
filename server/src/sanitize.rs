use std::path::{Path, PathBuf};

use anyhow::{bail, Result};

/// Maximum byte length accepted for a client-supplied path.
/// Matches the Linux VFS limit (PATH_MAX).
const MAX_PATH_LEN: usize = 4096;

/// Maximum number of path components allowed.
const MAX_PATH_DEPTH: usize = 128;

/// Resolve a client-supplied path relative to `root`, rejecting any path that
/// would escape the export root or contain suspicious components.
///
/// Security rules enforced:
/// - Total path byte length ≤ 4096 (PATH_MAX).
/// - No null bytes anywhere in the path string.
/// - No `..` components after splitting on `/`.
/// - No intermediate path component is itself a symlink, and (if the final path
///   exists) its canonical form must stay under `root`. Together these prevent a
///   client from escaping the export root via symlinks it created.
///   NOTE: this is a check-then-use pattern and is therefore NOT race-free on its
///   own. The path-based open sinks (create/open/truncate) additionally route
///   through [`open_confined`], which on Linux uses `openat2(RESOLVE_BENEATH)` so
///   the kernel re-checks confinement atomically at open time and the swap window
///   is closed. resolve() remains the portable first line and the only check for
///   non-opening ops (lstat/readlink/unlink/rename of a path).
/// - Errors return a generic message / Permission status rather than echoing the
///   client's path (avoids reflecting attacker input in logs/errors). This is
///   minor hardening, not a secrecy guarantee.
pub fn resolve(root: &Path, client_path: &str) -> Result<PathBuf> {
    // ── Input validation ──────────────────────────────────────────────────────

    if client_path.len() > MAX_PATH_LEN {
        bail!("path too long");
    }
    if client_path.contains('\0') {
        bail!("path contains null byte");
    }

    // ── Component normalisation ───────────────────────────────────────────────

    let rel = client_path.trim_start_matches('/');
    let mut components: Vec<&str> = Vec::with_capacity(16);

    for part in rel.split('/') {
        match part {
            "" | "." => {}
            ".." => bail!("path traversal rejected"),
            p => {
                if p.len() > 255 {
                    bail!("path component too long");
                }
                components.push(p);
            }
        }
    }

    if components.len() > MAX_PATH_DEPTH {
        bail!("path too deep");
    }

    // ── Intermediate symlink check ────────────────────────────────────────────
    //
    // Walk each prefix of the path. If any intermediate directory component is a
    // symlink, reject. This blocks the common escape where a client makes
    // `/a -> /etc` then accesses `/a/passwd`, and (unlike the canonicalize check
    // below) it also covers paths whose final component doesn't exist yet
    // (create/rename targets). It is NOT race-free - see resolve()'s doc comment.
    // We use `symlink_metadata()` (no-follow) so we see the symlink itself.
    //
    // We do NOT check the final component - it is allowed to be a symlink
    // (e.g. `readlink`, `lstat`) or a regular file.  The final canonicalize
    // check below handles the case where the final component is a symlink.
    let mut walking = root.to_path_buf();
    for (i, &c) in components.iter().enumerate() {
        if i + 1 < components.len() {
            // Intermediate component - must not be a symlink.
            walking.push(c);
            match std::fs::symlink_metadata(&walking) {
                Ok(m) if m.file_type().is_symlink() => {
                    bail!("path escapes export root");
                }
                Ok(_) | Err(_) => {}
            }
        } else {
            walking.push(c);
        }
    }
    let joined = walking;

    // ── Canonical escape check ────────────────────────────────────────────────
    //
    // If the fully-joined path exists, canonicalize both it and the root and
    // confirm the result is still under root.  This catches escaping symlinks in
    // the final component whose target EXISTS (read/open/write/truncate of them).
    //
    // NOTE: `exists()` follows symlinks, so a *dangling* final-component symlink
    // (target absent) reads as "absent" and skips this branch - that is fine for
    // non-creating opens (they fail with ENOENT), but a create() would otherwise
    // follow it and materialise a file outside root. That specific escape is
    // closed at the create sink with O_NOFOLLOW (see ops::data::handle_create),
    // not here, because resolve() must still allow readlink/lstat/unlink/rename
    // of a symlink that legitimately points outside the export.
    if joined.exists() {
        let canonical = joined.canonicalize().unwrap_or_else(|_| joined.clone());
        let root_canonical = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        if !canonical.starts_with(&root_canonical) {
            bail!("path escapes export root");
        }
    }

    Ok(joined)
}

/// Open a file confined beneath `root`, closing the narrow resolve-then-open race
/// that [`resolve`] documents.
///
/// `resolved` must be a path beneath `root` (as produced by [`resolve`]). `flags`
/// and `mode` are raw libc `open(2)` flags and create mode.
///
/// On Linux this uses `openat2(2)` with `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS`
/// against a directory fd on `root`: the kernel itself refuses any resolution step
/// (including a symlink swapped in after `resolve()` ran) that would leave `root`,
/// so the open is race-free, while still following symlinks that stay beneath the
/// root. On a kernel without `openat2` (pre-5.6, `ENOSYS`) or a non-Linux unix
/// target it falls back to a plain `open(2)` with the same flags - the same narrow
/// race as before this change, never anything less safe.
#[cfg(unix)]
pub fn open_confined(
    root: &Path,
    resolved: &Path,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> std::io::Result<std::fs::File> {
    #[cfg(target_os = "linux")]
    {
        match openat2_beneath(root, resolved, flags, mode) {
            // Kernel < 5.6 has no openat2: fall through to the plain open below.
            Err(e) if e.raw_os_error() == Some(libc::ENOSYS) => {}
            other => return other,
        }
    }
    open_plain(resolved, flags, mode)
}

/// fsync a directory beneath `root` (confined exactly like [`open_confined`]) so
/// a namespace mutation that just touched it becomes crash-durable.
///
/// fsync'ing a file persists its data and inode, but the *directory entry* that
/// names it (or a rename/unlink/mkdir that changed which names exist) is only
/// guaranteed on stable storage after the containing directory is fsync'd. This
/// is the server half of the durable write-tmp-fsync-rename idiom. `dir` must be
/// `root` or a directory beneath it (the parent of an already-resolved path); we
/// open it confined and `sync_all()` it. Opening read-only is enough to fsync.
#[cfg(unix)]
pub fn fsync_dir_confined(root: &Path, dir: &Path) -> std::io::Result<()> {
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW;
    let f = open_confined(root, dir, flags, 0)?;
    f.sync_all()
}

// ── Confined namespace operations ───────────────────────────────────────────
//
// The non-opening namespace ops (mkdir/rmdir/unlink/rename/symlink/link/readlink)
// historically ran a path-based `std::fs` call right after resolve(), which left
// the same resolve-then-use TOCTOU that `open_confined` closes for the open sinks:
// a client could swap an intermediate path component to a symlink between
// resolve()'s walk and the syscall and steer the mutation OUTSIDE the export root.
// These helpers close that window the same way. They open the target's PARENT as a
// confined directory fd (`openat2(RESOLVE_BENEATH)`, race-free), then perform the
// operation with the `*at` family against the single trailing component. The dirfd
// pins the parent inode, the kernel refuses any parent path that leaves the root,
// and the `*at` calls operate on the named entry without following it, so neither
// the directory nor the final name can be steered out of the jail. On a non-unix
// target the handlers keep their portable `std::fs` path (best effort, no openat2).

/// Open the confined parent directory of `resolved` and return (dirfd, final name).
/// The dirfd is O_PATH, which is sufficient as the `dirfd` argument to the `*at`
/// calls. Fails (PermissionDenied) if the parent is not beneath `root`, e.g. when
/// `resolved` IS the export root (you cannot mkdir/unlink the root itself).
#[cfg(unix)]
fn confined_parent(
    root: &Path,
    resolved: &Path,
) -> std::io::Result<(std::fs::File, std::ffi::CString)> {
    use std::os::unix::ffi::OsStrExt;
    let parent = resolved
        .parent()
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let name = resolved
        .file_name()
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let name_c = std::ffi::CString::new(name.as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let dir = open_confined(root, parent, libc::O_PATH | libc::O_DIRECTORY, 0)?;
    Ok((dir, name_c))
}

#[cfg(unix)]
fn ok_or_errno(rc: libc::c_int) -> std::io::Result<()> {
    if rc != 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// `mkdir` confined beneath `root`. The mode is then set exactly (the client mode
/// already accounts for the client umask; we override the server umask so the new
/// directory carries the intended bits, matching the old create_dir + chmod path).
#[cfg(unix)]
pub fn mkdir_confined(root: &Path, resolved: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let (dir, name) = confined_parent(root, resolved)?;
    let m = (mode & 0o777) as libc::mode_t;
    ok_or_errno(unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), m) })?;
    ok_or_errno(unsafe { libc::fchmodat(dir.as_raw_fd(), name.as_ptr(), m, 0) })
}

/// `unlink` (a file, `is_dir = false`) or `rmdir` (`is_dir = true`) confined.
#[cfg(unix)]
pub fn remove_confined(root: &Path, resolved: &Path, is_dir: bool) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let (dir, name) = confined_parent(root, resolved)?;
    let flag = if is_dir { libc::AT_REMOVEDIR } else { 0 };
    ok_or_errno(unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), flag) })
}

/// Create a symlink at `link` (confined) whose contents are the arbitrary `target`
/// string. The target is not resolved or confined: it is just the link's payload,
/// and any later access through it goes back through resolve() + the confined sinks.
#[cfg(unix)]
pub fn symlink_confined(root: &Path, link: &Path, target: &str) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let (dir, name) = confined_parent(root, link)?;
    let target_c = std::ffi::CString::new(target.as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    ok_or_errno(unsafe { libc::symlinkat(target_c.as_ptr(), dir.as_raw_fd(), name.as_ptr()) })
}

/// Hard-link `src` -> `dst`, both confined beneath `root`. No symlink follow on the
/// source (flags 0), matching `std::fs::hard_link`.
#[cfg(unix)]
pub fn link_confined(root: &Path, src: &Path, dst: &Path) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let (sdir, sname) = confined_parent(root, src)?;
    let (ddir, dname) = confined_parent(root, dst)?;
    ok_or_errno(unsafe {
        libc::linkat(
            sdir.as_raw_fd(),
            sname.as_ptr(),
            ddir.as_raw_fd(),
            dname.as_ptr(),
            0,
        )
    })
}

/// Rename `old` -> `new`, both confined beneath `root` (plain rename semantics:
/// overwrites an existing destination, like `std::fs::rename`).
#[cfg(unix)]
pub fn rename_confined(root: &Path, old: &Path, new: &Path) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let (odir, oname) = confined_parent(root, old)?;
    let (ndir, nname) = confined_parent(root, new)?;
    ok_or_errno(unsafe {
        libc::renameat(
            odir.as_raw_fd(),
            oname.as_ptr(),
            ndir.as_raw_fd(),
            nname.as_ptr(),
        )
    })
}

/// Read a symlink's target confined beneath `root`.
#[cfg(unix)]
pub fn readlink_confined(root: &Path, resolved: &Path) -> std::io::Result<PathBuf> {
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::io::AsRawFd;
    let (dir, name) = confined_parent(root, resolved)?;
    let mut buf = vec![0u8; MAX_PATH_LEN];
    let n = unsafe {
        libc::readlinkat(
            dir.as_raw_fd(),
            name.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
        )
    };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    buf.truncate(n as usize);
    Ok(PathBuf::from(std::ffi::OsString::from_vec(buf)))
}

/// Plain `open(2)` fallback (non-Linux unix, or Linux without openat2).
#[cfg(unix)]
fn open_plain(
    resolved: &Path,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> std::io::Result<std::fs::File> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::FromRawFd;
    let c = std::ffi::CString::new(resolved.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    // O_CLOEXEC so no forked child inherits the fd.
    let fd = unsafe { libc::open(c.as_ptr(), flags | libc::O_CLOEXEC, mode as libc::c_uint) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

/// Linux `openat2(RESOLVE_BENEATH)` confined open.
#[cfg(target_os = "linux")]
fn openat2_beneath(
    root: &Path,
    resolved: &Path,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> std::io::Result<std::fs::File> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::FromRawFd;

    // openat2(RESOLVE_BENEATH) needs a path RELATIVE to the dirfd with no leading
    // slash; an absolute path (or a leading '/') is rejected with EXDEV. resolve()
    // returns root.join(components), so strip the root prefix to get that path.
    let rel = resolved.strip_prefix(root).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "path escapes export root",
        )
    })?;
    // openat2 rejects an empty pathname (without AT_EMPTY_PATH); when `resolved`
    // IS the root, the relative path is empty, so resolve the dirfd itself via
    // ".". This lets callers open/fsync the export root directory.
    let rel_os = rel.as_os_str();
    let rel_os = if rel_os.is_empty() {
        std::ffi::OsStr::new(".")
    } else {
        rel_os
    };
    let rel_c = std::ffi::CString::new(rel_os.as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let root_c = std::ffi::CString::new(root.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;

    // Anchor resolution at a dirfd on the export root. O_PATH is enough.
    let dirfd = unsafe {
        libc::open(
            root_c.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if dirfd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    // open_how is #[non_exhaustive]; zero it, then set only the fields we use.
    // mode must be 0 unless creating, or openat2 returns EINVAL.
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (flags | libc::O_CLOEXEC) as u64;
    how.mode = if flags & libc::O_CREAT != 0 {
        mode as u64
    } else {
        0
    };
    how.resolve = (libc::RESOLVE_BENEATH | libc::RESOLVE_NO_MAGICLINKS) as u64;

    let ret = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dirfd,
            rel_c.as_ptr(),
            &how as *const libc::open_how,
            std::mem::size_of::<libc::open_how>(),
        )
    };
    let err = std::io::Error::last_os_error();
    unsafe { libc::close(dirfd) };
    if ret < 0 {
        return Err(err);
    }
    Ok(unsafe { std::fs::File::from_raw_fd(ret as libc::c_int) })
}

#[cfg(test)]
mod tests {
    use super::*;

    // A root that does not exist on disk, so resolve() never reaches the
    // canonicalize() branch and symlink_metadata always errs (treated as
    // "not a symlink"). Keeps the component-jail tests hermetic.
    fn root() -> &'static Path {
        Path::new("/quicfs-test-export-root")
    }

    #[test]
    fn normal_paths_join_under_root() {
        assert_eq!(resolve(root(), "/a/b").unwrap(), root().join("a").join("b"));
        assert_eq!(
            resolve(root(), "a/b/c").unwrap(),
            root().join("a").join("b").join("c")
        );
        assert_eq!(resolve(root(), "/").unwrap(), root());
        assert_eq!(resolve(root(), "").unwrap(), root());
    }

    #[test]
    fn dot_and_empty_components_are_skipped() {
        assert_eq!(resolve(root(), "/./a").unwrap(), root().join("a"));
        assert_eq!(
            resolve(root(), "a/./b").unwrap(),
            root().join("a").join("b")
        );
        assert_eq!(
            resolve(root(), "///a//b").unwrap(),
            root().join("a").join("b")
        );
    }

    #[test]
    fn dotdot_is_rejected() {
        assert!(
            resolve(root(), "/a/../b").is_err(),
            "..-in-middle must be rejected"
        );
        assert!(resolve(root(), "..").is_err());
        assert!(resolve(root(), "/../etc/passwd").is_err());
        assert!(resolve(root(), "a/b/../../../../etc").is_err());
    }

    #[test]
    fn null_byte_is_rejected() {
        assert!(resolve(root(), "/a\0b").is_err());
        assert!(resolve(root(), "\0").is_err());
    }

    #[test]
    fn oversized_inputs_are_rejected() {
        let long_path = format!("/{}", "a".repeat(MAX_PATH_LEN));
        assert!(
            resolve(root(), &long_path).is_err(),
            "path > PATH_MAX must be rejected"
        );

        let long_component = format!("/{}", "x".repeat(256));
        assert!(
            resolve(root(), &long_component).is_err(),
            "component > 255 must be rejected"
        );

        let deep: String = std::iter::repeat("d")
            .take(MAX_PATH_DEPTH + 1)
            .map(|s| format!("/{s}"))
            .collect();
        assert!(
            resolve(root(), &deep).is_err(),
            "depth > MAX_PATH_DEPTH must be rejected"
        );
    }

    #[test]
    fn accepted_inputs_stay_under_root() {
        for p in ["/a", "a/b", "/./x/y", "deep/nested/path", "/"] {
            let resolved = resolve(root(), p).unwrap();
            assert!(
                resolved.starts_with(root()),
                "{p:?} escaped root: {resolved:?}"
            );
        }
    }

    proptest::proptest! {
        // The export-root jail invariant as a CI-runnable property test (a durable
        // guard mirroring the `resolve` cargo-fuzz target): for ANY input string,
        // resolve() must either error or return a path under the export root. A
        // regression here is a jail break. The `root()` here does not exist on disk,
        // so this exercises the pure component-normalization and `..`-rejection
        // logic (the kernel-enforced half is the `open_confined` fuzz target).
        #[test]
        fn resolve_never_escapes_root(s in ".*") {
            if let Ok(p) = resolve(root(), &s) {
                proptest::prop_assert!(
                    p.starts_with(root()),
                    "JAIL ESCAPE: resolve({:?}) -> {:?}",
                    s,
                    p
                );
            }
        }
    }
}

// openat2(RESOLVE_BENEATH) confinement. Linux-only: the helper degrades to a
// plain open elsewhere, so the kernel-enforced rejection only holds here (and on
// kernels >= 5.6, which the dev/CI box is).
#[cfg(all(test, target_os = "linux"))]
mod confined_open_tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn open_confined_reads_a_file_beneath_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::File::create(root.join("a"))
            .unwrap()
            .write_all(b"hi")
            .unwrap();
        // resolve() produces exactly the kind of path the handlers pass in.
        let resolved = resolve(root, "/a").unwrap();
        let mut f = open_confined(root, &resolved, libc::O_RDONLY, 0)
            .expect("a regular file beneath root must open");
        let mut s = String::new();
        f.read_to_string(&mut s).unwrap();
        assert_eq!(s, "hi");
    }

    #[test]
    fn open_confined_rejects_symlink_that_escapes_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // root/esc -> /etc (absolute symlink). resolve() would catch this for an
        // existing target, but we call open_confined directly to prove the kernel
        // also refuses it (closes the post-resolve swap window).
        std::os::unix::fs::symlink("/etc", root.join("esc")).unwrap();
        let resolved = root.join("esc").join("hostname"); // root/esc/hostname
        let opened = open_confined(root, &resolved, libc::O_RDONLY, 0);
        assert!(
            opened.is_err(),
            "escaping symlink must be rejected by RESOLVE_BENEATH"
        );
    }

    #[test]
    fn open_confined_creates_with_mode() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let resolved = resolve(root, "/new").unwrap();
        let f = open_confined(root, &resolved, libc::O_RDWR | libc::O_CREAT, 0o600)
            .expect("create beneath root must succeed");
        drop(f);
        assert!(
            root.join("new").exists(),
            "created file must exist beneath root"
        );
    }

    #[test]
    fn namespace_ops_refuse_escaping_parent_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let outside = tempfile::tempdir().unwrap();
        // root/esc -> outside (an escaping directory symlink). Any namespace op
        // whose parent traverses `esc` must be refused: the confined parent open
        // (openat2 RESOLVE_BENEATH) rejects leaving the root, closing the TOCTOU.
        std::os::unix::fs::symlink(outside.path(), root.join("esc")).unwrap();

        // mkdir through the escaping parent must fail AND must not create outside.
        let target = root.join("esc").join("pwned");
        assert!(mkdir_confined(root, &target, 0o755).is_err());
        assert!(
            !outside.path().join("pwned").exists(),
            "mkdir escaped the export root"
        );

        // A real file outside the root must be untouchable via the escaping parent.
        std::fs::write(outside.path().join("victim"), b"x").unwrap();
        let victim = root.join("esc").join("victim");
        assert!(remove_confined(root, &victim, false).is_err());
        assert!(
            outside.path().join("victim").exists(),
            "unlink escaped the export root"
        );
        let renamed = root.join("esc").join("renamed");
        assert!(rename_confined(root, &victim, &renamed).is_err());
        assert!(
            outside.path().join("victim").exists(),
            "rename escaped the export root"
        );

        // And a confined op with a legitimate in-root parent still works.
        std::fs::create_dir(root.join("realdir")).unwrap();
        assert!(mkdir_confined(root, &root.join("realdir").join("sub"), 0o755).is_ok());
        assert!(root.join("realdir").join("sub").is_dir());
    }
}
