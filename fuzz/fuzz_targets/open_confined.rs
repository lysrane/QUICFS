#![no_main]
//! Fuzz the KERNEL-enforced half of the export-root jail: the composition of
//! `resolve` (produces a path under root) and `open_confined`
//! (openat2 RESOLVE_BENEATH). The invariant: whatever file open_confined opens,
//! its real path is under the export root - no client path string can make it
//! open something outside, including via planted symlinks.

use libfuzzer_sys::fuzz_target;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::OnceLock;

static ROOT: OnceLock<tempfile::TempDir> = OnceLock::new();

fn root() -> &'static Path {
    let dir = ROOT.get_or_init(|| {
        let d = tempfile::tempdir().expect("tempdir");
        let r = d.path();
        // A real subtree plus the symlinks an attacker would plant.
        let _ = std::fs::create_dir_all(r.join("sub/deep"));
        let _ = std::fs::write(r.join("sub/file"), b"x");
        let _ = std::os::unix::fs::symlink("/etc", r.join("escape")); // absolute escape
        let _ = std::os::unix::fs::symlink("../../../../etc", r.join("up")); // relative escape
        let _ = std::os::unix::fs::symlink("sub", r.join("link_in")); // legit within-root
        d
    });
    dir.path()
}

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let root = root();
    let Ok(resolved) = quicfs_server::sanitize::resolve(root, s) else {
        return;
    };
    let Ok(file) = quicfs_server::sanitize::open_confined(root, &resolved, libc::O_RDONLY, 0) else {
        return;
    };
    // Resolve what actually got opened and assert it is under the root.
    let link = format!("/proc/self/fd/{}", file.as_raw_fd());
    if let Ok(real) = std::fs::read_link(&link) {
        let root_canon = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        assert!(
            real.starts_with(&root_canon),
            "JAIL ESCAPE via open_confined: {s:?} opened {real:?} outside {root_canon:?}"
        );
    }
});
