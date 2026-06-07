#![no_main]
//! Fuzz the export-root jail's first line, `sanitize::resolve`.
//!
//! THE security invariant: for ANY client-supplied path string, if resolve()
//! returns Ok(p), then p must stay under the export root. A bug here (a missed
//! `..`, a normalization slip) is a jail break - arbitrary server-side file
//! access. This is the single highest-value security fuzz target; the area has
//! already shipped a CRITICAL escape and a HIGH TOCTOU that audits caught.
//!
//! We use a non-existent root so the filesystem-dependent checks (symlink_metadata
//! / canonicalize / exists) are inert, isolating the pure component-normalization
//! and `..`-rejection logic. The kernel-enforced confinement of the path-based
//! opens is fuzzed separately in `open_confined`.

use libfuzzer_sys::fuzz_target;
use std::path::Path;

fuzz_target!(|data: &[u8]| {
    // resolve takes a &str; only valid UTF-8 reaches it on the wire (the request
    // path fields deserialize as String), so confine the fuzz to UTF-8 inputs.
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let root = Path::new("/quicfs-fuzz-export-root-does-not-exist");
    if let Ok(resolved) = quicfs_server::sanitize::resolve(root, s) {
        assert!(
            resolved.starts_with(root),
            "JAIL ESCAPE: resolve({s:?}) -> {resolved:?} is outside the export root"
        );
    }
});
