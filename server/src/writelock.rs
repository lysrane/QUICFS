//! Per-inode write serialization via lock striping.
//!
//! Two Write RPCs to the same physical file can arrive on different open
//! handles (separate opens, even separate client sessions), each backed by its
//! own file descriptor and its own per-handle mutex. Without coordination their
//! individual `write(2)` calls can interleave: a single logical client write
//! that the client coalesced into one multi-frame RPC could land in pieces,
//! torn by another writer's bytes. On a local filesystem the kernel's per-inode
//! lock makes each `write(2)` atomic; splitting one logical write across frames
//! on the server loses that guarantee.
//!
//! We restore it by serializing every Write RPC to a given inode on a shared
//! async mutex, held for the whole RPC (so the coalesced batch lands as a unit).
//! Rather than a growing map of one mutex per live inode (which needs lifecycle
//! management), we use a fixed stripe array indexed by a hash of the inode key.
//! Two unrelated files that hash to the same stripe merely serialize against
//! each other occasionally - never a correctness problem, only a rare and minor
//! loss of write parallelism. Memory is bounded and constant; nothing to clean
//! up. The lock is process-global so it serializes writers across sessions too.

use std::sync::LazyLock;

use tokio::sync::Mutex;

/// Number of stripes. Large enough that unrelated files rarely collide onto one
/// lock, small enough that the one-time allocation stays cheap.
const STRIPES: usize = 1024;

static STRIPES_ARR: LazyLock<Vec<Mutex<()>>> =
    LazyLock::new(|| (0..STRIPES).map(|_| Mutex::new(())).collect());

/// The stripe mutex guarding writes to the file identified by `key`
/// (`dev << 64 | ino` on unix). Every Write RPC to one physical file locks the
/// same returned mutex for its whole duration, so a multi-frame write lands
/// contiguously and cannot be interleaved byte-for-byte with another writer.
pub fn stripe_for(key: u128) -> &'static Mutex<()> {
    // Mix both halves so adjacent inodes (the common case on one filesystem)
    // spread across stripes instead of clustering.
    let lo = (key as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let hi = ((key >> 64) as u64).wrapping_mul(0xD1B5_4A32_D192_ED03);
    let mixed = lo ^ hi.rotate_left(32);
    &STRIPES_ARR[(mixed as usize) % STRIPES]
}

#[cfg(test)]
mod tests {
    use super::*;

    // The same inode key must always map to the same stripe, so two write RPCs
    // to one file serialize against each other.
    #[test]
    fn same_key_maps_to_the_same_stripe() {
        let k = 0x0000_0001_0000_002au128; // dev 1, ino 42
        assert!(std::ptr::eq(stripe_for(k), stripe_for(k)));
    }

    // The index must actually depend on the key: a run of adjacent inodes (the
    // common case on one filesystem) must not all collapse onto one stripe, or
    // unrelated files would needlessly serialize. This catches a degenerate mix
    // (e.g. an index that is constant or ignores the low bits).
    #[test]
    fn adjacent_inodes_spread_across_stripes() {
        let mut seen = std::collections::HashSet::new();
        for ino in 0..256u128 {
            seen.insert(stripe_for(ino) as *const _ as usize);
        }
        assert!(
            seen.len() > 1,
            "stripe index must vary with the inode key, not be constant"
        );
    }
}
