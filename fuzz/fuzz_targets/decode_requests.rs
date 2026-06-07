#![no_main]
//! Fuzz the wire-frame deserialization - the literal entry point for all attacker
//! bytes. The server reads a length-prefixed frame and `decode`s it (rmp-serde /
//! MessagePack) into a typed request before acting on it. We decode arbitrary
//! bytes into EVERY server-handled request type, discarding the result: the goal
//! is to surface panics, multi-GB allocations, or hangs on hostile input. This
//! directly stresses the known "frame reader pre-allocates the declared length"
//! DoS concern at the payload-parsing layer.

use libfuzzer_sys::fuzz_target;
use quicfs_common::frames::*;
use quicfs_common::io::decode;

macro_rules! try_decode {
    ($data:expr, $($t:ty),* $(,)?) => {
        $( let _ = decode::<$t>($data); )*
    };
}

fuzz_target!(|data: &[u8]| {
    try_decode!(
        data,
        Envelope,
        HandshakeRequest,
        PingRequest,
        GetAttrRequest,
        SetAttrRequest,
        ReadDirRequest,
        OpenRequest,
        ReleaseRequest,
        ReadRequest,
        WriteRequest,
        RenameRequest,
        PathRequest,
        MkDirRequest,
        CreateRequest,
        FsyncRequest,
        SymlinkRequest,
        LinkRequest,
        WatchRequest,
    );
});
