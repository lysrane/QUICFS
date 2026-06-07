use serde::{Deserialize, Serialize};

use crate::stat::{DirEntry, Stat, StatFs};

// Operation codes (§5.3)
pub const OP_GET_ATTR: u8 = 0x01;
pub const OP_SET_ATTR: u8 = 0x02;
pub const OP_READ_DIR: u8 = 0x03;
pub const OP_MKDIR: u8 = 0x04;
pub const OP_RMDIR: u8 = 0x05;
pub const OP_UNLINK: u8 = 0x06;
pub const OP_RENAME: u8 = 0x07;
pub const OP_SYMLINK: u8 = 0x08;
pub const OP_READLINK: u8 = 0x09;
pub const OP_LINK: u8 = 0x0A;
pub const OP_STAT_FS: u8 = 0x0B;

pub const OP_OPEN: u8 = 0x10;
pub const OP_RELEASE: u8 = 0x11;
pub const OP_CREATE: u8 = 0x12;

pub const OP_READ: u8 = 0x20;
pub const OP_WRITE: u8 = 0x21;
pub const OP_FSYNC: u8 = 0x22;

pub const OP_GET_XATTR: u8 = 0x30;
pub const OP_SET_XATTR: u8 = 0x31;
pub const OP_LIST_XATTR: u8 = 0x32;
pub const OP_REMOVE_XATTR: u8 = 0x33;

pub const OP_LOCK: u8 = 0x40;
pub const OP_UNLOCK: u8 = 0x41;

pub const OP_HANDSHAKE: u8 = 0xF0;
pub const OP_PING: u8 = 0xF1;
pub const OP_WATCH: u8 = 0xF2;

/// Maximum encoded frame size enforced by both sides. This is the hard wire
/// ceiling that bounds per-stream read allocation (DoS protection); it is not
/// operator-tunable on purpose, a frame larger than this is always a protocol
/// violation regardless of config.
pub const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

/// ALPN protocol identifier advertised on every QUIC connection. Both ends set
/// the same value; a peer that does not offer it is rejected during the TLS
/// handshake (no_application_protocol), so a stray non-QuicFS QUIC client never
/// reaches the app handshake. Bump the suffix on any wire-incompatible change.
pub const ALPN_PROTOCOL: &[u8] = b"quicfs/1";

/// Minimal envelope parsed first to route a frame to the right handler.
#[derive(Debug, Deserialize)]
pub struct Envelope {
    pub op: u8,
    pub seq: u64,
}

// ── Handshake (0xF0) ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeRequest {
    pub op: u8,
    pub seq: u64,
    pub version: u8,
    pub client_id: String,
    pub features: Vec<String>,
    pub chunk_size: u32,
    /// Authentication scheme. Only `"mtls"` (TOFU client key) is supported.
    pub auth_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeResponse {
    pub op: u8,
    pub seq: u64,
    pub status: u8,
    pub version: u8,
    pub features: Vec<String>,
    pub chunk_size: u32,
    pub server_id: String,
    pub export_root: String,
}

// ── Ping (0xF1) ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingRequest {
    pub op: u8,
    pub seq: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingResponse {
    pub op: u8,
    pub seq: u64,
    pub status: u8,
}

// ── GetAttr (0x01) ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetAttrRequest {
    pub op: u8,
    pub seq: u64,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetAttrResponse {
    pub op: u8,
    pub seq: u64,
    pub status: u8,
    pub stat: Option<Stat>,
}

// ── SetAttr (0x02) ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetAttrRequest {
    pub op: u8,
    pub seq: u64,
    pub path: String,
    /// Bitmask: 0x1=mode 0x2=uid 0x4=gid 0x8=size 0x10=atime 0x20=mtime
    pub valid: u32,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub atime: i64,
    pub mtime: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetAttrResponse {
    pub op: u8,
    pub seq: u64,
    pub status: u8,
    pub stat: Option<Stat>,
}

// ── ReadDir (0x03) ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadDirRequest {
    pub op: u8,
    pub seq: u64,
    pub path: String,
    pub cursor: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadDirResponse {
    pub op: u8,
    pub seq: u64,
    pub status: u8,
    pub entries: Vec<DirEntry>,
    pub cursor: u64,
    pub eof: bool,
}

// ── Open (0x10) ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenRequest {
    pub op: u8,
    pub seq: u64,
    pub path: String,
    pub flags: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenResponse {
    pub op: u8,
    pub seq: u64,
    pub status: u8,
    pub handle: u64,
    pub stat: Option<Stat>,
}

// ── Release (0x11) ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseRequest {
    pub op: u8,
    pub seq: u64,
    pub handle: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseResponse {
    pub op: u8,
    pub seq: u64,
    pub status: u8,
}

// ── Read (0x20) ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadRequest {
    pub op: u8,
    pub seq: u64,
    pub handle: u64,
    pub offset: u64,
    pub length: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadResponse {
    pub op: u8,
    pub seq: u64,
    pub status: u8,
    pub offset: u64,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
    pub eof: bool,
}

// ── Write (0x21) ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteRequest {
    pub op: u8,
    pub seq: u64,
    pub handle: u64,
    pub offset: u64,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
    pub done: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteResponse {
    pub op: u8,
    pub seq: u64,
    pub status: u8,
    /// Total bytes committed in this Write RPC.  u64 to avoid overflow on
    /// large writes (u32 wraps at 4 GiB).
    pub written: u64,
}

// ── Rename (0x07) ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenameRequest {
    pub op: u8,
    pub seq: u64,
    pub old: String,
    pub new: String,
    pub flags: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenameResponse {
    pub op: u8,
    pub seq: u64,
    pub status: u8,
}

// ── Simple path-only ops (Unlink, RmDir, ReadLink) ───────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathRequest {
    pub op: u8,
    pub seq: u64,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    pub op: u8,
    pub seq: u64,
    pub status: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadLinkResponse {
    pub op: u8,
    pub seq: u64,
    pub status: u8,
    pub target: String,
}

// ── MkDir (0x04) ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MkDirRequest {
    pub op: u8,
    pub seq: u64,
    pub path: String,
    pub mode: u32,
}

// ── Create (0x12) ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateRequest {
    pub op: u8,
    pub seq: u64,
    pub path: String,
    pub flags: u32,
    pub mode: u32,
}

// ── Fsync (0x22) ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsyncRequest {
    pub op: u8,
    pub seq: u64,
    pub handle: u64,
    pub datasync: bool,
}

// ── StatFS (0x0B) ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatFsResponse {
    pub op: u8,
    pub seq: u64,
    pub status: u8,
    pub statfs: Option<StatFs>,
}

// ── Symlink (0x08) / Link (0x0A) ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymlinkRequest {
    pub op: u8,
    pub seq: u64,
    /// The target the symlink points to.
    pub target: String,
    /// The path at which the symlink is created.
    pub link: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkRequest {
    pub op: u8,
    pub seq: u64,
    /// Existing file path.
    pub path: String,
    /// New (hard) link path.
    pub link: String,
}

// ── Watch (0xF2) ─────────────────────────────────────────────────────────────

pub const WATCH_CREATE: u32 = 1;
pub const WATCH_DELETE: u32 = 2;
pub const WATCH_MODIFY: u32 = 4;
pub const WATCH_RENAME: u32 = 8;
pub const WATCH_ATTR: u32 = 16;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchRequest {
    pub op: u8,
    pub seq: u64,
    pub watch_id: u64,
    pub path: String,
    pub recursive: bool,
    pub events: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchEvent {
    pub op: u8,
    pub watch_id: u64,
    pub event: u8,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stat: Option<Stat>,
}
