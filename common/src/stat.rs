use serde::{Deserialize, Serialize};

/// POSIX-approximate stat structure sent over the wire.
/// All times are nanoseconds since Unix epoch.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Stat {
    pub ino: u64,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub atime: i64,
    pub mtime: i64,
    pub ctime: i64,
    pub blksz: u32,
    pub blocks: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirEntry {
    pub name: String,
    pub ino: u64,
    pub mode: u32,
}

/// Filesystem statistics (returned by StatFS).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StatFs {
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
    pub bsize: u32,
    pub namelen: u32,
    pub frsize: u32,
}
