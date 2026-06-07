#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok = 0,
    NotFound = 1,
    Permission = 2,
    Io = 3,
    Exists = 4,
    NotEmpty = 5,
    NotDir = 6,
    IsDir = 7,
    InvalidArg = 8,
    NoSpace = 9,
    TooLarge = 10,
    Stale = 11,
    Unknown = 255,
}

impl From<u8> for Status {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Ok,
            1 => Self::NotFound,
            2 => Self::Permission,
            3 => Self::Io,
            4 => Self::Exists,
            5 => Self::NotEmpty,
            6 => Self::NotDir,
            7 => Self::IsDir,
            8 => Self::InvalidArg,
            9 => Self::NoSpace,
            10 => Self::TooLarge,
            11 => Self::Stale,
            _ => Self::Unknown,
        }
    }
}

impl From<std::io::Error> for Status {
    fn from(e: std::io::Error) -> Self {
        use std::io::ErrorKind::*;
        match e.kind() {
            NotFound => Self::NotFound,
            PermissionDenied => Self::Permission,
            AlreadyExists => Self::Exists,
            InvalidInput | InvalidData => Self::InvalidArg,
            _ => Self::Io,
        }
    }
}
