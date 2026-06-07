use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::frames::MAX_FRAME_SIZE;

/// Write a length-prefixed frame: 4-byte big-endian length followed by `data`.
pub async fn write_frame<W: AsyncWriteExt + Unpin>(writer: &mut W, data: &[u8]) -> Result<()> {
    if data.len() > MAX_FRAME_SIZE {
        bail!("frame too large: {} bytes", data.len());
    }
    writer
        .write_u32(data.len() as u32)
        .await
        .context("write length prefix")?;
    writer.write_all(data).await.context("write frame body")?;
    Ok(())
}

/// Read a length-prefixed frame.
pub async fn read_frame<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let len = reader.read_u32().await.context("read length prefix")? as usize;
    if len > MAX_FRAME_SIZE {
        bail!("frame too large: {len} bytes");
    }
    let mut buf = vec![0u8; len];
    reader
        .read_exact(&mut buf)
        .await
        .context("read frame body")?;
    Ok(buf)
}

/// Encode `val` as named MessagePack map.
pub fn encode<T: serde::Serialize>(val: &T) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(val).context("msgpack encode")
}

/// Decode `data` as `T`.
pub fn decode<T: serde::de::DeserializeOwned>(data: &[u8]) -> Result<T> {
    rmp_serde::from_slice(data).context("msgpack decode")
}
