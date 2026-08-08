use alloc::vec::Vec;
use rustbinary::Config;
use serde::{Deserialize, Serialize};

pub const HEADER_LEN: usize = 25;
pub const MAGIC0: u8 = 0xd1;
pub const MAGIC1: u8 = 0x0f;
pub const FLAG_SYSTEMATIC: u8 = 1;
pub const FLAG_CAUSAL: u8 = 2;
pub const FLAG_MASK: u8 = FLAG_SYSTEMATIC | FLAG_CAUSAL;
pub const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_STREAM_BYTES: u64 = MAX_FILE_BYTES + 2 * u16::MAX as u64 + 128;

const CFG: Config = Config::legacy()
    .with_little_endian()
    .with_fixint_encoding()
    .reject_trailing_bytes()
    .with_limit(32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameHeader {
    pub flags: u8,
    pub session_id: u16,
    pub seq: u32,
    pub k: u16,
    pub block_len: u16,
    pub total_len: u32,
    pub stream_tag: u32,
    pub frame_tag: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamIdentity {
    pub flags: u8,
    pub session_id: u16,
    pub k: u16,
    pub block_len: u16,
    pub total_len: u32,
    pub stream_tag: u32,
}

pub fn pack_frame(h: &FrameHeader, block: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + block.len());
    out.push(MAGIC0);
    out.push(MAGIC1);
    out.extend_from_slice(&CFG.serialize(h).expect("fixed header cannot fail"));
    out.extend_from_slice(block);
    out
}

pub fn parse_frame(bytes: &[u8]) -> Option<(FrameHeader, &[u8])> {
    if bytes.len() <= HEADER_LEN || bytes[0] != MAGIC0 || bytes[1] != MAGIC1 {
        return None;
    }
    let h: FrameHeader = CFG.deserialize(&bytes[2..HEADER_LEN]).ok()?;
    if h.flags & !FLAG_MASK != 0
        || h.flags & FLAG_MASK == FLAG_MASK
        || h.k == 0
        || h.block_len == 0
        || h.total_len == 0
    {
        return None;
    }
    if bytes.len() != HEADER_LEN + h.block_len as usize {
        return None;
    }
    let block = &bytes[HEADER_LEN..];
    if frame_checksum(&h, block) != h.frame_tag {
        return None;
    }
    Some((h, block))
}

pub const fn stream_identity(h: &FrameHeader) -> StreamIdentity {
    StreamIdentity {
        flags: h.flags,
        session_id: h.session_id,
        k: h.k,
        block_len: h.block_len,
        total_len: h.total_len,
        stream_tag: h.stream_tag,
    }
}

#[inline]
pub fn checksum32(bytes: &[u8]) -> u32 {
    let digest = blake3::hash(bytes);
    let b = digest.as_bytes();
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

pub fn frame_checksum(h: &FrameHeader, block: &[u8]) -> u32 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[h.flags]);
    hasher.update(&h.session_id.to_le_bytes());
    hasher.update(&h.seq.to_le_bytes());
    hasher.update(&h.k.to_le_bytes());
    hasher.update(&h.block_len.to_le_bytes());
    hasher.update(&h.total_len.to_le_bytes());
    hasher.update(&h.stream_tag.to_le_bytes());
    hasher.update(block);
    let digest = hasher.finalize();
    let b = digest.as_bytes();
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

#[inline]
pub fn fnv1a(bytes: &[u8]) -> u32 {
    let mut h = 0x811c_9dc5u32;
    for &b in bytes {
        h ^= b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}
