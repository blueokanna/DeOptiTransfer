use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use rustbinary::Config;
use serde::{Deserialize, Serialize};

pub const HEADER_LEN: usize = 21;
pub const MAGIC0: u8 = 0xd1;
pub const MAGIC1: u8 = 0x0e;
pub const FLAG_SYSTEMATIC: u8 = 1;
pub const FLAG_MASK: u8 = FLAG_SYSTEMATIC;
pub const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

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
    pub payload_fnv: u32,
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
    if h.flags & !FLAG_MASK != 0 || h.k == 0 || h.block_len == 0 || h.total_len == 0 {
        return None;
    }
    if bytes.len() != HEADER_LEN + h.block_len as usize {
        return None;
    }
    Some((h, &bytes[HEADER_LEN..]))
}

pub fn stream_identity(h: &FrameHeader) -> String {
    format!(
        "{}:{}:{}:{}:{}:{}",
        h.flags, h.session_id, h.k, h.block_len, h.total_len, h.payload_fnv
    )
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
