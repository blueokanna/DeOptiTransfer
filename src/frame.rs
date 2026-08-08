//! Protocol v3 frame format and integrity.
//!
//! Every frame is fully self-describing (no handshake): a 25-byte
//! little-endian header followed by the `block_len` payload bytes.
//!
//! ```text
//!  0  2 bytes  magic        D1 0F
//!  2  u8       flags        bit0 direct-systematic, bit1 causal
//!  3  u16      session_id   random per sender start
//!  5  u32      seq
//!  9  u16      k            source block count
//! 11  u16      block_len    payload bytes per frame
//! 13  u32      total_len    protected container length
//! 17  u32      stream_tag   BLAKE3 tag of the whole container
//! 21  u32      frame_tag    BLAKE3 tag of this header + block
//! ```
//!
//! [`parse_frame`] verifies `frame_tag` before a frame reaches the decoder,
//! so a damaged frame becomes an erasure instead of a poisoned equation. A
//! receiver locks to the first [`StreamIdentity`]; frames from any other
//! stream are rejected by the [`session`](crate::session) layer.

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

/// The fixed, self-describing fields of a protocol-v3 frame.
///
/// Serialized little-endian (2 magic bytes are prepended by
/// [`pack_frame`]); every field except `seq` is constant across a stream and
/// together they form the stream's [`StreamIdentity`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameHeader {
    /// Mode bits: `FLAG_SYSTEMATIC` (direct systematic) or `FLAG_CAUSAL`
    /// (causal weave); the receiver adapts to whichever is set.
    pub flags: u8,
    /// Random per sender start; mixed into the fountain PRNG seed.
    pub session_id: u16,
    /// Sequence number; drives the fountain / weave.
    pub seq: u32,
    /// Source block count.
    pub k: u16,
    /// Payload bytes per frame.
    pub block_len: u16,
    /// Protected container length in bytes.
    pub total_len: u32,
    /// BLAKE3-derived tag identifying the whole transmitted container.
    pub stream_tag: u32,
    /// BLAKE3-derived tag over this header and block, verified on arrival.
    pub frame_tag: u32,
}

/// Everything about a frame that must hold constant for a decoder to keep
/// accepting frames into it. `seq` is deliberately absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamIdentity {
    pub flags: u8,
    pub session_id: u16,
    pub k: u16,
    pub block_len: u16,
    pub total_len: u32,
    pub stream_tag: u32,
}

/// Serialize a frame: the 25-byte header (with magic prefix) followed by
/// `block`.
pub fn pack_frame(h: &FrameHeader, block: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + block.len());
    out.push(MAGIC0);
    out.push(MAGIC1);
    out.extend_from_slice(&CFG.serialize(h).expect("fixed header cannot fail"));
    out.extend_from_slice(block);
    out
}

/// Parse and integrity-check a frame.
///
/// Returns `None` for wrong magic, inconsistent fields, or a `frame_tag`
/// mismatch — a damaged frame is an erasure, never a poisoned equation.
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

/// Project a frame header onto its constant stream identity.
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
