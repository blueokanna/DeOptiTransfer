use alloc::vec::Vec;

use crate::capacity::source_block_count;
use crate::container::PackedOpticalFile;
use crate::error::{Error, Result};
use crate::fountain::{LtDecoder, LtEncoder};
use crate::frame::{
    checksum32, frame_checksum, pack_frame, parse_frame, stream_identity, FrameHeader,
    StreamIdentity, FLAG_CAUSAL, FLAG_SYSTEMATIC, HEADER_LEN, MAX_STREAM_BYTES,
};

pub struct Sender {
    encoder: LtEncoder,
    seq: u32,
    exhausted: bool,
    session_id: u16,
    k: u16,
    block_len: u16,
    total_len: u32,
    stream_tag: u32,
    flags: u8,
}

impl Sender {
    pub fn new(container: &[u8], block_len: usize, session_id: u16) -> Self {
        Self::try_new(container, block_len, session_id).expect("valid sender parameters")
    }

    pub fn try_new(container: &[u8], block_len: usize, session_id: u16) -> Result<Self> {
        Self::try_with_mode(container, block_len, session_id, FLAG_CAUSAL)
    }

    pub fn new_systematic(container: &[u8], block_len: usize, session_id: u16) -> Self {
        Self::try_new_systematic(container, block_len, session_id).expect("valid sender parameters")
    }

    pub fn try_new_systematic(container: &[u8], block_len: usize, session_id: u16) -> Result<Self> {
        Self::try_with_mode(container, block_len, session_id, FLAG_SYSTEMATIC)
    }

    pub fn new_rsd(container: &[u8], block_len: usize, session_id: u16) -> Self {
        Self::try_new_rsd(container, block_len, session_id).expect("valid sender parameters")
    }

    pub fn try_new_rsd(container: &[u8], block_len: usize, session_id: u16) -> Result<Self> {
        Self::try_with_mode(container, block_len, session_id, 0)
    }

    fn try_with_mode(
        container: &[u8],
        block_len: usize,
        session_id: u16,
        flags: u8,
    ) -> Result<Self> {
        if container.is_empty() {
            return Err(Error::Empty);
        }
        if block_len == 0 || block_len > u16::MAX as usize {
            return Err(Error::InvalidStream);
        }
        if container.len() as u64 > MAX_STREAM_BYTES {
            return Err(Error::TooLarge {
                len: container.len() as u64,
                max: MAX_STREAM_BYTES,
            });
        }
        let frame_bytes = block_len
            .checked_add(HEADER_LEN)
            .ok_or(Error::InvalidStream)?;
        let k = source_block_count(container.len(), frame_bytes).ok_or(Error::InvalidStream)?;
        if k == 0 || k > u16::MAX as usize {
            return Err(Error::InvalidStream);
        }
        let encoder = match flags {
            FLAG_CAUSAL => LtEncoder::try_new_causal(container, block_len, session_id as u32),
            FLAG_SYSTEMATIC => {
                LtEncoder::try_new_systematic(container, block_len, session_id as u32)
            }
            _ => LtEncoder::try_new(container, block_len, session_id as u32),
        }?;
        Ok(Self {
            encoder,
            seq: 0,
            exhausted: false,
            session_id,
            k: k as u16,
            block_len: block_len as u16,
            total_len: container.len() as u32,
            stream_tag: checksum32(container),
            flags,
        })
    }

    pub fn from_packed(packed: &PackedOpticalFile, block_len: usize, session_id: u16) -> Self {
        Self::new(&packed.container, block_len, session_id)
    }

    pub fn try_from_packed(
        packed: &PackedOpticalFile,
        block_len: usize,
        session_id: u16,
    ) -> Result<Self> {
        Self::try_new(&packed.container, block_len, session_id)
    }

    #[inline]
    pub fn k(&self) -> u16 {
        self.k
    }

    #[inline]
    pub fn session_id(&self) -> u16 {
        self.session_id
    }

    #[inline]
    pub fn is_systematic(&self) -> bool {
        self.flags == FLAG_SYSTEMATIC
    }

    #[inline]
    pub fn is_causal(&self) -> bool {
        self.flags == FLAG_CAUSAL
    }

    pub fn try_next_frame(&mut self) -> Result<Frame> {
        if self.exhausted {
            return Err(Error::SequenceExhausted);
        }
        let seq = self.seq;
        let block = self.encoder.encode(seq);
        let mut header = FrameHeader {
            flags: self.flags,
            session_id: self.session_id,
            seq,
            k: self.k,
            block_len: self.block_len,
            total_len: self.total_len,
            stream_tag: self.stream_tag,
            frame_tag: 0,
        };
        header.frame_tag = frame_checksum(&header, &block);
        if seq == u32::MAX {
            self.exhausted = true;
        } else {
            self.seq += 1;
        }
        Ok(Frame { header, block })
    }

    pub fn next_frame(&mut self) -> Frame {
        self.try_next_frame().expect("frame sequence exhausted")
    }
}

pub struct Frame {
    pub header: FrameHeader,
    pub block: Vec<u8>,
}

impl Frame {
    pub fn to_bytes(&self) -> Vec<u8> {
        pack_frame(&self.header, &self.block)
    }
}

pub struct Receiver {
    decoder: Option<LtDecoder>,
    identity: Option<StreamIdentity>,
    delivered: bool,
}

impl Receiver {
    pub const fn new() -> Self {
        Self {
            decoder: None,
            identity: None,
            delivered: false,
        }
    }

    pub fn reset(&mut self) {
        self.decoder = None;
        self.identity = None;
        self.delivered = false;
    }

    pub fn try_push(&mut self, bytes: &[u8]) -> Result<Option<Vec<u8>>> {
        let (h, block) = parse_frame(bytes).ok_or(Error::CorruptFrame)?;
        let id = stream_identity(&h);
        if let Some(active) = self.identity {
            if active != id {
                return Err(Error::StreamConflict);
            }
        } else {
            let decoder = match h.flags {
                FLAG_CAUSAL => LtDecoder::try_new_causal(
                    h.k as usize,
                    h.block_len as usize,
                    h.session_id as u32,
                    h.total_len as usize,
                ),
                FLAG_SYSTEMATIC => LtDecoder::try_new_systematic(
                    h.k as usize,
                    h.block_len as usize,
                    h.session_id as u32,
                    h.total_len as usize,
                ),
                _ => LtDecoder::try_new(
                    h.k as usize,
                    h.block_len as usize,
                    h.session_id as u32,
                    h.total_len as usize,
                ),
            }?;
            self.decoder = Some(decoder);
            self.identity = Some(id);
        }
        if self.delivered {
            return Ok(None);
        }
        let decoder = self.decoder.as_mut().ok_or(Error::InvalidStream)?;
        decoder.add_frame(h.seq, block);
        if !decoder.is_complete() {
            return Ok(None);
        }
        let container = decoder.assemble().ok_or(Error::InvalidStream)?;
        if checksum32(&container) != h.stream_tag {
            self.reset();
            return Err(Error::CorruptFrame);
        }
        self.delivered = true;
        Ok(Some(container))
    }

    pub fn push(&mut self, bytes: &[u8]) -> Option<Vec<u8>> {
        self.try_push(bytes).ok().flatten()
    }

    #[inline]
    pub fn is_active(&self) -> bool {
        self.decoder.is_some()
    }

    #[inline]
    pub const fn identity(&self) -> Option<StreamIdentity> {
        self.identity
    }
}

impl Default for Receiver {
    fn default() -> Self {
        Self::new()
    }
}
