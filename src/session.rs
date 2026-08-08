use alloc::string::String;
use alloc::vec::Vec;

use crate::capacity::source_block_count;
use crate::container::PackedOpticalFile;
use crate::fountain::{LtDecoder, LtEncoder};
use crate::frame::{
    fnv1a, parse_frame, pack_frame, stream_identity, FrameHeader, FLAG_SYSTEMATIC,
};

pub struct Sender {
    encoder: LtEncoder,
    seq: u32,
    session_id: u16,
    k: u16,
    block_len: u16,
    total_len: u32,
    payload_fnv: u32,
}

impl Sender {
    pub fn new(container: &[u8], block_len: usize, session_id: u16) -> Self {
        Self::with_mode(container, block_len, session_id, true)
    }

    pub fn new_rsd(container: &[u8], block_len: usize, session_id: u16) -> Self {
        Self::with_mode(container, block_len, session_id, false)
    }

    fn with_mode(container: &[u8], block_len: usize, session_id: u16, systematic: bool) -> Self {
        assert!(block_len > 0, "block_len must be positive");
        let k = source_block_count(container.len(), block_len + crate::frame::HEADER_LEN);
        assert!(k <= u16::MAX as usize, "payload does not fit one stream at this frame size");
        assert!(container.len() <= u32::MAX as usize);
        let encoder = if systematic {
            LtEncoder::new_systematic(container, block_len, session_id as u32)
        } else {
            LtEncoder::new(container, block_len, session_id as u32)
        };
        Self {
            encoder,
            seq: 0,
            session_id,
            k: k as u16,
            block_len: block_len as u16,
            total_len: container.len() as u32,
            payload_fnv: fnv1a(container),
        }
    }

    pub fn from_packed(packed: &PackedOpticalFile, block_len: usize, session_id: u16) -> Self {
        Self::new(&packed.container, block_len, session_id)
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
        self.encoder.sys_span() > 0
    }

    pub fn header(&self) -> FrameHeader {
        FrameHeader {
            flags: if self.encoder.sys_span() > 0 {
                FLAG_SYSTEMATIC
            } else {
                0
            },
            session_id: self.session_id,
            seq: self.seq,
            k: self.k,
            block_len: self.block_len,
            total_len: self.total_len,
            payload_fnv: self.payload_fnv,
        }
    }

    pub fn next_frame(&mut self) -> Frame {
        let header = self.header();
        let block = self.encoder.encode(self.seq);
        self.seq = self.seq.wrapping_add(1);
        Frame { header, block }
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
    identity: String,
}

impl Receiver {
    pub fn new() -> Self {
        Self {
            decoder: None,
            identity: String::new(),
        }
    }

    pub fn push(&mut self, bytes: &[u8]) -> Option<Vec<u8>> {
        let (h, block) = parse_frame(bytes)?;
        let id = stream_identity(&h);
        if self.decoder.is_none() || self.identity != id {
            let decoder = if h.flags & FLAG_SYSTEMATIC != 0 {
                LtDecoder::try_new_systematic(
                    h.k as usize,
                    h.block_len as usize,
                    h.session_id as u32,
                    h.total_len as usize,
                )
            } else {
                LtDecoder::try_new(
                    h.k as usize,
                    h.block_len as usize,
                    h.session_id as u32,
                    h.total_len as usize,
                )
            }
            .ok()?;
            self.decoder = Some(decoder);
            self.identity = id;
        }
        let decoder = self.decoder.as_mut()?;
        decoder.add_frame(h.seq, block);
        if !decoder.is_complete() {
            return None;
        }
        let container = decoder.assemble()?;
        if fnv1a(&container) != h.payload_fnv {
            self.decoder = None;
            return None;
        }
        Some(container)
    }

    #[inline]
    pub fn is_active(&self) -> bool {
        self.decoder.is_some()
    }
}

impl Default for Receiver {
    fn default() -> Self {
        Self::new()
    }
}
