use alloc::vec;
use alloc::vec::Vec;

use crate::bytes::{words_as_bytes, words_as_bytes_mut};
use crate::capacity::MAX_SOURCE_BLOCKS;
use crate::error::{Error, Result};
use crate::frame::MAX_FILE_BYTES;
use crate::prng::{frame_seed, SplitMix32};
use crate::set::U32Set;
use crate::simd::xor_into;
use crate::soliton::{degree_binary, DegreeCdf};

const DENSE_LIMIT: usize = 256;

pub fn frame_indices(k: usize, cdf: &[f64], session_id: u32, seq: u32) -> Vec<u32> {
    let mut out = Vec::new();
    let mut scratch = Vec::new();
    let mut rnd = SplitMix32::new(frame_seed(session_id, seq));
    let u = (rnd.next_u32() as f64) / 4_294_967_296.0;
    let d = degree_binary(cdf, u).min(k);
    select_blocks(&mut out, &mut scratch, k, d, &mut rnd);
    out
}

fn frame_indices_into(
    out: &mut Vec<u32>,
    scratch: &mut Vec<u32>,
    cdf: &DegreeCdf,
    session_id: u32,
    seq: u32,
) {
    out.clear();
    let mut rnd = SplitMix32::new(frame_seed(session_id, seq));
    let u = (rnd.next_u32() as f64) / 4_294_967_296.0;
    let k = cdf.k();
    let d = cdf.sample(u).min(k);
    select_blocks(out, scratch, k, d, &mut rnd);
}

fn select_blocks(out: &mut Vec<u32>, scratch: &mut Vec<u32>, k: usize, d: usize, rnd: &mut SplitMix32) {
    if d > (k >> 3) {
        if scratch.len() < k {
            scratch.resize(k, 0);
        }
        for (i, slot) in scratch.iter_mut().enumerate() {
            *slot = i as u32;
        }
        out.reserve(d);
        for i in 0..d {
            let j = i + rnd.next_bounded((k - i) as u32) as usize;
            scratch.swap(i, j);
            out.push(scratch[i]);
        }
    } else {
        out.reserve(d);
        'outer: while out.len() < d {
            let v = rnd.next_bounded(k as u32);
            for &x in out.iter() {
                if x == v {
                    continue 'outer;
                }
            }
            out.push(v);
        }
    }
}

pub struct LtEncoder {
    k: usize,
    block_len: usize,
    words: usize,
    session_id: u32,
    sys_span: usize,
    blocks: Vec<u32>,
    cdf: DegreeCdf,
    idx: Vec<u32>,
    idx_scratch: Vec<u32>,
    acc: Vec<u32>,
}

impl LtEncoder {
    pub fn new(payload: &[u8], block_len: usize, session_id: u32) -> Self {
        Self::with_sys_span(payload, block_len, session_id, 0)
    }

    pub fn new_systematic(payload: &[u8], block_len: usize, session_id: u32) -> Self {
        let k = payload.len().div_ceil(block_len).max(1);
        Self::with_sys_span(payload, block_len, session_id, k)
    }

    fn with_sys_span(payload: &[u8], block_len: usize, session_id: u32, sys_span: usize) -> Self {
        assert!(block_len > 0, "block_len must be positive");
        let k = payload.len().div_ceil(block_len).max(1);
        let words = block_len.div_ceil(4);
        let mut blocks = vec![0u32; k * words];
        {
            let bytes = words_as_bytes_mut(&mut blocks);
            for b in 0..k {
                let start = b * block_len;
                let end = (start + block_len).min(payload.len());
                let dst = b * words * 4;
                bytes[dst..dst + (end - start)].copy_from_slice(&payload[start..end]);
            }
        }
        Self {
            k,
            block_len,
            words,
            session_id,
            sys_span,
            blocks,
            cdf: DegreeCdf::new(k),
            idx: Vec::new(),
            idx_scratch: Vec::new(),
            acc: vec![0u32; words],
        }
    }

    #[inline]
    pub fn k(&self) -> usize {
        self.k
    }

    #[inline]
    pub fn block_len(&self) -> usize {
        self.block_len
    }

    #[inline]
    pub fn session_id(&self) -> u32 {
        self.session_id
    }

    #[inline]
    pub fn is_systematic(&self) -> bool {
        self.sys_span > 0
    }

    #[inline]
    pub fn sys_span(&self) -> usize {
        self.sys_span
    }

    pub fn encode(&mut self, seq: u32) -> Vec<u8> {
        let mut out = vec![0u8; self.block_len];
        self.encode_into(seq, &mut out);
        out
    }

    pub fn encode_into(&mut self, seq: u32, out: &mut [u8]) {
        assert_eq!(out.len(), self.block_len, "output buffer must be block_len bytes");
        if (seq as usize) < self.sys_span {
            let base = ((seq as usize) % self.k) * self.words;
            out.copy_from_slice(&words_as_bytes(&self.blocks[base..base + self.words])
                [..self.block_len]);
            return;
        }
        frame_indices_into(
            &mut self.idx,
            &mut self.idx_scratch,
            &self.cdf,
            self.session_id,
            seq,
        );
        self.acc.fill(0);
        for &b in self.idx.iter() {
            let base = (b as usize) * self.words;
            xor_into(&mut self.acc, &self.blocks[base..base + self.words]);
        }
        out.copy_from_slice(&words_as_bytes(&self.acc)[..self.block_len]);
    }
}

type FrameId = usize;

#[derive(Debug)]
enum BlockSet {
    Dense(Vec<u32>),
    Sparse { bits: Vec<u64>, count: usize },
}

impl BlockSet {
    fn new(k: usize, members: Vec<u32>) -> Self {
        if members.len() > DENSE_LIMIT {
            let mut bits = vec![0u64; k.div_ceil(64)];
            for &b in &members {
                bits[b as usize / 64] |= 1u64 << (b as usize % 64);
            }
            Self::Sparse {
                bits,
                count: members.len(),
            }
        } else {
            Self::Dense(members)
        }
    }

    #[inline]
    fn len(&self) -> usize {
        match self {
            BlockSet::Dense(v) => v.len(),
            BlockSet::Sparse { count, .. } => *count,
        }
    }

    #[inline]
    fn remove(&mut self, block: u32) {
        match self {
            BlockSet::Dense(v) => {
                if let Some(i) = v.iter().position(|&x| x == block) {
                    v.swap_remove(i);
                }
            }
            BlockSet::Sparse { bits, count } => {
                let word = &mut bits[block as usize / 64];
                let mask = 1u64 << (block as usize % 64);
                if *word & mask != 0 {
                    *word &= !mask;
                    *count -= 1;
                }
            }
        }
    }

    #[inline]
    fn single(&self) -> u32 {
        match self {
            BlockSet::Dense(v) => v[0],
            BlockSet::Sparse { bits, .. } => {
                for (wi, word) in bits.iter().enumerate() {
                    if *word != 0 {
                        return (wi * 64 + word.trailing_zeros() as usize) as u32;
                    }
                }
                unreachable!("Sparse set with count 1 has no set bit")
            }
        }
    }
}

#[derive(Debug)]
struct PendingFrame {
    idx: BlockSet,
    off: usize,
    active: bool,
}

#[inline]
fn xor_at(arena: &mut [u32], a: usize, b: usize, words: usize) {
    debug_assert!(a != b, "distinct frames never share arena offsets");
    if a < b {
        let (left, right) = arena.split_at_mut(b);
        xor_into(&mut left[a..a + words], &right[..words]);
    } else {
        let (left, right) = arena.split_at_mut(a);
        xor_into(&mut right[..words], &left[b..b + words]);
    }
}

pub struct LtDecoder {
    k: usize,
    block_len: usize,
    words: usize,
    session_id: u32,
    total_len: usize,
    sys_span: usize,
    cdf: DegreeCdf,
    solved: Vec<Option<usize>>,
    solved_count: usize,
    frames: Vec<PendingFrame>,
    by_block: Vec<Vec<FrameId>>,
    seen: U32Set,
    idx: Vec<u32>,
    idx_scratch: Vec<u32>,
    arena: Vec<u32>,
    max_arena_words: usize,
    frames_new: usize,
    frames_dup: usize,
    frames_dropped: usize,
}

impl LtDecoder {
    pub fn new(k: usize, block_len: usize, session_id: u32, total_len: usize) -> Self {
        Self::try_new(k, block_len, session_id, total_len).expect("consistent stream parameters")
    }

    pub fn new_systematic(k: usize, block_len: usize, session_id: u32, total_len: usize) -> Self {
        Self::try_new_systematic(k, block_len, session_id, total_len)
            .expect("consistent stream parameters")
    }

    pub fn try_new(k: usize, block_len: usize, session_id: u32, total_len: usize) -> Result<Self> {
        Self::try_new_mode(k, block_len, session_id, total_len, 0)
    }

    pub fn try_new_systematic(
        k: usize,
        block_len: usize,
        session_id: u32,
        total_len: usize,
    ) -> Result<Self> {
        Self::try_new_mode(k, block_len, session_id, total_len, k)
    }

    fn try_new_mode(
        k: usize,
        block_len: usize,
        session_id: u32,
        total_len: usize,
        sys_span: usize,
    ) -> Result<Self> {
        if k == 0 || block_len == 0 || total_len == 0 {
            return Err(Error::InvalidStream);
        }
        if k > MAX_SOURCE_BLOCKS || block_len > u16::MAX as usize {
            return Err(Error::InvalidStream);
        }
        if (total_len as u64) > MAX_FILE_BYTES {
            return Err(Error::TooLarge {
                len: total_len as u64,
                max: MAX_FILE_BYTES,
            });
        }
        if k != total_len.div_ceil(block_len) {
            return Err(Error::InvalidStream);
        }
        let words = block_len.div_ceil(4);
        let max_arena_words = k.saturating_mul(words).saturating_mul(4);
        Ok(Self {
            k,
            block_len,
            words,
            session_id,
            total_len,
            sys_span,
            cdf: DegreeCdf::new(k),
            solved: vec![None; k],
            solved_count: 0,
            frames: Vec::new(),
            by_block: vec![Vec::new(); k],
            seen: U32Set::with_capacity(k),
            idx: Vec::new(),
            idx_scratch: Vec::new(),
            arena: Vec::with_capacity((k * words).min(1 << 21)),
            max_arena_words,
            frames_new: 0,
            frames_dup: 0,
            frames_dropped: 0,
        })
    }

    #[inline]
    pub fn is_complete(&self) -> bool {
        self.solved_count >= self.k
    }

    #[inline]
    pub fn is_systematic(&self) -> bool {
        self.sys_span > 0
    }

    #[inline]
    pub fn frames_new(&self) -> usize {
        self.frames_new
    }

    #[inline]
    pub fn frames_dup(&self) -> usize {
        self.frames_dup
    }

    #[inline]
    pub fn frames_dropped(&self) -> usize {
        self.frames_dropped
    }

    #[inline]
    pub fn solved_count(&self) -> usize {
        self.solved_count
    }

    pub fn add_frame(&mut self, seq: u32, block: &[u8]) {
        if !self.seen.insert(seq) {
            self.frames_dup += 1;
            return;
        }
        self.frames_new += 1;
        if self.is_complete() {
            return;
        }
        if self.arena.len() >= self.max_arena_words {
            self.frames_dropped += 1;
            return;
        }

        let off = self.arena.len();
        self.arena.resize(off + self.words, 0);
        {
            let n = block.len().min(self.block_len);
            words_as_bytes_mut(&mut self.arena[off..off + self.words])[..n]
                .copy_from_slice(&block[..n]);
        }

        if (seq as usize) < self.sys_span {
            let b = ((seq as usize) % self.k) as u32;
            self.resolve(b, off);
            return;
        }

        frame_indices_into(&mut self.idx, &mut self.idx_scratch, &self.cdf, self.session_id, seq);
        let mut unsolved = Vec::with_capacity(8);
        for &b in self.idx.iter() {
            match self.solved[b as usize] {
                Some(s_off) => xor_at(&mut self.arena, off, s_off, self.words),
                None => unsolved.push(b),
            }
        }

        if unsolved.is_empty() {
            return;
        }
        if unsolved.len() == 1 {
            let b = unsolved[0];
            self.resolve(b, off);
            return;
        }

        let frame_id = self.frames.len();
        for &b in &unsolved {
            self.by_block[b as usize].push(frame_id);
        }
        self.frames.push(PendingFrame {
            idx: BlockSet::new(self.k, unsolved),
            off,
            active: true,
        });
    }

    fn resolve(&mut self, b0: u32, off0: usize) {
        let mut queue: Vec<(u32, usize)> = Vec::with_capacity(16);
        queue.push((b0, off0));
        while let Some((b, off)) = queue.pop() {
            if self.solved[b as usize].is_some() {
                continue;
            }
            self.solved[b as usize] = Some(off);
            self.solved_count += 1;

            let waiting = core::mem::take(&mut self.by_block[b as usize]);
            for frame_id in waiting {
                let frame = &mut self.frames[frame_id];
                if !frame.active {
                    continue;
                }
                let s_off = self.solved[b as usize].expect("just stored");
                xor_at(&mut self.arena, frame.off, s_off, self.words);
                frame.idx.remove(b);
                match frame.idx.len() {
                    0 => frame.active = false,
                    1 => {
                        let r = frame.idx.single();
                        frame.active = false;
                        if self.solved[r as usize].is_none() {
                            queue.push((r, frame.off));
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    pub fn assemble(&self) -> Option<Vec<u8>> {
        if !self.is_complete() {
            return None;
        }
        let mut out = vec![0u8; self.total_len];
        for (b, value) in self.solved.iter().enumerate() {
            if let Some(off) = value {
                let start = b * self.block_len;
                let len = self.block_len.min(self.total_len - start);
                let src = words_as_bytes(&self.arena[*off..*off + self.words]);
                out[start..start + len].copy_from_slice(&src[..len]);
            }
        }
        Some(out)
    }
}
