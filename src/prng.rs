//! Deterministic wire-format PRNG: [`SplitMix32`] and [`frame_seed`].
//! Integer-only, so it is bit-identical on every target.

/// splitmix32: the wire-format PRNG. Integer-only, bit-identical everywhere.
pub struct SplitMix32 {
    state: u32,
}

impl SplitMix32 {
    #[inline]
    pub fn new(seed: u32) -> Self {
        Self { state: seed }
    }

    #[inline]
    pub fn next_u32(&mut self) -> u32 {
        self.state = self.state.wrapping_add(0x9e37_79b9);
        let mut t = self.state ^ (self.state >> 16);
        t = t.wrapping_mul(0x21f0_aaad);
        t ^= t >> 15;
        t = t.wrapping_mul(0x735a_2d97);
        t ^= t >> 15;
        t
    }

    #[inline]
    pub fn next_bounded(&mut self, bound: u32) -> u32 {
        if bound == 0 {
            0
        } else {
            self.next_u32() % bound
        }
    }
}

impl Iterator for SplitMix32 {
    type Item = u32;

    #[inline]
    fn next(&mut self) -> Option<u32> {
        Some(self.next_u32())
    }
}

/// Derive the per-frame PRNG seed from the session and sequence number.
/// Mixing both means a fresh session reshuffles the whole stream.
#[inline]
pub fn frame_seed(session_id: u32, seq: u32) -> u32 {
    let mut h =
        session_id.wrapping_add(1).wrapping_mul(0x9e37_79b1) ^ seq.wrapping_add(0x85eb_ca6b);
    h = (h ^ (h >> 13)).wrapping_mul(0xc2b2_ae35);
    h ^ (h >> 16)
}
