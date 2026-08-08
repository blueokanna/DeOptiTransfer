//! A zero-dependency open-addressing `u32` set.
//!
//! The hash `v·0x9E3779B1 mod 2^t` is a bijection on the low bits, so any
//! run of consecutive keys (fountain sequence numbers) never collides.

use alloc::vec;
use alloc::vec::Vec;

const LOAD_NUM: usize = 7;
const LOAD_DEN: usize = 10;

/// An open-addressing set of `u32` keys with no external dependencies.
///
/// The multiplicative hash is a bijection on the low bits, so consecutive
/// keys (fountain sequence numbers) never collide; occupancy is packed into
/// a bit vector; the table rehashes at 0.7 load.
pub struct U32Set {
    keys: Vec<u32>,
    occ: Vec<u64>,
    mask: usize,
    len: usize,
}

impl U32Set {
    pub fn new() -> Self {
        Self {
            keys: Vec::new(),
            occ: Vec::new(),
            mask: 0,
            len: 0,
        }
    }

    pub fn with_capacity(n: usize) -> Self {
        let mut s = Self::new();
        let cap = n.next_power_of_two().max(8);
        s.keys = vec![0; cap];
        s.occ = vec![0; cap / 64 + 1];
        s.mask = cap - 1;
        s
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub fn contains(&self, v: u32) -> bool {
        if self.mask == 0 {
            return false;
        }
        let mut i = hash(v) & self.mask;
        loop {
            if !occ_bit(&self.occ, i) {
                return false;
            }
            if self.keys[i] == v {
                return true;
            }
            i = (i + 1) & self.mask;
        }
    }

    pub fn insert(&mut self, v: u32) -> bool {
        if self.mask == 0 || (self.len + 1) * LOAD_DEN >= self.keys.len() * LOAD_NUM {
            self.grow();
        }
        let mut i = hash(v) & self.mask;
        loop {
            if !occ_bit(&self.occ, i) {
                occ_set(&mut self.occ, i, true);
                self.keys[i] = v;
                self.len += 1;
                return true;
            }
            if self.keys[i] == v {
                return false;
            }
            i = (i + 1) & self.mask;
        }
    }

    fn grow(&mut self) {
        let old_keys = core::mem::take(&mut self.keys);
        let old_occ = core::mem::take(&mut self.occ);
        let old_mask = self.mask;
        let new_cap = if old_mask == 0 { 8 } else { (old_mask + 1) * 2 };
        self.keys = vec![0; new_cap];
        self.occ = vec![0; new_cap / 64 + 1];
        self.mask = new_cap - 1;
        self.len = 0;
        if old_mask != 0 {
            for (i, key) in old_keys.iter().enumerate() {
                if occ_bit(&old_occ, i) {
                    self.insert(*key);
                }
            }
        }
    }
}

impl Default for U32Set {
    fn default() -> Self {
        Self::new()
    }
}

#[inline]
fn hash(v: u32) -> usize {
    (v.wrapping_mul(0x9e37_79b1)) as usize
}

#[inline]
fn occ_bit(occ: &[u64], i: usize) -> bool {
    occ[i >> 6] & (1u64 << (i & 63)) != 0
}

#[inline]
fn occ_set(occ: &mut [u64], i: usize, v: bool) {
    let mask = 1u64 << (i & 63);
    if v {
        occ[i >> 6] |= mask;
    } else {
        occ[i >> 6] &= !mask;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_contains() {
        let mut s = U32Set::with_capacity(4);
        assert!(s.insert(7));
        assert!(!s.insert(7));
        assert!(s.insert(0xffff_ffff));
        assert!(s.insert(0));
        assert!(s.contains(7));
        assert!(s.contains(0xffff_ffff));
        assert!(s.contains(0));
        assert!(!s.contains(8));
        assert_eq!(s.len(), 3);
    }

    #[test]
    fn sequential_keys_never_collide() {
        let mut s = U32Set::with_capacity(1024);
        for v in 0..10_000u32 {
            assert!(s.insert(v), "seq {v} should be new");
        }
        for v in 0..10_000u32 {
            assert!(s.contains(v), "seq {v} lost");
        }
    }

    #[test]
    fn rehash_preserves_all_keys() {
        let mut s = U32Set::new();
        let mut rng: u32 = 0x1234_5678;
        let mut values = Vec::new();
        for _ in 0..50_000 {
            rng = rng.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            values.push(rng);
        }
        for &v in &values {
            s.insert(v);
        }
        for &v in &values {
            assert!(s.contains(v), "value {v} lost after rehash");
        }
    }

    #[test]
    fn duplicates_are_rejected() {
        let mut s = U32Set::with_capacity(8);
        let mut seen = 0;
        for _ in 0..20_000 {
            let v = (seen % 1000) as u32;
            if s.insert(v) {
                seen += 1;
            }
        }
        assert_eq!(seen, 1000);
    }
}
