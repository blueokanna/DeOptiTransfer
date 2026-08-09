//! The robust-soliton degree distribution and [`DegreeCdf`], a two-level
//! quantized sampler whose bracketing invariant yields the same result as a
//! full binary search.

use alloc::vec;
use alloc::vec::Vec;

use crate::dlog::dlog;

pub const SOLITON_C: f64 = 0.1;
pub const SOLITON_DELTA: f64 = 0.5;

const QUANT: usize = 1024;

pub fn soliton_cdf(k: usize) -> Vec<f64> {
    let mut cdf = vec![0.0; k];
    if k == 0 {
        return cdf;
    }
    if k == 1 {
        cdf[0] = 1.0;
        return cdf;
    }
    let r = (SOLITON_C * dlog(k as f64 / SOLITON_DELTA) * libm::sqrt(k as f64)).max(1.0);
    let spike = (libm::ceil(k as f64 / r)).min(k as f64) as usize;
    let mut total = 0.0;
    for d in 1..=k {
        let rho = if d == 1 {
            1.0 / (k as f64)
        } else {
            1.0 / ((d * (d - 1)) as f64)
        };
        let mut tau = 0.0;
        if d < spike {
            tau = r / ((d * k) as f64);
        } else if d == spike {
            tau = (r * dlog(r / SOLITON_DELTA).max(0.0)) / (k as f64);
        }
        total += rho + tau;
        cdf[d - 1] = total;
    }
    for x in cdf.iter_mut() {
        *x /= total;
    }
    cdf[k - 1] = 1.0;
    cdf
}

/// The robust-soliton CDF with a two-level quantized sampler.
///
/// For finite `u` in `[0, 1)`, the quantized endpoints bracket the global
/// lower bound, so `sample` returns the same degree as [`degree_binary`].
/// Boundary and large deterministic sample sets are covered by tests.
pub struct DegreeCdf {
    cdf: Vec<f64>,
    quant: Vec<u32>,
}

impl DegreeCdf {
    pub fn new(k: usize) -> Self {
        let cdf = soliton_cdf(k);
        let mut quant = vec![0u32; QUANT + 1];
        if cdf.is_empty() {
            return Self { cdf, quant };
        }
        for (i, q) in quant.iter_mut().enumerate() {
            *q = lower_bound(&cdf, (i as f64) / (QUANT as f64)) as u32;
        }
        Self { cdf, quant }
    }

    #[inline]
    pub fn k(&self) -> usize {
        self.cdf.len()
    }

    #[inline]
    pub fn cdf(&self) -> &[f64] {
        &self.cdf
    }

    #[inline]
    pub fn sample(&self, u: f64) -> usize {
        if self.cdf.is_empty() {
            return 0;
        }
        if u.is_nan() || u <= 0.0 {
            return 1;
        }
        if u >= 1.0 {
            return self.cdf.len();
        }
        let i = (u * QUANT as f64) as usize;
        let mut lo = self.quant[i] as usize;
        let mut hi = self.quant[i + 1] as usize;
        while lo < hi {
            let mid = (lo + hi) >> 1;
            if self.cdf[mid] >= u {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        lo + 1
    }
}

#[inline]
fn lower_bound(cdf: &[f64], x: f64) -> usize {
    let (mut lo, mut hi) = (0usize, cdf.len() - 1);
    while lo < hi {
        let mid = (lo + hi) >> 1;
        if cdf[mid] >= x {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    lo
}

pub fn degree_binary(cdf: &[f64], u: f64) -> usize {
    if cdf.is_empty() {
        return 0;
    }
    if u.is_nan() || u <= 0.0 {
        return 1;
    }
    if u >= 1.0 {
        return cdf.len();
    }
    (lower_bound(cdf, u) + 1).min(cdf.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prng::SplitMix32;

    #[test]
    fn quantized_sampling_matches_binary_search_exactly() {
        for &k in &[1usize, 2, 17, 179, 716, 5000, 11440, 65535] {
            let dc = DegreeCdf::new(k);
            let cdf = dc.cdf();
            for i in 0..(1 << 20) {
                let u = (i as f64) / (1 << 20) as f64;
                assert_eq!(dc.sample(u), degree_binary(cdf, u), "k={k} u={u}");
            }
            let mut rng = SplitMix32::new(k as u32);
            for _ in 0..100_000 {
                let u = (rng.next_u32() as f64) / 4_294_967_296.0;
                assert_eq!(dc.sample(u), degree_binary(cdf, u), "k={k} u={u}");
            }
        }
    }

    #[test]
    fn quantiles_are_monotone() {
        for &k in &[17usize, 716, 65535] {
            let dc = DegreeCdf::new(k);
            for i in 0..QUANT {
                assert!(dc.quant[i] <= dc.quant[i + 1], "k={k} quant[{i}]");
            }
        }
    }

    #[test]
    fn public_sampling_boundaries_are_total() {
        let empty = DegreeCdf::new(0);
        assert_eq!(empty.sample(0.5), 0);
        assert_eq!(degree_binary(&[], 0.5), 0);

        let dc = DegreeCdf::new(17);
        for u in [f64::NAN, f64::NEG_INFINITY, -1.0, 0.0] {
            assert_eq!(dc.sample(u), 1);
            assert_eq!(degree_binary(dc.cdf(), u), 1);
        }
        for u in [1.0, 2.0, f64::INFINITY] {
            assert_eq!(dc.sample(u), 17);
            assert_eq!(degree_binary(dc.cdf(), u), 17);
        }
    }
}
