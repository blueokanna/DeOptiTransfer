//! Deterministic natural logarithm, bit-exact with the reference
//! implementation and pinned by golden-vector tests. Wire format: sender and
//! receiver must derive identical degree distributions.

use core::f64::consts::LN_2;

pub fn dlog(x: f64) -> f64 {
    if x.is_nan() || x < 0.0 {
        return f64::NAN;
    }
    if x == 0.0 {
        return f64::NEG_INFINITY;
    }
    if x == f64::INFINITY {
        return f64::INFINITY;
    }
    let mut e: i32 = 0;
    let mut m = x;
    while m >= 1.5 {
        m /= 2.0;
        e += 1;
    }
    while m < 0.75 {
        m *= 2.0;
        e -= 1;
    }
    let z = (m - 1.0) / (m + 1.0);
    let z2 = z * z;
    let mut term = z;
    let mut sum = 0.0;
    let mut n = 1;
    while n <= 21 {
        sum += term / (n as f64);
        term *= z2;
        n += 2;
    }
    (e as f64) * LN_2 + 2.0 * sum
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_positive_and_non_finite_inputs_are_total() {
        assert_eq!(dlog(0.0), f64::NEG_INFINITY);
        assert_eq!(dlog(f64::INFINITY), f64::INFINITY);
        assert!(dlog(-1.0).is_nan());
        assert!(dlog(f64::NAN).is_nan());
    }
}
