#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

#[cfg(target_arch = "x86_64")]
fn avx2_available() -> bool {
    use core::arch::x86_64::{__cpuid, _xgetbv};
    let info = __cpuid(1);
    let osxsave = info.ecx & (1 << 27) != 0;
    let avx = info.ecx & (1 << 28) != 0;
    if !osxsave || !avx {
        return false;
    }
    // SAFETY: reading XCR0 via xgetbv is always valid on x86_64.
    let xcr0 = unsafe { _xgetbv(0) };
    if xcr0 & 0x6 != 0x6 {
        return false;
    }
    let info7 = __cpuid(7);
    info7.ebx & (1 << 5) != 0
}

pub fn xor_into(dst: &mut [u32], src: &[u32]) {
    debug_assert_eq!(dst.len(), src.len());
    #[cfg(target_arch = "x86_64")]
    {
        if avx2_available() {
            unsafe { xor_avx2(dst, src) }
        } else {
            unsafe { xor_sse2(dst, src) }
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        unsafe { xor_neon(dst, src) }
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        xor_scalar(dst, src);
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn xor_avx2(dst: &mut [u32], src: &[u32]) {
    let (d, s, n) = (dst.as_mut_ptr(), src.as_ptr(), dst.len());
    let mut i = 0;
    while i + 8 <= n {
        // SAFETY: `i` is bounds-checked against `n`, both slices are valid
        // for `n` elements, and avx2 is guaranteed by the caller's runtime
        // check before invoking this function.
        unsafe {
            let a = _mm256_loadu_si256(d.add(i) as *const __m256i);
            let b = _mm256_loadu_si256(s.add(i) as *const __m256i);
            _mm256_storeu_si256(d.add(i) as *mut __m256i, _mm256_xor_si256(a, b));
        }
        i += 8;
    }
    while i < n {
        // SAFETY: as above, bounds-checked raw writes.
        unsafe {
            *d.add(i) ^= *s.add(i);
        }
        i += 1;
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn xor_sse2(dst: &mut [u32], src: &[u32]) {
    let (d, s, n) = (dst.as_mut_ptr(), src.as_ptr(), dst.len());
    let mut i = 0;
    while i + 4 <= n {
        // SAFETY: `i` is bounds-checked against `n`; both slices are valid
        // for `n` elements; sse2 is always available on x86_64.
        unsafe {
            let a = _mm_loadu_si128(d.add(i) as *const __m128i);
            let b = _mm_loadu_si128(s.add(i) as *const __m128i);
            _mm_storeu_si128(d.add(i) as *mut __m128i, _mm_xor_si128(a, b));
        }
        i += 4;
    }
    while i < n {
        // SAFETY: bounds-checked raw writes.
        unsafe {
            *d.add(i) ^= *s.add(i);
        }
        i += 1;
    }
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn xor_neon(dst: &mut [u32], src: &[u32]) {
    use core::arch::aarch64::*;
    let (d, s, n) = (dst.as_mut_ptr(), src.as_ptr(), dst.len());
    let mut i = 0;
    while i + 4 <= n {
        // SAFETY: `i` is bounds-checked against `n`; both slices are valid
        // for `n` elements; neon is always available on aarch64.
        unsafe {
            let a = vld1q_u32(d.add(i));
            let b = vld1q_u32(s.add(i));
            vst1q_u32(d.add(i), veorq_u32(a, b));
        }
        i += 4;
    }
    while i < n {
        // SAFETY: bounds-checked raw writes.
        unsafe {
            *d.add(i) ^= *s.add(i);
        }
        i += 1;
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn xor_scalar(dst: &mut [u32], src: &[u32]) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d ^= *s;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn reference(dst: &mut [u32], src: &[u32]) {
        for (d, s) in dst.iter_mut().zip(src) {
            *d ^= *s;
        }
    }

    #[test]
    fn matches_reference_for_various_lengths() {
        for &n in &[0usize, 1, 3, 4, 5, 7, 8, 9, 15, 16, 17, 63, 64, 65, 1025] {
            let mut dst: Vec<u32> = (0..n as u32).collect();
            let src: Vec<u32> = (0..n as u32).map(|i| i.wrapping_mul(0x9e3779b1)).collect();
            let mut expected = dst.clone();
            reference(&mut expected, &src);
            xor_into(&mut dst, &src);
            assert_eq!(dst, expected, "length {n}");
        }
    }

    #[test]
    fn avx2_detection_is_self_consistent() {
        #[cfg(target_arch = "x86_64")]
        {
            let _ = avx2_available();
        }
    }
}
