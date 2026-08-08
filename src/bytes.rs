//! Internal `u32 ↔ u8` reinterpret helpers.

#[inline]
pub(crate) fn words_as_bytes(words: &[u32]) -> &[u8] {
    unsafe { core::slice::from_raw_parts(words.as_ptr() as *const u8, words.len() * 4) }
}

#[inline]
pub(crate) fn words_as_bytes_mut(words: &mut [u32]) -> &mut [u8] {
    unsafe { core::slice::from_raw_parts_mut(words.as_mut_ptr() as *mut u8, words.len() * 4) }
}
