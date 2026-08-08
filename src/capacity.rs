use crate::frame::HEADER_LEN;

pub const MAX_SOURCE_BLOCKS: usize = 0xffff;

#[inline]
pub fn block_length(frame_bytes: usize) -> Option<usize> {
    frame_bytes
        .checked_sub(HEADER_LEN)
        .filter(|block_len| *block_len > 0 && *block_len <= u16::MAX as usize)
}

#[inline]
pub fn source_block_count(payload_bytes: usize, frame_bytes: usize) -> Option<usize> {
    let block_len = block_length(frame_bytes)?;
    Some(payload_bytes.div_ceil(block_len))
}

#[inline]
pub fn fits_in_one_stream(payload_bytes: usize, frame_bytes: usize) -> bool {
    source_block_count(payload_bytes, frame_bytes)
        .is_some_and(|blocks| blocks > 0 && blocks <= MAX_SOURCE_BLOCKS)
}

#[inline]
pub fn minimum_frame_bytes(payload_bytes: usize) -> usize {
    payload_bytes
        .div_ceil(MAX_SOURCE_BLOCKS)
        .max(1)
        .saturating_add(HEADER_LEN)
}

pub fn smallest_sufficient_frame_size(payload_bytes: usize, options: &[usize]) -> Option<usize> {
    let minimum = minimum_frame_bytes(payload_bytes);
    options
        .iter()
        .copied()
        .filter(|&v| v >= minimum && block_length(v).is_some())
        .min()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_frame_sizes_are_rejected_without_panicking() {
        assert_eq!(block_length(0), None);
        assert_eq!(block_length(HEADER_LEN), None);
        assert_eq!(block_length(HEADER_LEN + 1), Some(1));
        assert_eq!(source_block_count(1, HEADER_LEN), None);
        assert!(!fits_in_one_stream(1, HEADER_LEN));
        assert!(!fits_in_one_stream(0, HEADER_LEN + 1));
    }

    #[test]
    fn frame_selection_excludes_unrepresentable_block_lengths() {
        let too_large = HEADER_LEN + u16::MAX as usize + 1;
        assert_eq!(
            smallest_sufficient_frame_size(1024, &[too_large, HEADER_LEN + 100]),
            Some(HEADER_LEN + 100)
        );
    }
}
