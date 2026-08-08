use crate::frame::HEADER_LEN;

pub const MAX_SOURCE_BLOCKS: usize = 0xffff;

#[inline]
pub fn block_length(frame_bytes: usize) -> usize {
    frame_bytes - HEADER_LEN
}

#[inline]
pub fn source_block_count(payload_bytes: usize, frame_bytes: usize) -> usize {
    payload_bytes.div_ceil(block_length(frame_bytes))
}

#[inline]
pub fn fits_in_one_stream(payload_bytes: usize, frame_bytes: usize) -> bool {
    source_block_count(payload_bytes, frame_bytes) <= MAX_SOURCE_BLOCKS
}

#[inline]
pub fn minimum_frame_bytes(payload_bytes: usize) -> usize {
    payload_bytes.div_ceil(MAX_SOURCE_BLOCKS) + HEADER_LEN
}

pub fn smallest_sufficient_frame_size(payload_bytes: usize, options: &[usize]) -> Option<usize> {
    let minimum = minimum_frame_bytes(payload_bytes);
    options.iter().copied().filter(|&v| v >= minimum).min()
}
