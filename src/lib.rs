#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_op_in_unsafe_fn)]
extern crate alloc;

pub mod bytes;
pub mod capacity;
pub mod container;
pub mod crypto;
pub mod dlog;
pub mod error;
pub mod fountain;
pub mod frame;
pub mod prng;
pub mod session;
pub mod set;
pub mod simd;
pub mod soliton;

pub use capacity::{
    block_length, fits_in_one_stream, minimum_frame_bytes, smallest_sufficient_frame_size,
    source_block_count, MAX_SOURCE_BLOCKS,
};
pub use container::{
    is_precompressed_type, pack_file, safe_file_name, unpack_file, verify_file, Compression,
    OpticalFile, PackedOpticalFile, FILE_HEADER_LEN,
};
#[cfg(feature = "encryption")]
pub use container::{
    pack_file_encrypted, pack_file_encrypted_with_password, unpack_file_with_key,
    unpack_file_with_password,
};
pub use dlog::dlog;
pub use error::{Error, Result};
pub use fountain::{frame_indices, LtDecoder, LtEncoder};
pub use frame::{
    checksum32, fnv1a, frame_checksum, pack_frame, parse_frame, stream_identity, FrameHeader,
    StreamIdentity, HEADER_LEN, MAGIC0, MAGIC1, MAX_FILE_BYTES, MAX_STREAM_BYTES,
};
pub use prng::{frame_seed, SplitMix32};
pub use session::{Frame as SessionFrame, Receiver, Sender};
pub use soliton::{soliton_cdf, SOLITON_C, SOLITON_DELTA};
