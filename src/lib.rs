//! # deopti-transfer
//!
//! A `no_std + alloc` LT fountain-code core for one-way data transfer. A
//! protocol-v3 sender emits self-contained frames and the receiver peels
//! verified equations until the original byte stream is complete.
//!
//! The default causal first phase is the invertible transform
//! `y[0] = x[0]`, `y[i] = x[i-1] XOR x[i]`; a deterministic robust-soliton
//! tail supplies repairs. Completion under loss is probabilistic and no fixed
//! overhead is guaranteed. The 32-bit frame and stream tags detect accidental
//! corruption but are not message authentication codes.
//!
//! Feature `encryption` adds XChaCha20-Poly1305 containers, the JRC
//! designated-judge recovery construction, and the JRP composition interface.
//! JRP becomes a proof system only when the caller supplies a sound,
//! zero-knowledge [`jrp::RelationProofSystem`] backend.
//!
//! ## Quick start
//!
//! ```
//! use deopti_transfer::container::{pack_file, unpack_file};
//! use deopti_transfer::session::{Receiver, Sender};
//!
//! let packed = pack_file("notes.txt", "text/plain", b"hello over light").unwrap();
//! let mut sender = Sender::try_from_packed(&packed, 1465, 0x0c_d1).unwrap();
//! let mut receiver = Receiver::new();
//! let mut recovered = None;
//! for _ in 0..sender.k() as usize * 4 {
//!     let frame = sender.try_next_frame().unwrap();
//!     if let Some(container) = receiver.try_push(&frame.to_bytes()).unwrap() {
//!         recovered = Some(container);
//!         break;
//!     }
//! }
//! let file = unpack_file(&recovered.expect("stream completed")).unwrap();
//! assert_eq!(file.bytes, b"hello over light");
//! ```
//!
//! ## Modules
//!
//! | Module | Purpose |
//! | --- | --- |
//! | [`frame`] | Protocol v3 frame format: 25-byte header, BLAKE3 integrity tags, stream identity |
//! | [`fountain`] | The codec: causal weave / systematic / pure-RSD `LtEncoder` / `LtDecoder` |
//! | [`session`] | High-level middleware: `Sender` emits frames, `Receiver` reconstructs the stream |
//! | [`container`] | DCF3 file container: name + type + bytes + digest, gzip, optional AEAD |
//! | [`crypto`] | Argon2id keys, XChaCha20-Poly1305 AEAD, nonces |
//! | [`jrc`] *(encryption)* | Judge-recoverable commitment: hiding commitment + judge-only recovery channel |
//! | [`jrp`] *(encryption)* | Composition with an application-supplied relation-proof backend |
//! | [`capacity`] | Frame-capacity arithmetic (`k` fits a `u16`?) |
//! | [`soliton`] | Robust-soliton degree distribution and the quantized `DegreeCdf` |
//! | [`prng`] | Deterministic wire-format PRNG (`SplitMix32`, `frame_seed`) |
//! | [`set`] | Zero-dependency open-addressing `U32Set` (collision-free for sequential keys) |
//! | [`simd`] | Runtime-dispatched SIMD XOR engine |
//! | [`dlog`] | Deterministic natural log (wire-format pinned) |
//! | [`error`] | `Error` / `Result` |
//!
//! ## Features
//!
//! - `std` (default): gzip container compression via `flate2`.
//! - `encryption`: Argon2id, XChaCha20-Poly1305, X25519 JRC/JRP support,
//!   operating-system randomness, and key zeroization.
//!
//! Build a pure `no_std + alloc` library with
//! `cargo build --release --no-default-features`, and add authenticated
//! encryption with `--features encryption`.
//!
//! ## License
//!
//! Apache-2.0. See the repository `LICENSE`.

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
#[cfg(feature = "encryption")]
pub mod jrc;
#[cfg(feature = "encryption")]
pub mod jrp;
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
    pack_file_encrypted, pack_file_encrypted_with_password, pack_file_jrc, unpack_file_jrc,
    unpack_file_with_key, unpack_file_with_password, JrcPackedFile,
};
pub use error::{Error, Result};
pub use fountain::{frame_indices, LtDecoder, LtEncoder};
pub use frame::{
    checksum32, fnv1a, frame_checksum, pack_frame, parse_frame, stream_identity, FrameHeader,
    StreamIdentity, HEADER_LEN, MAGIC0, MAGIC1, MAX_FILE_BYTES, MAX_STREAM_BYTES,
};
#[cfg(feature = "encryption")]
pub use jrc::{
    commit, commit_with_prover_opening, envelope_len, judge_recover, keygen, verify_ext,
    JrcCommitment, JrcProverOpening, JudgeKeyPair, JudgePublicKey, JudgeSecretKey, COMMIT_LEN,
    ENVELOPE_OVERHEAD, MAX_MESSAGE_LEN,
};
#[cfg(feature = "encryption")]
pub use jrp::{
    JrpProof, JrpPublicInput, RelationProofSystem, MAX_RELATION_PROOF_LEN, PROOF_OVERHEAD,
};
pub use prng::{frame_seed, SplitMix32};
pub use session::{Frame as SessionFrame, Receiver, ReceiverLimits, Sender};
pub use soliton::{soliton_cdf, SOLITON_C, SOLITON_DELTA};
