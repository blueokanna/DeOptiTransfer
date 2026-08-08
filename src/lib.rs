//! # deopti-transfer
//!
//! A `no_std + alloc` **LT fountain-code core** for **unidirectional optical
//! data transfer**: move a file between two devices using only a screen and a
//! camera — no network path, no pairing, no retransmission. The sender emits
//! an endless stream of self-contained frames; the receiver reconstructs the
//! payload from *any* ~K·1.15 distinct frames, in any order. **Dropped frames
//! cost time, never correctness.**
//!
//! The current wire protocol is **version 3** (frame magic `D1 0F`).
//!
//! ## What makes this crate novel
//!
//! - **The causal weave** ([`session::Sender`], default mode): the first K
//!   frames are a *causal* encoding of the source blocks,
//!   `y[0] = x[0]`, `y[i] = x[i-1] XOR x[i]` — an **invertible
//!   lower-bidiagonal matrix**. Receiving the first K frames, in any order,
//!   reconstructs the payload in exactly K frames; a missing frame cuts the
//!   chain into *components* that peeling recovers cheaply. An endless
//!   deterministic robust-soliton repair tail follows, so receivers that
//!   start mid-stream still decode.
//! - **Per-frame integrity**: every 25-byte frame header carries two
//!   BLAKE3-derived 32-bit tags — `frame_tag` (verified on arrival, so a
//!   damaged frame becomes an erasure instead of poisoning the decoder) and
//!   `stream_tag` (verified after reconstruction).
//! - **Authenticated encryption** (`encryption` feature): container-level
//!   XChaCha20-Poly1305 with Argon2id key derivation and zeroized keys — a
//!   co-receiving camera sees only ciphertext.
//! - **Extreme throughput**: SIMD XOR engine (AVX2/SSE2/NEON/scalar, no_std
//!   via `core::arch`), flat word arena (no per-frame heap allocation),
//!   two-level quantized degree sampling, and a bijective multiplicative-hash
//!   dedup set. Measured decode throughput is **3.9–6.6 Gbps** on the
//!   reference machine (see the module docs and `README.md`).
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
//! - `encryption`: container AEAD via `argon2` + `chacha20poly1305` +
//!   `getrandom` + `zeroize`.
//!
//! Build a pure `no_std + alloc` library with
//! `cargo build --release --no-default-features`, and add authenticated
//! encryption with `--features encryption`.
//!
//! ## License
//!
//! Apache-2.0. See the repository `LICENSE` and `NOTICE`.

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
pub use error::{Error, Result};
pub use fountain::{frame_indices, LtDecoder, LtEncoder};
pub use frame::{
    checksum32, fnv1a, frame_checksum, pack_frame, parse_frame, stream_identity, FrameHeader,
    StreamIdentity, HEADER_LEN, MAGIC0, MAGIC1, MAX_FILE_BYTES, MAX_STREAM_BYTES,
};
pub use prng::{frame_seed, SplitMix32};
pub use session::{Frame as SessionFrame, Receiver, Sender};
pub use soliton::{soliton_cdf, SOLITON_C, SOLITON_DELTA};
