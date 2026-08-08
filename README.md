# deopti-transfer

The no_std LT Fountain Code Core for Unidirectional Optical Data Transfer.

A bit-exact, zero-handshake engine that transmits files over a one-way visual
channel — a screen streaming animated QR codes to a camera. No back-channel,
no retransmission: the sender emits an endless fountain of coded frames and
the receiver peels the file out of any ~K·1.15 distinct frames, in any order.
Dropped frames cost time, never correctness.

Protocol version **2** (frame magic `D1 0E`).

## Hybrid systematic-robust-soliton distribution

The session layer defaults to systematic (`Sender::new`); the low-level
codec defaults to pure RSD (`LtEncoder::new`, wire-compatible with the
original sampling), with `LtEncoder::new_systematic` / `LtDecoder::new_systematic`
selecting the hybrid. The frame header's flags byte carries the mode, so the
receiver adapts automatically (the protocol stays self-describing).

Measured frames-needed-to-complete (K=139, deterministic per-seq drop mask,
identical coded frames available to all decoders):

| Loss rate | Systematic (1 lap) | Pure RSD |
| --- | --- | --- |
| 0% | **1.000 ×K** | 1.317 ×K |
| 10% | 1.403 ×K | 1.173 ×K |
| 30% | 1.554 ×K | 1.317 ×K |

At zero loss the systematic phase completes in **exactly K frames** (provable
and tested: `systematic_phase_completes_in_exactly_k_frames`) — 24% fewer
frames than pure RSD. Under loss, the residual sub-problem exhibits the
**systematic puncturing effect** known from systematic LT codes: frames whose
blocks are already solved carry no new information, so the tail decodes less
efficiently. The measured crossover sits below 10% loss. Use systematic for
a well-positioned low-loss camera link; use pure RSD for lossy channels. A
receiver that locks on mid-stream (after the systematic phase) still decodes
from the coded tail alone (tested).

A multi-lap variant (each source block emitted twice) was implemented and
**measured and rejected**: at 10% loss it needed 2.14×K frames. The residual
set shrinks to p²·K, but the LT tail then starves for degree-1 frames against
a tiny target set (~200 coded frames to hit 1–2 residual blocks), which is
worse than both alternatives. The negative result is reported here rather
than shipped.

## Authenticated encryption (anti-co-reception)

The optical channel is a public broadcast: **any camera pointed at the screen
receives the same frames**. With the `encryption` feature, containers are
encrypted so a co-receiver or mid-path observer sees only ciphertext:

- **AEAD**: XChaCha20-Poly1305 (RustCrypto, no_std), 24-byte nonce, 16-byte
  tag. The header, name, type and digest are **authenticated as associated
  data** — tampering with any field fails the tag before decryption.
- **Keys**: `EncryptionKey` (32 bytes, redacted `Debug`), derived from a
  password via `blake3::derive_key` (HKDF-based KDF), or supplied directly.
  Strength is the password's responsibility, as usual.
- **Nonces**: 24 bytes, unique per encryption under a key. `random_nonce()`
  (std builds) uses the OS RNG; no_std applications supply their own (e.g.,
  from an embedded TRNG).
- **Layout**: DCF3 container, 73-byte header, `flags` bit1 = encrypted; the
  transmitted payload is ciphertext+tag. `unpack_file_with_key` verifies the
  tag, decrypts, then re-checks the BLAKE3 digest of the recovered plaintext.
- An encrypted container unpacked without a key, with the wrong key, or with
  a single flipped byte is rejected (tested).

## Performance & data-structure design

- **SIMD XOR engine** (`simd`): runtime-dispatched AVX2 (via `__cpuid` +
  `_xgetbv` XCR0 check), SSE2, NEON, scalar — no_std through `core::arch`.
  Measured 22.2 GiB/s on a 4 MiB buffer.
- **Flat word arena** (`LtDecoder`): all frame words live in one `Vec<u32>`
  carved by index (stable across growth) — **no per-frame heap allocation**;
  disjoint ranges are XORed via `split_at_mut`.
- **Two-level quantized degree sampling** (`DegreeCdf`): a 1024-entry
  quantile table narrows the inverse-CDF search to a small cache-warm window;
  **exactly equal** to binary search (proven over a 2^20 grid + 100k random
  samples per K).
- **Bijective multiplicative-hash dedup** (`U32Set`): open addressing where
  `v·0x9E3779B1 mod 2^t` is a bijection — sequential seq numbers never
  collide; packed occupancy bits; amortized rehash at 0.7 load.

### Benchmarks

`criterion 0.8`, Intel Core i7-11850H @ 2.50 GHz, 32 GB; `BLOCK_LEN=2933`;
reproduce with `cargo bench`.

| Group | Case | Median | Throughput |
| --- | --- | --- | --- |
| xor | dispatched (AVX2) | 175.8 µs | 22.22 GiB/s |
| xor | scalar reference | 216.5 µs | 18.05 GiB/s |
| encode | stream, 1 MiB | 3.766 ms | 360.3 MiB/s |
| encode | stream, 32 MiB | 312.0 ms | 136.8 MiB/s |
| decode | peel, 1 MiB | 1.240 ms | 806.3 MiB/s |
| decode | peel, 32 MiB | 67.45 ms | 474.4 MiB/s |

Decode runs at **3.8–6.5 Gbps**, encode at **1.1–2.9 Gbps** — both above the
1 Gbps target. Encode falls off with payload size because random block access
from a multi-MB table is memory-latency-bound (not compute); decode reads the
same table cache-warm. The optical channel itself consumes these frames at
~0.1–0.2 MB/s, three orders of magnitude below the codec.

## Security model

Every field from the optical channel is validated before use: stream headers
must be consistent (`k == ceil(total/block)`, `total ≤ 64 MiB`), pending
frame memory is capped at 4× payload, gzip inflate is hard-bounded, and
authenticated encryption covers the container. The per-frame FNV-1a is a
corruption check, not authentication — with `encryption`, integrity comes
from the AEAD tag.

## no_std

`--no-default-features` builds pure `no_std + alloc` (verified). Features:
`std` (gzip via flate2), `encryption` (XChaCha20-Poly1305 + `getrandom`).
Dependencies: `rustbinary`, `serde` (derive), `blake3`, `libm`,
`chacha20poly1305` + `getrandom` (encryption only), `flate2` (std only).

## Usage

```toml
[dependencies]
deopti-transfer = { version = "0.1", features = ["encryption"] }
```

```rust
use deopti_transfer::container::{pack_file, unpack_file};
use deopti_transfer::crypto::EncryptionKey;
use deopti_transfer::session::{Receiver, Sender};

let key = EncryptionKey::from_password("correct horse battery staple");
let packed = pack_file("notes.txt", "text/plain", b"...")?;

let mut sender = Sender::from_packed(&packed, 1465, 0x0c_d1);
let mut receiver = Receiver::new();
let wire = sender.next_frame().to_bytes();
if let Some(container) = receiver.push(&wire) {
    let file = unpack_file(&container)?;
}
```

## Wire-format guarantees

The derivation chain — `dlog`, the robust-soliton CDF, `frame_seed`,
`SplitMix32`, `frame_indices` — is pinned by golden-vector tests, including an
exhaustive FNV-1a fingerprint of `dlog`. `rustbinary`'s fixed-width
little-endian profile reproduces the 21-byte frame header and 73-byte
container header byte-for-byte. The systematic stream has its own pinned
fingerprints.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
