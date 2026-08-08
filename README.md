# deopti-transfer

[中文](README_CN.md)

> The `no_std` LT fountain-code core for unidirectional optical data transfer.
> A bit-exact, zero-handshake engine that moves a file between two devices
> using nothing but a screen and a camera — no network path, no pairing, no
> retransmission.

`deopti-transfer` is a `no_std + alloc` fountain-code core for one-way optical
file transfer. A sender continuously emits self-contained frames; a receiver
can reconstruct the stream without acknowledgements or retransmission control.
Dropped frames cost time, never correctness.

The current wire protocol is **version 3** (frame magic `D1 0F`). Version 2
frames are intentionally rejected because they lack a per-frame integrity tag
and can poison the decoder with a corrupted equation.

---

## Highlights

- **Causal weave (default sender)** — an invertible lower-bidiagonal first
  phase: `K` frames reconstruct the payload in exactly `K` frames, in any
  order, and a missing frame splits the chain into components that peeling
  recovers cheaply. Followed by an endless deterministic robust-soliton
  repair tail, so a receiver that starts late still decodes.
- **Per-frame integrity** — every 25-byte frame header carries two
  BLAKE3-derived 32-bit tags (`frame_tag` verified on arrival, `stream_tag`
  verified after reconstruction). Damaged frames become erasures, never
  poison.
- **Authenticated encryption (optional)** — container-level
  XChaCha20-Poly1305 with an Argon2id key derivation and zeroized keys, so a
  co-receiving camera sees only ciphertext.
- **Extreme throughput** — SIMD XOR engine (AVX2/SSE2/NEON/scalar runtime
  dispatch, no_std via `core::arch`), flat word arena (no per-frame heap
  allocation), two-level quantized degree sampling, bijective multiplicative
  hash dedup. Decode runs at **3.8–6.6 Gbps** on the reference machine.

---

## Protocol v3 — frames, tags, identity

Every QR frame is fully self-describing: no handshake, the receiver locks onto
a stream mid-flight, and a new session id simply starts a fresh transfer.

**25-byte little-endian header:**

```text
 0  2 bytes  magic        D1 0F (protocol v3)
 2  u8       flags        bit0 direct-systematic, bit1 causal
 3  u16      session_id   random per sender start
 5  u32      seq          drives the fountain / weave
 9  u16      k            source block count
11  u16      block_len    payload bytes per frame
13  u32      total_len    protected container length
17  u32      stream_tag   BLAKE3-derived tag of the whole container
21  u32      frame_tag    BLAKE3-derived tag of this header + block
```

The serialized header is produced by `rustbinary`'s fixed-width little-endian
legacy profile, so the byte layout is pinned by golden-vector tests.

**`frame_tag`** = first 4 bytes of `BLAKE3(flags ‖ session ‖ seq ‖ k ‖
block_len ‖ total_len ‖ stream_tag ‖ block)`. `parse_frame` verifies it
before a frame ever reaches the decoder: a damaged frame is rejected as an
erasure and the same sequence number can be admitted later.

**`stream_tag`** = first 4 bytes of `BLAKE3(container)`. It identifies the
complete transmitted container and is re-checked after reconstruction
(`checksum32`). Both tags detect accidental optical corruption; they are not
message authentication codes. Use the `encryption` feature against active
tampering.

**Stream identity** — a receiver locks to the first valid
`StreamIdentity { flags, session_id, k, block_len, total_len, stream_tag }`.
Frames from any other stream return `Error::StreamConflict` without discarding
current progress; call `Receiver::reset` to select a different stream
deliberately.

**Limits** — `MAX_FILE_BYTES = 64 MiB`; `MAX_STREAM_BYTES =
64 MiB + 2·0xFFFF + 128` (container header and metadata headroom).
Decoder payload storage is bounded to four times the source-block arena, and
capacity is checked before the sequence deduplication set can grow.

---

## The causal weave construction

The default sender (`Sender::new`) emits a **causal** first phase. For source
blocks `x[0]..x[K-1]`:

```text
y[0] = x[0]
y[i] = x[i-1] XOR x[i]     for 1 <= i < K
```

This is an **invertible lower-bidiagonal encoding matrix**. Receiving the
first `K` frames — in any order — reconstructs the payload in exactly `K`
frames. A missing first-phase frame cuts the chain into **components** instead
of leaving an isolated missing source block. When a later repair equation
solves one member of a component, peeling propagates through every received
edge in that component.

After the first phase, the sender emits deterministic robust-soliton LT repair
equations indefinitely, so a receiver that starts mid-stream still completes.

The construction is pinned by golden vectors and tested in reverse frame
order, with isolated cuts, and under deterministic loss.

### Measured regression (K = 139, deterministic per-seq drop mask)

Frames admitted by the decoder, relative to K:

| Drop rate | Causal | Direct systematic | Pure RSD |
| --- | ---: | ---: | ---: |
| 0%  | **1.000 K** | **1.000 K** | 1.317 K |
| 10% | **1.043 K** | 1.403 K | 1.173 K |
| 30% | **1.554 K** | 1.554 K | 1.317 K |

These are deterministic regression measurements — not a general channel model
and not a claim of academic novelty. They are reproduced by
`systematic_reduces_frames_needed_under_loss`. Applications can explicitly
select direct systematic or pure RSD when their measured channel favors one
of those modes.

---

## Transmission modes

| Mode | `Sender` constructor | flags | First phase |
| --- | --- | --- | --- |
| Causal (default) | `Sender::new` / `try_new` | `FLAG_CAUSAL` | bidiagonal weave |
| Direct systematic | `Sender::new_systematic` / `try_new_systematic` | `FLAG_SYSTEMATIC` | source blocks verbatim |
| Pure RSD | `Sender::new_rsd` / `try_new_rsd` | 0 | robust-soliton LT |

The low-level codec mirrors these: `LtEncoder::new` / `new_systematic` /
`new_causal` and `LtDecoder::new` / `new_systematic` / `new_causal` (each with
`try_*` variants). The frame header's flags byte carries the mode, so the
receiver adapts automatically.

---

## Frame integrity & session isolation

- `Error::CorruptFrame` — a frame failed its BLAKE3 tag, or the recovered
  container failed its `stream_tag`. The frame is dropped as an erasure; the
  decoder stays intact.
- `Error::StreamConflict` — a frame from a different stream identity arrived.
  Current progress is preserved; `Receiver::reset` switches streams.
- `Error::SequenceExhausted` — the sender's `u32` sequence counter wrapped
  after `2^32` frames.
- `Receiver::try_push` returns `Result<Option<Vec<u8>>>`: `Ok(None)` while the
  stream is incomplete, `Ok(Some(container))` exactly once on completion
  (double delivery is prevented), and `Err` for the cases above.

---

## Authenticated encryption (anti-co-reception)

The optical channel is a public broadcast — **any camera pointed at the
screen receives the same frames**. With the `encryption` feature, containers
are encrypted so a co-receiver or mid-path observer sees only ciphertext.

- **AEAD** — XChaCha20-Poly1305 (RustCrypto, no_std), 24-byte nonce, 16-byte
  tag. The container header, name, type and digest are authenticated as
  associated data: tampering with any field fails the tag before decryption.
- **Key derivation** — `EncryptionKey::from_password(password, salt)` derives
  a 32-byte key with **Argon2id** (19 MiB, 2 iterations) and zeroizes it on
  drop (`zeroize`). The 24-byte nonce doubles as the Argon2 salt, so a fresh
  nonce yields a fresh key.
- **Nonces** — `random_nonce()` (std builds) uses the OS RNG; no_std
  applications supply their own (e.g., from an embedded TRNG). A nonce must be
  unique per encryption under the same key.
- **API** — `pack_file_encrypted` / `pack_file_encrypted_with_password`;
  `unpack_file_with_key` / `unpack_file_with_password`. An encrypted container
  unpacked without a key, with the wrong key, or with a single flipped byte
  is rejected (tested).

---

## Performance & data structures

- **SIMD XOR engine** (`simd::xor_into`) — runtime-dispatched AVX2 (checked
  via `__cpuid` + `_xgetbv` XCR0 state), SSE2, NEON, scalar fallback. no_std
  through `core::arch`.
- **Flat word arena** (`LtDecoder`) — all frame words live in one `Vec<u32>`
  carved by index; indices are stable across growth, so there is **no
  per-frame heap allocation**. Disjoint ranges are XORed via `split_at_mut`.
- **Two-level quantized degree sampling** (`DegreeCdf`) — a 1024-entry
  quantile table narrows the inverse-CDF search to a cache-warm window. The
  result is **exactly equal** to binary search (proven over a 2^20 grid plus
  100k random samples per K).
- **Bijective multiplicative-hash dedup** (`U32Set`) — open addressing where
  `v·0x9E3779B1 mod 2^t` is a bijection on the low bits, so consecutive
  sequence numbers never collide; packed occupancy bits; amortized rehash at
  0.7 load.

### Benchmarks

`criterion 0.8`, 100 samples, 3 s warm-up, `-O3` + `lto`; hardware
**Intel Core i7-11850H @ 2.50 GHz, 32 GB**. `BLOCK_LEN = 2933`. Reproduce with
`cargo bench`.

| Group | Case | Median time | Throughput |
| --- | --- | --- | --- |
| xor | dispatched (AVX2) | 203.7 µs | 19.18 GiB/s |
| xor | scalar reference | 193.7 µs | 20.16 GiB/s |
| degree_sample | quantized, K=357 | 10.46 µs | — |
| degree_sample | binary, K=357 | 29.73 µs | — |
| degree_sample | quantized, K=11440 | 10.62 µs | — |
| degree_sample | binary, K=11440 | 49.87 µs | — |
| dedup | u32_set_insert × 65536 | 292.9 µs | ~224 M inserts/s |
| encode | stream, 1 MiB | 3.718 ms | 364.9 MiB/s |
| encode | stream, 8 MiB | 56.92 ms | 187.8 MiB/s |
| encode | stream, 32 MiB | 314.9 ms | 135.6 MiB/s |
| decode | peel, 1 MiB | 1.212 ms | 825.1 MiB/s |
| decode | peel, 8 MiB | 11.76 ms | 680.2 MiB/s |
| decode | peel, 32 MiB | 65.89 ms | 485.7 MiB/s |

In bit terms (×8): **decode runs at 3.9–6.6 Gbps**, encode at 1.1–2.9 Gbps —
both above 1 Gbps on every measured size. Encode falls off with payload size
because sampling random blocks from a multi-MB table is memory-latency-bound
(not compute); decode reads the same table cache-warm. The optical channel
that consumes these frames runs at ~0.1–0.2 MB/s — three orders of magnitude
below the codec, which is therefore never the channel bottleneck.

---

## API reference

| Module | Public surface |
| --- | --- |
| `frame` | `FrameHeader`, `StreamIdentity`, `pack_frame`, `parse_frame`, `stream_identity`, `checksum32`, `frame_checksum`, `fnv1a`, `HEADER_LEN`, `MAGIC0/1`, `FLAG_SYSTEMATIC`, `FLAG_CAUSAL`, `MAX_FILE_BYTES`, `MAX_STREAM_BYTES` |
| `fountain` | `LtEncoder` (`new`/`new_systematic`/`new_causal` + `try_*`, `encode`, `encode_into`, `k`, `block_len`, `session_id`, `is_causal`, `is_systematic`, `sys_span`), `LtDecoder` (`new`/`new_systematic`/`new_causal` + `try_*`, `add_frame`, `assemble`, `is_complete`, `frames_new/dup/dropped`, `solved_count`), `frame_indices` |
| `session` | `Sender` (`new`/`new_systematic`/`new_rsd` + `try_*`, `from_packed`/`try_from_packed`, `try_next_frame`, `next_frame`, `k`, `session_id`, `is_causal`, `is_systematic`), `Frame` (`to_bytes`), `Receiver` (`new`, `reset`, `try_push`, `push`, `is_active`) |
| `container` | `pack_file`, `pack_file_encrypted`, `pack_file_encrypted_with_password`, `unpack_file`, `unpack_file_with_key`, `unpack_file_with_password`, `verify_file`, `safe_file_name`, `is_precompressed_type`, `Compression`, `PackedOpticalFile`, `OpticalFile`, `FILE_HEADER_LEN` |
| `crypto` *(encryption)* | `EncryptionKey` (`new`, `from_password`), `random_nonce`, `encrypt`, `decrypt`, `NONCE_LEN`, `TAG_LEN` |
| `capacity` | `block_length`, `source_block_count`, `fits_in_one_stream`, `minimum_frame_bytes`, `smallest_sufficient_frame_size`, `MAX_SOURCE_BLOCKS` |
| `soliton` | `soliton_cdf`, `DegreeCdf`, `degree_binary`, `SOLITON_C`, `SOLITON_DELTA` |
| `prng` | `SplitMix32`, `frame_seed` |
| `set` | `U32Set` |
| `simd` | `xor_into` |
| `dlog` | `dlog` |
| `error` | `Error`, `Result` |

---

## Quick start

```toml
[dependencies]
deopti-transfer = { version = "0.1", features = ["encryption"] }
```

### Plain transfer

```rust
use deopti_transfer::container::{pack_file, unpack_file};
use deopti_transfer::session::{Receiver, Sender};

let packed = pack_file("notes.txt", "text/plain", b"hello over light")?;

let mut sender = Sender::try_from_packed(&packed, 1465, 0x0c_d1)?; // causal
let mut receiver = Receiver::new();
let mut recovered = None;
for _ in 0..sender.k() as usize * 4 {
    let frame = sender.try_next_frame()?;
    if let Some(container) = receiver.try_push(&frame.to_bytes())? {
        recovered = Some(container);
        break;
    }
}
let file = unpack_file(&recovered.expect("stream completed"))?;
assert_eq!(file.bytes, b"hello over light");
```

### Encrypted transfer (anti-co-reception)

```rust
use deopti_transfer::container::unpack_file_with_password;
use deopti_transfer::crypto::random_nonce;

let nonce = random_nonce()?;
let packed = deopti_transfer::pack_file_encrypted_with_password(
    "secret.txt", "text/plain", b"top secret", b"correct horse battery staple", &nonce,
)?;
let file = unpack_file_with_password(&packed.container, b"correct horse battery staple")?;
assert_eq!(file.bytes, b"top secret");
```

For lossy or out-of-order channels, keep pushing frames — the decoder
completes whenever enough distinct frames have arrived.

---

## no_std, features, dependencies

```bash
# Pure no_std + alloc build (no gzip, no encryption)
cargo build --release --no-default-features

# + encryption (Argon2id + XChaCha20-Poly1305, all no_std)
cargo build --release --no-default-features --features encryption
```

| Feature | Adds | Enables |
| --- | --- | --- |
| `std` (default) | `flate2` | gzip container compression |
| `encryption` | `argon2`, `chacha20poly1305`, `getrandom`, `zeroize` | container AEAD |

Runtime dependencies are all no_std-capable: `rustbinary` (binary codec),
`serde` (derive), `blake3` (hashing), `libm` (no_std float math), plus the
optional `flate2` / `argon2` / `chacha20poly1305` / `getrandom` / `zeroize`.

---

## Correctness & safety

- **Golden vectors** (`tests/golden.rs`) pin the wire format: the frame
  header bytes, the RSD and systematic/causal encoded streams, an exhaustive
  FNV-1a fingerprint of `dlog`, and the quantized-sampling equivalence proof.
- **Round trips** (`tests/roundtrip.rs`) cover the fountain under loss and
  out-of-order delivery, the causal weave in reverse order and isolated cuts,
  encrypted containers (wrong key, tampering, missing key), and crafted
  header-amplification attacks.
- Every field from the optical channel is validated before use; the only
  `unsafe` is a bounds-checked `u32 ↔ u8` reinterpret and the SIMD kernels.
- `#![forbid(unsafe_op_in_unsafe_fn)]`, `cargo clippy --all-features
  --all-targets` is clean, and all feature combinations build in `--release`.

---

## License

Apache-2.0. See [LICENSE](LICENSE).
