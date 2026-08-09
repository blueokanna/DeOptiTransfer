# deopti-transfer

`deopti-transfer` is a Rust `no_std + alloc` LT fountain-code core for
one-way transfer channels such as screen-to-camera links. It provides the
binary transport, bounded peeling decoder, file container, optional
authenticated encryption, and a designated-judge recovery construction. It
does not render QR codes or control a camera.

Current formats:

- frame protocol: v3, magic `D1 0F`;
- file container: DCF3, magic `DCF3`;
- judge-recoverable commitment: JRC1;
- judge-recoverable proof composition: JRP2.

The implementation is production-oriented, but it has not received an
independent security audit. The names JRC/JRP and the causal first phase must
not be treated as proof of academic novelty. Closely related work includes
escrowed and extractable commitments and designated-verifier systems; a
publication claim requires a proper prior-art review.

[中文文档](README_CN.md)

## What is implemented

- Three LT modes: causal first phase plus repair tail (default), direct
  systematic plus repair tail, and pure robust-soliton coding.
- Deterministic wire behavior with golden vectors.
- AVX2, SSE2, NEON, and scalar XOR paths with runtime dispatch where needed.
- Per-frame corruption filtering, stream identity locking, duplicate
  suppression, and final reconstructed-stream verification.
- DCF3 file metadata, bounded gzip decompression, filename/MIME validation,
  and a BLAKE3 file digest.
- Optional XChaCha20-Poly1305 encryption and Argon2id password derivation.
- Optional X25519-based JRC designated-judge recovery.
- JRP composition with an application-supplied relation-proof backend. No
  fake hash-based “proof” and no bundled general-purpose SNARK/STARK.
- Configurable receiver limits and hard decoder storage budgets.

## Installation and features

```toml
[dependencies]
deopti_transfer = "0.1.2"
```

| Feature | Default | Effect |
| --- | --- | --- |
| `std` | yes | gzip compression/decompression through `flate2` |
| `encryption` | no | Argon2id, XChaCha20-Poly1305, OS randomness, X25519 JRC/JRP, zeroization |

```bash
cargo build --release
cargo build --release --no-default-features
cargo build --release --no-default-features --features encryption
```

The last configuration remains `no_std + alloc`; the target must still supply
the randomness backend required by `getrandom`, or the application must build
keys from externally generated secret bytes where supported.

## End-to-end transfer

```rust
use deopti_transfer::container::{pack_file, unpack_file};
use deopti_transfer::session::{Receiver, Sender};

let packed = pack_file("notes.txt", "text/plain", b"hello over light")?;
let mut sender = Sender::try_from_packed(&packed, 1465, 0x0cd1)?;
let mut receiver = Receiver::new();
let mut recovered = None;

for _ in 0..usize::from(sender.k()) * 4 {
    let frame = sender.try_next_frame()?;
    if let Some(container) = receiver.try_push(&frame.to_bytes())? {
        recovered = Some(container);
        break;
    }
}

let container = recovered.ok_or(deopti_transfer::Error::InvalidStream)?;
let file = unpack_file(&container)?;
assert_eq!(file.bytes, b"hello over light");
# Ok::<(), deopti_transfer::Error>(())
```

The loop bound is an application timeout, not a decoding guarantee. Under
loss, continue requesting new sequence numbers until completion, policy
timeout, or `Error::SequenceExhausted`.

## Protocol v3

Every frame is `25 + block_len` bytes and is self-describing:

| Offset | Size | Field | Meaning |
| ---: | ---: | --- | --- |
| 0 | 2 | magic | `D1 0F` |
| 2 | 1 | flags | `0` pure RSD, `1` direct systematic, `2` causal |
| 3 | 2 | session ID | little-endian sender-selected identifier |
| 5 | 4 | sequence | equation selector |
| 9 | 2 | `K` | source-block count |
| 11 | 2 | block length | payload bytes in every frame |
| 13 | 4 | total length | reconstructed stream bytes |
| 17 | 4 | stream tag | first 32 bits of BLAKE3(stream) |
| 21 | 4 | frame tag | first 32 bits of BLAKE3(header fields, block) |
| 25 | variable | block | LT equation payload |

`parse_frame` validates magic, flags, lengths, and the frame tag before the
equation reaches the decoder. `Receiver` locks to the full constant stream
identity `(flags, session_id, K, block_len, total_len, stream_tag)`.

The tags are truncated, unkeyed hashes. They are suitable for accidental
corruption detection, with an idealized random-collision probability of
`2^-32` per check. They do not authenticate a sender: an active attacker can
recompute both tags. Use encrypted containers for payload authentication and
an application-level signature when sender identity matters.

## Fountain construction

Split the byte stream into `K = ceil(L / B)` blocks `x_0,...,x_{K-1}` of `B`
bytes, padding only the final internal block with zeroes.

### Causal first phase

The first `K` equations are

```text
y_0 = x_0
y_i = x_(i-1) XOR x_i,  1 <= i < K.
```

Over `GF(2)`, this is `y = A x`, where `A` is lower bidiagonal with ones on
the diagonal and subdiagonal. Since `A` is triangular,

```text
det(A) = product_i A[i,i] = 1,
```

so `A` is invertible for every `K >= 1`. Explicitly,

```text
x_i = y_0 XOR y_1 XOR ... XOR y_i.
```

Therefore all first-phase frames reconstruct exactly in `K` distinct frames,
regardless of arrival order. This theorem is only about receiving all `K`
first-phase equations. If one is missing, invertibility of the received
submatrix is not guaranteed; repair frames are then required.

### Robust-soliton repair tail

For sequence numbers `seq >= K`, sender and receiver derive the same degree
and block subset from `SplitMix32(session_id, seq)`. With
`c = 0.1`, `delta = 0.5` and

```text
R = max(1, c * ln(K / delta) * sqrt(K)),
s = min(K, ceil(K / R)),
rho(1) = 1/K,
rho(d) = 1/(d(d-1))                       for d >= 2,
tau(d) = R/(dK)                           for d < s,
tau(s) = R * max(0, ln(R/delta)) / K,
mu(d) = (rho(d) + tau(d)) / sum_j(rho(j) + tau(j)),
```

the encoder XORs the sampled distinct source blocks. The decoder performs
standard degree-one peeling.

Robust-soliton analysis gives probabilistic performance under its sampling
model; it does not make every finite set of frames decodable and it does not
justify a universal `1.15K` bound. Tests measure selected deterministic loss
patterns, but those measurements are regression checks rather than proofs for
all channels.

### Modes

| Constructor | First `K` frames | Tail |
| --- | --- | --- |
| `Sender::try_new` | causal transform | robust soliton |
| `Sender::try_new_systematic` | source blocks directly | robust soliton |
| `Sender::try_new_rsd` | robust soliton immediately | robust soliton |

## Decoder resource model

Wire fields are hostile input. Before allocating, `LtDecoder` requires:

- `K > 0`, `block_len > 0`, and `total_len > 0`;
- `K = ceil(total_len / block_len)`;
- `K <= 65,535` and `total_len <= MAX_STREAM_BYTES`.

The equation arena is capped at four source-stream equivalents. Stored
pending adjacency entries are capped at `64 * K`; frames exceeding a budget
are counted by `frames_dropped()` and are not inserted into duplicate state.
This prevents crafted high-degree sequences from growing metadata without a
bound.

Applications should also set deployment-specific limits before accepting the
first frame:

```rust
use deopti_transfer::{Receiver, ReceiverLimits};

let receiver = Receiver::with_limits(ReceiverLimits {
    max_stream_bytes: 8 * 1024 * 1024,
    max_source_blocks: 8192,
    max_block_len: 4096,
});
assert_eq!(receiver.limits().max_stream_bytes, 8 * 1024 * 1024);
```

## DCF3 container

DCF3 stores a fixed 73-byte header followed by sanitized filename bytes,
validated MIME bytes, and transmitted data. The header includes flags,
metadata lengths, original length, transmitted length, BLAKE3 digest, and a
24-byte nonce.

- Maximum original file size: 64 MiB.
- gzip is used only with `std`, for non-precompressed media, and only when it
  saves at least 64 bytes after a 768-byte threshold.
- Decompression is bounded by the declared original length and checks the
  gzip `ISIZE` field.
- Received filenames discard path components, controls, bidi controls,
  Windows-invalid characters, trailing dots/spaces, and reserved device-name
  ambiguity.
- MIME values must have a valid ASCII `type/subtype` and contain no control or
  non-ASCII bytes.
- The file digest detects corruption but is not a signature or MAC.

## Authenticated encryption

Enable `encryption` and use either a 32-byte `EncryptionKey` or the password
API. DCF3 encrypts compressed file bytes with XChaCha20-Poly1305. Flags,
lengths, digest, filename, and MIME type are associated data, so changes are
rejected.

```rust
use deopti_transfer::container::{
    pack_file_encrypted_with_password, unpack_file_with_password,
};
use deopti_transfer::crypto::random_nonce;

let nonce = random_nonce()?;
let packed = pack_file_encrypted_with_password(
    "secret.txt",
    "text/plain",
    b"classified",
    b"correct horse battery staple",
    &nonce,
)?;
let file = unpack_file_with_password(
    &packed.container,
    b"correct horse battery staple",
)?;
assert_eq!(file.bytes, b"classified");
# Ok::<(), deopti_transfer::Error>(())
```

Password keys use Argon2id v1.3 with 19 MiB, two iterations, one lane, and a
32-byte output. The 24-byte nonce is also the password salt. Reusing a nonce
with the same direct key, or with the same password-derived mode, is unsafe;
generate it randomly for every encrypted container. Filenames, MIME values,
lengths, and digests remain visible in ordinary encrypted DCF3 headers.

## JRC: designated-judge recovery

JRC hides the entire inner DCF3 container, including its metadata, from
external receivers while allowing one judge key to recover it.

```text
(dk, ek)  = X25519 judge key pair
(e_sk, e_pk) = fresh ephemeral X25519 key pair
shared    = X25519(e_sk, ek)
k_enc     = BLAKE3 derive_key("deopti-transfer jrc enc v1", context)
k_com     = BLAKE3 derive_key("deopti-transfer jrc com v1", context)
c         = BLAKE3 keyed_hash(k_com, message)
ct        = XChaCha20-Poly1305(k_enc, nonce, message, aad = c)
aux       = e_pk || nonce || ct
```

`context = shared || e_pk || ek || nonce`. The wire envelope is
`"JRC\x01" || c || aux`, with 108 bytes of overhead. Creation and recovery
reject non-contributory X25519 inputs.

```rust
use deopti_transfer::crypto::random_nonce;
use deopti_transfer::{keygen, pack_file_jrc, unpack_file_jrc};

let judge = keygen()?;
let nonce = random_nonce()?;
let packed = pack_file_jrc(
    "report.pdf",
    "application/pdf",
    b"document bytes",
    &judge.ek,
    &nonce,
)?;

// Send packed.envelope through Sender/Receiver.
let file = unpack_file_jrc(&packed.envelope, &judge.dk)?;
assert_eq!(file.bytes, b"document bytes");
# Ok::<(), deopti_transfer::Error>(())
```

### Conditional security statement

The construction claims the following only under hashed Diffie-Hellman for
X25519 in the random-oracle model, domain-separated BLAKE3 KDF/PRF security,
multi-key collision resistance of the 256-bit keyed commitment, and
XChaCha20-Poly1305 AEAD security:

1. Correctness: honest X25519 computations derive equal shared secrets; AEAD
   decryption inverts encryption and the recomputed commitment matches.
2. External hiding: for equal-length messages, replace hashed-DH keys with
   random keys, then apply AEAD confidentiality and keyed-PRF security.
3. Computational binding: two accepted openings recovering different
   messages for one `c` directly imply a collision across the
   adversary-influenced keyed commitment instances. PRF security alone is not
   enough for this claim; multi-key collision resistance is assumed.
4. Judge-only confidentiality: equal-length challenge messages remain
   indistinguishable without `dk`. This does not prevent guessing a
   low-entropy message from outside information.

JRC leaks envelope length, does not authenticate who created a commitment,
and has no forward secrecy after compromise of the long-term judge key. The
judge secret must be stored outside the optical sender/receiver and backed up
as sensitive 32-byte key material.

## JRP: relation-proof composition

JRP2 is not a hash tag presented as a proof. It requires an implementation of
`RelationProofSystem` that proves, in zero knowledge, knowledge of
`(witness, output, JRC opening)` satisfying:

```text
JRC.Commit(ek, output; opening) = public commitment
R(statement, witness) = true
output = f(statement, witness).
```

`jrp::prove` creates the JRC commitment, asks the backend to prove the exact
relation, self-verifies the returned proof, and emits
`"JRP\x02" || proof_len || relation_proof || JRC-envelope`.
`jrp::verify_ext` invokes the backend over the statement, judge public key,
and complete JRC transcript. `jrp::judge_recover` verifies first and decrypts
only after acceptance.

The crate does not bundle a universal ZK backend. This is intentional: a
production choice needs an explicit circuit, verification-key lifecycle,
trusted-setup policy, size budget, and security level. JRP inherits
completeness, soundness, and zero knowledge from that backend; implementing
only a public hash violates the trait contract.

## Performance

The hot path uses word arenas, deterministic degree tables, open-addressing
sequence deduplication, and SIMD XOR. No fixed throughput number is claimed:
results depend on CPU, compiler, block size, payload size, and mode.

```bash
cargo bench
```

The Criterion decode fixture first verifies that its prepared frame set
actually completes; incomplete decoding is not reported as successful
throughput.

## Verification

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo test --all-features
cargo check --no-default-features
cargo check --no-default-features --features encryption
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
cargo package --allow-dirty
```

Tests cover wire golden vectors, deterministic logarithm/CDF fingerprints,
all three transfer modes, loss and duplicate handling, malformed containers,
decompression bounds, metadata validation, receiver allocation policy, SIMD
equivalence and length safety, AEAD/JRC tampering, non-contributory X25519
keys, JRP relation/tampering behavior, and `no_std` compilation.

Tests establish implementation behavior for tested inputs. They do not prove
cryptographic assumptions, universal fountain overhead, academic originality,
or resistance to side channels on every target.

## Operational limitations

- There is no QR/barcode renderer, camera pipeline, framing UI, or device
  discovery in this crate.
- Fountain decoding handles erasures and verified equations; it is not a
  Byzantine error-correcting code.
- A first valid-looking frame can lock a receiver and cause denial of service;
  use timeouts, `reset`, limits, and sender authentication where required.
- Session IDs and integrity tags are short protocol fields, not security
  identities.
- The sender sequence space is finite (`u32`); checked APIs report exhaustion.
- Wire-format changes require a new version and new golden vectors.

## License

Apache-2.0. See [LICENSE](LICENSE).
