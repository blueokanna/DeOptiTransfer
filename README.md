# deopti-transfer

`deopti-transfer` is a `no_std + alloc` fountain-code core for one-way optical
file transfer. A sender continuously emits self-contained frames; a receiver
can reconstruct the stream without acknowledgements or retransmission control.

The current wire protocol is version 3 (frame magic `D1 0F`). Version 2 frames
are intentionally rejected because they do not contain a per-frame integrity
tag and can poison the decoder with a corrupted equation.

## Causal weave

The session sender uses the causal mode by default. For source blocks
`x[0]..x[K-1]`, its first phase emits:

```text
y[0] = x[0]
y[i] = x[i-1] XOR x[i]    for 1 <= i < K
```

This is an invertible lower-bidiagonal encoding matrix. Receiving the first
`K` frames, in any order, reconstructs the payload in exactly `K` frames. A
missing first-phase frame cuts the chain into components instead of leaving an
isolated missing source block. When a later repair equation solves one member
of a component, peeling propagates through all received edges in that component.
After the first phase, the sender emits deterministic robust-soliton LT repair
equations indefinitely, so a receiver that starts late can still decode.

The construction is pinned by golden vectors and tested in reverse frame order,
with isolated cuts, and under deterministic loss. For `K=139` with the same
per-sequence drop mask, frames admitted by the decoder were:

| Drop rate | Causal | Direct systematic | Pure RSD |
| --- | ---: | ---: | ---: |
| 0% | 1.000 K | 1.000 K | 1.317 K |
| 10% | 1.043 K | 1.403 K | 1.173 K |
| 30% | 1.554 K | 1.554 K | 1.317 K |

These are deterministic regression measurements, not a general channel model
or a claim of academic novelty. Applications can explicitly select direct
systematic or pure RSD when their measured channel favors one of those modes.

## Frame integrity and session isolation

Each 25-byte frame header contains two separate BLAKE3-derived 32-bit tags:

- `frame_tag` covers the canonical frame header and block before the equation
  enters the decoder. A damaged frame is treated as an erasure and the same
  sequence number can be admitted later.
- `stream_tag` identifies the complete transmitted container and is checked
  again after reconstruction.

The 32-bit tags detect accidental optical corruption; they are not message
authentication codes. Use the `encryption` feature against active tampering.

A receiver locks to the first valid stream identity. Frames from another stream
return `Error::StreamConflict` without discarding current progress. Call
`Receiver::reset` to select a different stream deliberately. Decoder payload
storage is bounded to four times the source-block arena, and capacity is checked
before the sequence deduplication set can grow.

## Authenticated encryption

The optional `encryption` feature uses XChaCha20-Poly1305. Container metadata,
declared lengths, digest, name, and media type are authenticated as associated
data. The plaintext is verified with BLAKE3 after decryption and decompression.

Two key paths are available:

- `EncryptionKey::new` accepts a high-entropy 32-byte key.
- Password helpers use Argon2id with a 19 MiB memory cost, two iterations, one
  lane, and the per-container 24-byte nonce as salt.

Nonces must be unique for each encryption under a direct key. On `std` builds,
`random_nonce()` obtains 24 bytes from the operating-system RNG and returns an
error if randomness is unavailable. Embedded applications must supply nonces
from a suitable platform RNG.

## Limits

- Original file: at most 64 MiB.
- Metadata fields: at most 65,535 bytes each.
- Source blocks: at most 65,535.
- Block length: 1 through 65,535 bytes.
- The stream limit separately includes the container header, metadata, and AEAD
  tag, so a valid 64 MiB file does not become unsendable after packaging.

All untrusted lengths are validated before decoder allocation or decompression.
Gzip output is bounded by the declared original length. Sender checked
constructors reject empty input and invalid sizes, and `try_next_frame` reports
sequence exhaustion instead of wrapping to duplicate sequence numbers.

## Usage

```toml
[dependencies]
deopti-transfer = { version = "0.1", features = ["encryption"] }
```

```rust
use deopti_transfer::container::{pack_file, unpack_file};
use deopti_transfer::session::{Receiver, Sender};

# fn run() -> deopti_transfer::Result<()> {
let packed = pack_file("notes.txt", "text/plain", b"payload")?;
let mut sender = Sender::try_from_packed(&packed, 1465, 0x0cd1)?;
let mut receiver = Receiver::new();

loop {
    let wire = sender.try_next_frame()?.to_bytes();
    if let Some(container) = receiver.try_push(&wire)? {
        let file = unpack_file(&container)?;
        assert_eq!(file.bytes, b"payload");
        break;
    }
}
# Ok(())
# }
```

Password encryption is available through `pack_file_encrypted_with_password`
and `unpack_file_with_password`. The nonce is stored in the container header;
only the password must be transferred out of band.

## Feature matrix

- Default `std`: bounded gzip compression and decompression.
- `--no-default-features`: pure `no_std + alloc` codec and uncompressed
  containers.
- `encryption`: XChaCha20-Poly1305, Argon2id, key zeroization, and OS nonce
  generation when `std` is also enabled.

Run the verification matrix with:

```text
cargo test --all-features
cargo check --no-default-features
cargo check --no-default-features --features encryption
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt -- --check
```

## License

Apache-2.0. See `LICENSE`.
