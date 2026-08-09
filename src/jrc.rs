//! Judge-Recoverable Commitment (JRC) — a commitment scheme with a
//! designated-judge recovery channel (the `JRC` primitive of `creative.md`).
//!
//! A JRC is a commitment that *additionally* carries a hidden channel
//! readable only by a designated judge:
//!
//! - **External observers** see only `(c, aux)`: a 32-byte commitment and a
//!   ciphertext blob. Under the construction below they learn nothing about
//!   the committed message (External Hiding), and the sender cannot later
//!   open `c` to a different message (Binding).
//! - **The judge**, holding `dk`, recovers the exact committed message from
//!   `(c, aux)` (Correctness), and *only* the judge can (Judge-Only
//!   Recoverability).
//!
//! # Construction
//!
//! The construction follows the generic template of `creative.md` — a
//! standard IND-CPA public-key encryption combined with a binding commitment
//! — instantiated entirely from no_std primitives:
//!
//! ```text
//! Setup:  (ek, dk) = X25519 keypair.
//! Commit(ek, m; r):
//!   e_sk, e_pk = fresh ephemeral X25519 keypair      (r = fresh 24-byte nonce)
//!   shared     = X25519(e_sk, ek)
//!   k_enc      = BLAKE3-derive_key("jrc enc v1", shared ‖ e_pk ‖ ek ‖ r)
//!   k_com      = BLAKE3-derive_key("jrc com v1", shared ‖ e_pk ‖ ek ‖ r)
//!   c          = BLAKE3-keyed_hash(k_com, m)                       [commitment]
//!   ct         = XChaCha20-Poly1305.encrypt(k_enc, r, m, aad = c)  [recovery channel]
//!   aux        = e_pk ‖ r ‖ ct
//! VerifyExt(c, aux):      format check only.
//! JudgeRecover(dk, c, aux):
//!   shared     = X25519(dk, e_pk)          ;  derive k_enc, k_com as above
//!   m          = AEAD.decrypt(k_enc, r, ct, aad = c)
//!   require c == BLAKE3-keyed_hash(k_com, m)   else ⊥
//! ```
//!
//! The commitment `c` is a *keyed* BLAKE3 hash, so it hides `m` even when
//! `m` has low entropy (the key `k_com` is secret to the observer); the
//! AEAD ciphertext hides `m` under X25519 CDH + XChaCha20-Poly1305.
//!
//! # Security statement
//!
//! The construction is a concrete KEM/DEM-style instantiation, not a new
//! hardness assumption. Its claims are conditional on hashed Diffie-Hellman
//! for X25519 in the random-oracle model, domain-separated BLAKE3 KDF/PRF
//! security, XChaCha20-Poly1305 AEAD security, and collision resistance of
//! the 256-bit commitment. No software test can prove those assumptions.
//!
//! **Correctness.** For every `(ek, dk) ← keygen()` and every `m`, if
//! `(c, aux) ← commit(ek, m; r)` then `judge_recover(dk, c, aux) = m` with
//! probability `1 − negl(λ)`. *Proof.* X25519 is correct, so sender and
//! judge derive the identical `shared`; BLAKE3 `derive_key`/`keyed_hash` are
//! deterministic; XChaCha20-Poly1305 decryption inverts encryption; the
//! recomputed commitment equals the original `c`. ∎
//!
//! **External Hiding.** For any PPT observer `A` given only `(ek, c, aux)`
//! and any equal-length messages `m₀, m₁` with `|m₀| = |m₁|`, the
//! distributions `commit(ek, m₀; r)` and `commit(ek, m₁; r)` are
//! computationally indistinguishable. *Proof.* `A` holds neither the
//! ephemeral secret `e_sk` nor the judge secret `dk`, so
//! `(e_pk, shared = X25519(e_sk, ek))` is an X25519 encapsulation. By the
//! **hashed-DH (HDH) assumption** — which reduces to CDH in the
//! random-oracle model — the RO evaluations `k_enc`, `k_com` of that
//! encapsulation are indistinguishable from uniform 32-byte keys to `A`.
//! Given uniform keys: (a) `ct` hides `m` by IND-CPA security of
//! XChaCha20-Poly1305 under `k_enc`; and (b) `c = keyed_hash(k_com, m)` is
//! indistinguishable from uniform by the keyed-PRF security of BLAKE3 —
//! *even for low-entropy `m`*, because `k_com` is secret to `A`. A standard
//! hybrid argument over the two transcript components completes the proof.
//! ∎
//!
//! *Honest caveat:* `|ct| = |m| + 16` is public, so hiding is claimed only
//! for messages of **equal length** (as in `creative.md`). If the plaintext
//! length itself is sensitive, pad `m` to a fixed size before committing.
//!
//! **Binding.** The relevant game fixes `ek` and asks an adversary for one
//! commitment `c` and two valid recovery records `aux_0`, `aux_1` that the
//! judge accepts as distinct messages. Because each accepted record decrypts
//! to one message and recomputes `c`, success directly produces a collision
//! across the domain-separated, adversary-influenced commitment keys. This is
//! a computational, not statistical, claim. PRF security alone is not
//! sufficient for this game; the statement explicitly assumes multi-key
//! collision resistance of the 256-bit keyed BLAKE3 output.
//!
//! **Judge-only confidentiality.** This is an indistinguishability claim for
//! equal-length chosen messages, not a claim that an adversary cannot guess a
//! predictable message. It follows by replacing the hashed-DH output with
//! random keys and then applying AEAD confidentiality and keyed-PRF security.
//! Both commitment creation and recovery reject non-contributory X25519
//! inputs, which excludes the all-zero shared-secret class.
//!
//! # Nonce discipline
//!
//! `r` is the AEAD nonce *and* part of the KDF salt. Because every
//! [`commit`] call draws a **fresh ephemeral keypair**, the derived `k_enc`
//! is fresh per commitment, so reusing the same `r` across different
//! [`commit`] calls is cryptographically safe (AEAD nonces only need to be
//! unique per key). The only forbidden pattern — reusing both the ephemeral
//! secret and `r` — is unreachable through the public API ([`commit`] always
//! draws a fresh ephemeral key); it exists only in the deterministic
//! `commit_with_ephemeral` test hook.
//!
//! # Honest scope
//!
//! JRC is *not* a zero-knowledge proof: the external verifier learns that a
//! commitment exists, not that any relation over `m` holds (that is the role
//! of [`crate::jrp`]). It is related to, but distinct from, escrowed
//! commitments, extractable commitments and designated-verifier proofs; the
//! judge channel here is *keyed* (only `dk` reads it), the commitment is
//! *keyed* (hiding holds for low-entropy messages), and `aux` is bound to
//! `c` as AEAD associated data.

use alloc::vec::Vec;
use zeroize::Zeroize;

use crate::crypto::{decrypt, encrypt, NONCE_LEN, TAG_LEN};
use crate::error::{Error, Result};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

/// Length of a JRC commitment in bytes.
pub const COMMIT_LEN: usize = 32;
/// Length of an ephemeral X25519 public key in bytes.
pub const EPHEMERAL_PK_LEN: usize = 32;
/// Serialized-envelope overhead for a message of length `L`:
/// `magic(4) ‖ commitment(32) ‖ e_pk(32) ‖ nonce(24) ‖ tag(16)`.
pub const ENVELOPE_OVERHEAD: usize = 4 + COMMIT_LEN + EPHEMERAL_PK_LEN + NONCE_LEN + TAG_LEN;
/// Largest message that can be carried by one protocol-v3 stream as a JRC
/// envelope.
pub const MAX_MESSAGE_LEN: usize = crate::frame::MAX_STREAM_BYTES as usize - ENVELOPE_OVERHEAD;

/// Checked serialized-envelope length for a message of `message_len` bytes.
/// Returns `None` on `usize` overflow. Compare the result with
/// [`crate::frame::MAX_STREAM_BYTES`] before committing.
pub const fn envelope_len(message_len: usize) -> Option<usize> {
    message_len.checked_add(ENVELOPE_OVERHEAD)
}

const ENVELOPE_MAGIC: [u8; 4] = [b'J', b'R', b'C', 1u8];
const KDF_ENC_CTX: &str = "deopti-transfer jrc enc v1";
const KDF_COM_CTX: &str = "deopti-transfer jrc com v1";

/// The judge's public key `ek`; anyone may commit against it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JudgePublicKey(PublicKey);

/// The judge's secret key `dk`; only it recovers committed messages.
///
/// Key material is zeroized on drop (x25519-dalek `zeroize` feature).
#[derive(Clone)]
pub struct JudgeSecretKey(StaticSecret);

/// A freshly generated judge keypair. `Debug` redacts the secret key.
#[derive(Clone)]
pub struct JudgeKeyPair {
    pub ek: JudgePublicKey,
    pub dk: JudgeSecretKey,
}

impl core::fmt::Debug for JudgeKeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("JudgeKeyPair")
            .field("ek", &self.ek)
            .field("dk", &self.dk)
            .finish()
    }
}

/// A JRC transcript: the public commitment `c` plus the recovery data `aux`.
///
/// `aux = e_pk ‖ nonce ‖ ciphertext`; the whole transcript serializes to
/// `magic ‖ c ‖ aux` via [`JrcCommitment::to_bytes`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JrcCommitment {
    pub commitment: [u8; COMMIT_LEN],
    pub aux: Vec<u8>,
}

/// Secret opening material used by a zero-knowledge relation-proof backend.
///
/// Normal JRC callers do not need this type: use [`commit`]. A JRP prover
/// calls [`commit_with_prover_opening`] and passes this value to a proof
/// backend capable of proving that the public JRC transcript encrypts and
/// commits to an output satisfying its relation. The ephemeral secret is
/// zeroized on drop and is never serialized.
pub struct JrcProverOpening {
    ephemeral_secret: [u8; 32],
    nonce: [u8; NONCE_LEN],
}

impl JrcProverOpening {
    /// Ephemeral X25519 scalar bytes for a proof circuit/backend.
    pub fn ephemeral_secret(&self) -> &[u8; 32] {
        &self.ephemeral_secret
    }

    /// Transcript nonce for a proof circuit/backend.
    pub fn nonce(&self) -> &[u8; NONCE_LEN] {
        &self.nonce
    }
}

impl core::fmt::Debug for JrcProverOpening {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("JrcProverOpening([redacted])")
    }
}

impl Drop for JrcProverOpening {
    fn drop(&mut self) {
        self.ephemeral_secret.zeroize();
        self.nonce.zeroize();
    }
}

impl JudgeSecretKey {
    /// Build a judge secret key from its 32 raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(StaticSecret::from(bytes))
    }

    /// The 32 raw bytes of the secret key. Use for backup or transport of
    /// the judge key; the caller must treat the returned bytes as secret
    /// material (zeroize after use). The copy in `self` is zeroized on drop.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Derive the matching public key.
    pub fn to_public(&self) -> JudgePublicKey {
        JudgePublicKey(PublicKey::from(&self.0))
    }
}

impl JudgePublicKey {
    /// Build a judge public key from its 32 raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(PublicKey::from(bytes))
    }

    /// The 32 raw bytes of the public key.
    pub fn to_bytes(&self) -> [u8; 32] {
        *self.0.as_bytes()
    }
}

impl core::fmt::Debug for JudgeSecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("JudgeSecretKey([redacted])")
    }
}

/// Generate a fresh judge keypair from the OS RNG. no_std applications that
/// cannot draw from the OS supply their own secret via
/// [`JudgeSecretKey::from_bytes`].
pub fn keygen() -> Result<JudgeKeyPair> {
    let mut raw = [0u8; 32];
    getrandom::fill(&mut raw).map_err(|_| Error::Crypto)?;
    let dk = JudgeSecretKey::from_bytes(raw);
    raw.zeroize();
    let ek = dk.to_public();
    Ok(JudgeKeyPair { ek, dk })
}

/// Commit to `m` against judge `ek` with nonce `r`.
///
/// `r` doubles as the AEAD nonce and the KDF salt. Because this function
/// draws a fresh ephemeral keypair on every call, the derived encryption
/// key is fresh per commitment and `r` may be reused across calls (see the
/// module-level "Nonce discipline" note). Use [`crate::crypto::random_nonce`]
/// on std builds, or a TRNG on no_std.
pub fn commit(ek: &JudgePublicKey, m: &[u8], r: &[u8; NONCE_LEN]) -> Result<JrcCommitment> {
    let (commitment, _opening) = commit_with_prover_opening(ek, m, r)?;
    Ok(commitment)
}

/// Commit and retain the secret opening needed to build a relation proof.
/// The returned opening must never be transmitted or logged.
pub fn commit_with_prover_opening(
    ek: &JudgePublicKey,
    m: &[u8],
    r: &[u8; NONCE_LEN],
) -> Result<(JrcCommitment, JrcProverOpening)> {
    check_message_len(m.len())?;
    let mut e_sk = [0u8; 32];
    getrandom::fill(&mut e_sk).map_err(|_| Error::Crypto)?;
    let out = commit_with_ephemeral(ek, m, r, &e_sk);
    match out {
        Ok(commitment) => Ok((
            commitment,
            JrcProverOpening {
                ephemeral_secret: e_sk,
                nonce: *r,
            },
        )),
        Err(error) => {
            e_sk.zeroize();
            Err(error)
        }
    }
}

/// Commit with an externally supplied ephemeral secret (deterministic; used
/// for golden-vector pinning and testing).
pub(crate) fn commit_with_ephemeral(
    ek: &JudgePublicKey,
    m: &[u8],
    r: &[u8; NONCE_LEN],
    e_sk_bytes: &[u8; 32],
) -> Result<JrcCommitment> {
    check_message_len(m.len())?;
    let e_sk = StaticSecret::from(*e_sk_bytes);
    let e_pk = PublicKey::from(&e_sk);
    let shared = e_sk.diffie_hellman(&ek.0);
    if !shared.was_contributory() {
        return Err(Error::InvalidKey);
    }
    let (mut k_enc, mut k_com) = derive_keys(&shared, &e_pk, &ek.0, r);
    let c = commit_value(&k_com, m);
    let ct = encrypt(&k_enc, r, m, &c);
    k_enc.zeroize();
    k_com.zeroize();
    let ct = ct.map_err(|_| Error::Crypto)?;
    let mut aux = Vec::with_capacity(EPHEMERAL_PK_LEN + NONCE_LEN + ct.len());
    aux.extend_from_slice(e_pk.as_bytes());
    aux.extend_from_slice(r);
    aux.extend_from_slice(&ct);
    Ok(JrcCommitment { commitment: c, aux })
}

/// External format verification of a JRC transcript: the commitment is a
/// 32-byte value and `aux` can hold `e_pk ‖ nonce ‖ at least one tag`.
/// Deliberately leaks nothing about `m`.
pub fn verify_ext(c: &[u8; COMMIT_LEN], aux: &[u8]) -> bool {
    let _ = c;
    aux.len() >= EPHEMERAL_PK_LEN + NONCE_LEN + TAG_LEN
        && aux.len() <= crate::frame::MAX_STREAM_BYTES as usize - 4 - COMMIT_LEN
}

/// Judge-side recovery: return the committed message, or `Err` when the
/// transcript is malformed, not encrypted for this judge, or the recovered
/// message does not match the commitment (binding check).
pub fn judge_recover(dk: &JudgeSecretKey, c: &[u8; COMMIT_LEN], aux: &[u8]) -> Result<Vec<u8>> {
    if aux.len() < EPHEMERAL_PK_LEN + NONCE_LEN + TAG_LEN {
        return Err(Error::Truncated);
    }
    let (e_pk_bytes, rest) = aux.split_at(EPHEMERAL_PK_LEN);
    let (r, ct) = rest.split_at(NONCE_LEN);
    let e_pk_bytes: [u8; EPHEMERAL_PK_LEN] = e_pk_bytes.try_into().map_err(|_| Error::Crypto)?;
    let r: [u8; NONCE_LEN] = r.try_into().map_err(|_| Error::Crypto)?;
    let e_pk = PublicKey::from(e_pk_bytes);
    let ek = PublicKey::from(&dk.0);
    let shared = dk.0.diffie_hellman(&e_pk);
    if !shared.was_contributory() {
        return Err(Error::InvalidKey);
    }
    let (mut k_enc, mut k_com) = derive_keys(&shared, &e_pk, &ek, &r);
    let m = match decrypt(&k_enc, &r, ct, c) {
        Ok(m) => m,
        Err(e) => {
            k_enc.zeroize();
            k_com.zeroize();
            return Err(e);
        }
    };
    let c_check = commit_value(&k_com, &m);
    k_enc.zeroize();
    k_com.zeroize();
    if c_check != *c {
        return Err(Error::Crypto);
    }
    Ok(m)
}

impl JrcCommitment {
    /// Serialized length of this transcript (`magic ‖ c ‖ aux`).
    pub fn transmitted_len(&self) -> usize {
        ENVELOPE_MAGIC.len() + COMMIT_LEN + self.aux.len()
    }

    /// Serialize the transcript: `magic(4) ‖ c(32) ‖ aux`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.transmitted_len());
        out.extend_from_slice(&ENVELOPE_MAGIC);
        out.extend_from_slice(&self.commitment);
        out.extend_from_slice(&self.aux);
        out
    }

    /// Parse a serialized transcript, validating magic and minimum length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > crate::frame::MAX_STREAM_BYTES as usize {
            return Err(Error::TooLarge {
                len: bytes.len() as u64,
                max: crate::frame::MAX_STREAM_BYTES,
            });
        }
        if bytes.len() < ENVELOPE_OVERHEAD {
            return Err(Error::Truncated);
        }
        if bytes[..ENVELOPE_MAGIC.len()] != ENVELOPE_MAGIC {
            return Err(Error::BadMagic);
        }
        let mut commitment = [0u8; COMMIT_LEN];
        commitment.copy_from_slice(&bytes[ENVELOPE_MAGIC.len()..ENVELOPE_MAGIC.len() + COMMIT_LEN]);
        Ok(Self {
            commitment,
            aux: bytes[ENVELOPE_MAGIC.len() + COMMIT_LEN..].to_vec(),
        })
    }
}

fn check_message_len(message_len: usize) -> Result<()> {
    if message_len > MAX_MESSAGE_LEN {
        return Err(Error::TooLarge {
            len: message_len as u64,
            max: MAX_MESSAGE_LEN as u64,
        });
    }
    Ok(())
}

/// Derive the two per-transcript keys from the ECDH shared secret.
/// The input mix binds the keys to the ephemeral key, the judge identity and
/// the nonce, so a fresh transcript never reuses a key.
fn derive_keys(
    shared: &SharedSecret,
    e_pk: &PublicKey,
    ek: &PublicKey,
    r: &[u8; NONCE_LEN],
) -> ([u8; 32], [u8; 32]) {
    let mut input = Vec::with_capacity(32 + 32 + 32 + NONCE_LEN);
    input.extend_from_slice(shared.as_bytes());
    input.extend_from_slice(e_pk.as_bytes());
    input.extend_from_slice(ek.as_bytes());
    input.extend_from_slice(r);
    let k_enc = blake3::derive_key(KDF_ENC_CTX, &input);
    let k_com = blake3::derive_key(KDF_COM_CTX, &input);
    input.zeroize();
    (k_enc, k_com)
}

/// The keyed commitment: `c = BLAKE3-keyed_hash(k_com, m)`.
fn commit_value(k_com: &[u8; 32], m: &[u8]) -> [u8; 32] {
    *blake3::keyed_hash(k_com, m).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const MSG: &[u8] = b"deopti-transfer judge-recoverable commitment";

    fn fixed_ephemeral() -> [u8; 32] {
        let mut b = [0u8; 32];
        for (i, byte) in b.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(0x5d).wrapping_add(0x11);
        }
        b
    }

    fn fixed_nonce() -> [u8; NONCE_LEN] {
        let mut b = [0u8; NONCE_LEN];
        for (i, byte) in b.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(0x9e).wrapping_add(0x42);
        }
        b
    }

    #[test]
    fn correctness_roundtrip() {
        let kp = keygen().expect("keygen");
        let r = fixed_nonce();
        let jc = commit(&kp.ek, MSG, &r).expect("commit");
        let m = judge_recover(&kp.dk, &jc.commitment, &jc.aux).expect("recover");
        assert_eq!(m, MSG);
    }

    #[test]
    fn envelope_roundtrip() {
        let kp = keygen().expect("keygen");
        let jc = commit(&kp.ek, MSG, &fixed_nonce()).expect("commit");
        let bytes = jc.to_bytes();
        assert_eq!(bytes.len(), MSG.len() + ENVELOPE_OVERHEAD);
        let parsed = JrcCommitment::from_bytes(&bytes).expect("parse");
        assert_eq!(parsed, jc);
        // Wrong magic or sub-minimum length is rejected at parse time.
        assert!(JrcCommitment::from_bytes(&bytes[4..]).is_err());
        assert!(JrcCommitment::from_bytes(&bytes[..ENVELOPE_OVERHEAD - 1]).is_err());
        // A single trailing byte lost still parses structurally (magic and
        // length hold) but must fail at judge recovery on the AEAD tag.
        let cut = JrcCommitment::from_bytes(&bytes[..bytes.len() - 1]).expect("structural parse");
        assert!(judge_recover(&kp.dk, &cut.commitment, &cut.aux).is_err());
    }

    #[test]
    fn judge_only_recoverability_wrong_key_fails() {
        let kp_a = keygen().expect("keygen a");
        let kp_b = keygen().expect("keygen b");
        let jc = commit(&kp_a.ek, MSG, &fixed_nonce()).expect("commit");
        assert!(judge_recover(&kp_b.dk, &jc.commitment, &jc.aux).is_err());
    }

    #[test]
    fn fresh_transcripts_do_not_repeat_or_expose_plaintext_bytes() {
        let kp = keygen().expect("keygen");
        // Independent calls use fresh ephemeral keys, so transcripts must be
        // unrelated even for the same message. Different nonces also exercise
        // transcript-domain separation.
        let r1 = fixed_nonce();
        let mut r2 = r1;
        r2[0] ^= 1;
        let jc1 = commit(&kp.ek, MSG, &r1).expect("commit 1");
        let jc2 = commit(&kp.ek, MSG, &r2).expect("commit 2");
        assert_ne!(jc1.commitment, jc2.commitment);
        assert_ne!(jc1.aux, jc2.aux);
        assert_ne!(jc1.commitment, *blake3::hash(MSG).as_bytes());
        assert!(!jc1.aux.windows(MSG.len()).any(|w| w == MSG));
        assert!(verify_ext(&jc1.commitment, &jc1.aux));
        assert!(!verify_ext(&jc1.commitment, &[]));
    }

    #[test]
    fn binding_tampered_aux_is_rejected() {
        let kp = keygen().expect("keygen");
        let jc = commit(&kp.ek, MSG, &fixed_nonce()).expect("commit");
        let mut aux = jc.aux.clone();
        let last = aux.len() - 1;
        aux[last] ^= 1;
        assert!(judge_recover(&kp.dk, &jc.commitment, &aux).is_err());
        let mut c = jc.commitment;
        c[0] ^= 1;
        assert!(judge_recover(&kp.dk, &c, &jc.aux).is_err());
    }

    #[test]
    fn commitment_binds_message() {
        let kp = keygen().expect("keygen");
        let e_sk = fixed_ephemeral();
        let r = fixed_nonce();
        let jc = commit_with_ephemeral(&kp.ek, MSG, &r, &e_sk).expect("commit");
        let other = commit_with_ephemeral(&kp.ek, b"different message", &r, &e_sk).expect("commit");
        assert_ne!(jc.commitment, other.commitment);
        // The judge recovers exactly the committed message; a ciphertext of a
        // different message cannot pass the commitment re-check.
        let m = judge_recover(&kp.dk, &jc.commitment, &jc.aux).expect("recover");
        assert_eq!(m, MSG);
    }

    #[test]
    fn deterministic_transcript_is_golden() {
        let kp = keygen().expect("keygen");
        // Pin determinism: fixed inputs must always produce the same
        // transcript bytes (structural golden, complements RFC 7748 vectors
        // covered by x25519-dalek itself).
        let a = commit_with_ephemeral(&kp.ek, MSG, &fixed_nonce(), &fixed_ephemeral()).expect("a");
        let b = commit_with_ephemeral(&kp.ek, MSG, &fixed_nonce(), &fixed_ephemeral()).expect("b");
        assert_eq!(a, b);
        assert_eq!(
            a.aux.len(),
            EPHEMERAL_PK_LEN + NONCE_LEN + MSG.len() + TAG_LEN
        );
    }

    #[test]
    fn zero_length_and_large_messages() {
        let kp = keygen().expect("keygen");
        for len in [0usize, 1, 31, 32, 1024, 1 << 16] {
            let m = vec![0xab; len];
            let jc = commit(&kp.ek, &m, &fixed_nonce()).expect("commit");
            let recovered = judge_recover(&kp.dk, &jc.commitment, &jc.aux).expect("recover");
            assert_eq!(recovered, m, "len {len}");
        }
    }

    #[test]
    fn secret_key_round_trips_through_bytes() {
        let kp = keygen().expect("keygen");
        let raw = kp.dk.to_bytes();
        let dk2 = JudgeSecretKey::from_bytes(raw);
        // Both the original and the rebuilt key recover the same transcript,
        // and both derive the same public key.
        assert_eq!(dk2.to_public(), kp.ek);
        let jc = commit(&kp.ek, MSG, &fixed_nonce()).expect("commit");
        assert_eq!(
            judge_recover(&dk2, &jc.commitment, &jc.aux).expect("recover"),
            MSG
        );
    }

    #[test]
    fn envelope_len_matches_serialized_size() {
        let kp = keygen().expect("keygen");
        let jc = commit(&kp.ek, MSG, &fixed_nonce()).expect("commit");
        assert_eq!(jc.transmitted_len(), jc.to_bytes().len());
        assert_eq!(Some(jc.transmitted_len()), envelope_len(MSG.len()));
        assert_eq!(envelope_len(0), Some(ENVELOPE_OVERHEAD));
        assert_eq!(envelope_len(usize::MAX), None);
        assert!(check_message_len(MAX_MESSAGE_LEN).is_ok());
        assert!(matches!(
            check_message_len(MAX_MESSAGE_LEN + 1),
            Err(Error::TooLarge { .. })
        ));
    }

    #[test]
    fn non_contributory_x25519_inputs_are_rejected() {
        let low_order = JudgePublicKey::from_bytes([0u8; 32]);
        assert!(matches!(
            commit_with_ephemeral(&low_order, MSG, &fixed_nonce(), &fixed_ephemeral()),
            Err(Error::InvalidKey)
        ));

        let judge = JudgeSecretKey::from_bytes([0x13; 32]);
        let mut aux = vec![0u8; EPHEMERAL_PK_LEN + NONCE_LEN + TAG_LEN];
        aux[EPHEMERAL_PK_LEN..EPHEMERAL_PK_LEN + NONCE_LEN].copy_from_slice(&fixed_nonce());
        assert!(matches!(
            judge_recover(&judge, &[0u8; COMMIT_LEN], &aux),
            Err(Error::InvalidKey)
        ));
    }

    #[test]
    fn golden_envelope_is_pinned() {
        // Deterministic judge key, ephemeral key and nonce so the entire
        // envelope is reproducible; pins the wire format of the JRC
        // transcript (magic ‖ c ‖ e_pk ‖ nonce ‖ ciphertext‖tag).
        let dk = JudgeSecretKey::from_bytes([0x13; 32]);
        let ek = dk.to_public();
        let jc = commit_with_ephemeral(&ek, b"jrc golden vector", &fixed_nonce(), &[0x77; 32])
            .expect("commit");
        let golden: [u8; 125] = [
            0x4a, 0x52, 0x43, 0x01, 0x2a, 0xae, 0xfd, 0xa6, 0x63, 0xac, 0x8d, 0x83, 0x05, 0x80,
            0x05, 0x53, 0xdb, 0x55, 0x97, 0xcc, 0xd2, 0xb8, 0x4d, 0x1e, 0x8e, 0xa9, 0x99, 0xa4,
            0xba, 0x4e, 0x0c, 0x0b, 0x70, 0x51, 0xf3, 0xe4, 0x1c, 0xf5, 0x79, 0xab, 0xa4, 0x5a,
            0x10, 0xba, 0x1d, 0x1e, 0xf0, 0x6d, 0x91, 0xfc, 0xa2, 0xaa, 0x9e, 0xd0, 0xa1, 0x15,
            0x05, 0x15, 0x65, 0x31, 0x55, 0x40, 0x5d, 0x0b, 0x18, 0xcb, 0x9a, 0x67, 0x42, 0xe0,
            0x7e, 0x1c, 0xba, 0x58, 0xf6, 0x94, 0x32, 0xd0, 0x6e, 0x0c, 0xaa, 0x48, 0xe6, 0x84,
            0x22, 0xc0, 0x5e, 0xfc, 0x9a, 0x38, 0xd6, 0x74, 0x70, 0x88, 0xc0, 0x3f, 0xcc, 0x50,
            0xd2, 0x04, 0xe0, 0x44, 0xa4, 0x44, 0xa0, 0x7a, 0xd9, 0x49, 0x33, 0x76, 0x30, 0xef,
            0xb0, 0x2a, 0xb2, 0x06, 0xb2, 0x64, 0x37, 0xa6, 0xb4, 0x03, 0x87, 0xde, 0xb3,
        ];
        assert_eq!(jc.to_bytes(), golden, "JRC envelope wire format drifted");
        assert_eq!(
            jc.aux.len(),
            EPHEMERAL_PK_LEN + NONCE_LEN + b"jrc golden vector".len() + TAG_LEN
        );
    }
}
