//! Judge-Recoverable Proof (JRP) composition.
//!
//! JRP combines a [`crate::jrc`] transcript with a caller-supplied
//! zero-knowledge relation-proof system. Unlike a public hash of a statement,
//! the relation proof must establish the following NP statement:
//!
//! ```text
//! public:  (judge public key ek, statement x, JRC transcript (c, aux))
//! private: (witness w, output y, JRC prover opening o)
//!
//! JRC.Commit(ek, y; o) = (c, aux)
//! and R(x, w)
//! and y = f(x, w)
//! ```
//!
//! The crate deliberately does not label a hash or format check as a proof.
//! It provides the composition and wire format; an application selects a
//! production proof backend and implements [`RelationProofSystem`]. JRP has
//! completeness, soundness, and zero knowledge only if that backend proves
//! the statement above with those properties.
//!
//! # Conditional security argument
//!
//! Let `Π` be the supplied proof system and let JRC satisfy its external
//! hiding, binding, and judge-only confidentiality games. Then:
//!
//! - completeness follows from JRC correctness and completeness of `Π`;
//! - external soundness reduces directly to soundness of `Π`, because the
//!   JRC transcript is part of the public input;
//! - output privacy follows by a two-hybrid argument: simulate `Π`, then use
//!   JRC external hiding for equal-length outputs;
//! - judge recovery follows from successful verification plus JRC
//!   correctness; [`judge_recover`] verifies before decrypting.
//!
//! This is a composition theorem, not a claim that every implementation of
//! [`RelationProofSystem`] is secure. Backend setup, trusted-setup rules,
//! circuit correctness, proof size, and verification-key distribution remain
//! application responsibilities.

use alloc::vec::Vec;

use crate::crypto::NONCE_LEN;
use crate::error::{Error, Result};
use crate::jrc::{
    commit_with_prover_opening, judge_recover as jrc_judge_recover, JrcCommitment,
    JrcProverOpening, JudgePublicKey, JudgeSecretKey,
};

const PROOF_MAGIC: [u8; 4] = [b'J', b'R', b'P', 2u8];
/// JRP v2 header: magic (4) plus relation-proof length (4).
pub const PROOF_OVERHEAD: usize = 8;
/// Maximum serialized relation-proof size accepted by this optical protocol.
pub const MAX_RELATION_PROOF_LEN: usize =
    crate::frame::MAX_STREAM_BYTES as usize - PROOF_OVERHEAD - crate::jrc::ENVELOPE_OVERHEAD;

/// Public input that a relation-proof backend must bind into its proof.
#[derive(Clone, Copy)]
pub struct JrpPublicInput<'a> {
    pub judge_key: &'a JudgePublicKey,
    pub statement: &'a [u8],
    pub commitment: &'a JrcCommitment,
}

/// Adapter for a concrete zero-knowledge relation-proof implementation.
///
/// Implementations must prove the exact relation documented at module level.
/// In particular, checking only a hash of the public input violates this
/// contract because it proves neither knowledge nor relation satisfaction.
pub trait RelationProofSystem {
    type Witness: ?Sized;

    /// Create a proof for `public`, using the private relation witness,
    /// recoverable output, and JRC opening.
    fn prove(
        &self,
        public: JrpPublicInput<'_>,
        witness: &Self::Witness,
        output: &[u8],
        opening: &JrcProverOpening,
    ) -> Result<Vec<u8>>;

    /// Verify a proof against every public input field.
    fn verify(&self, public: JrpPublicInput<'_>, proof: &[u8]) -> bool;
}

/// A JRP v2 transcript containing a JRC commitment and a relation proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JrpProof {
    relation_proof: Vec<u8>,
    commitment: JrcCommitment,
}

impl JrpProof {
    pub fn relation_proof(&self) -> &[u8] {
        &self.relation_proof
    }

    pub fn commitment(&self) -> &JrcCommitment {
        &self.commitment
    }

    /// Exact serialized size of this transcript.
    pub fn transmitted_len(&self) -> usize {
        PROOF_OVERHEAD + self.relation_proof.len() + self.commitment.transmitted_len()
    }

    /// Serialize as `"JRP\x02" || proof_len_le || proof || JRC-envelope`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.transmitted_len());
        out.extend_from_slice(&PROOF_MAGIC);
        out.extend_from_slice(&(self.relation_proof.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.relation_proof);
        out.extend_from_slice(&self.commitment.to_bytes());
        out
    }

    /// Parse a bounded JRP v2 transcript and its embedded JRC envelope.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > crate::frame::MAX_STREAM_BYTES as usize {
            return Err(Error::TooLarge {
                len: bytes.len() as u64,
                max: crate::frame::MAX_STREAM_BYTES,
            });
        }
        if bytes.len() < PROOF_OVERHEAD + crate::jrc::ENVELOPE_OVERHEAD {
            return Err(Error::Truncated);
        }
        if bytes[..PROOF_MAGIC.len()] != PROOF_MAGIC {
            return Err(Error::BadMagic);
        }
        let proof_len =
            u32::from_le_bytes(bytes[4..8].try_into().map_err(|_| Error::Truncated)?) as usize;
        if proof_len > MAX_RELATION_PROOF_LEN {
            return Err(Error::TooLarge {
                len: proof_len as u64,
                max: MAX_RELATION_PROOF_LEN as u64,
            });
        }
        let proof_end = PROOF_OVERHEAD
            .checked_add(proof_len)
            .ok_or(Error::Lengths)?;
        if bytes.len().saturating_sub(proof_end) < crate::jrc::ENVELOPE_OVERHEAD {
            return Err(Error::Truncated);
        }
        let commitment = JrcCommitment::from_bytes(&bytes[proof_end..])?;
        Ok(Self {
            relation_proof: bytes[PROOF_OVERHEAD..proof_end].to_vec(),
            commitment,
        })
    }
}

/// Build and self-verify a JRP transcript using `system`.
pub fn prove<P: RelationProofSystem + ?Sized>(
    system: &P,
    ek: &JudgePublicKey,
    statement: &[u8],
    witness: &P::Witness,
    output: &[u8],
    nonce: &[u8; NONCE_LEN],
) -> Result<JrpProof> {
    let (commitment, opening) = commit_with_prover_opening(ek, output, nonce)?;
    let public = JrpPublicInput {
        judge_key: ek,
        statement,
        commitment: &commitment,
    };
    let relation_proof = system.prove(public, witness, output, &opening)?;
    if relation_proof.len() > MAX_RELATION_PROOF_LEN {
        return Err(Error::TooLarge {
            len: relation_proof.len() as u64,
            max: MAX_RELATION_PROOF_LEN as u64,
        });
    }
    if !system.verify(public, &relation_proof) {
        return Err(Error::InvalidProof);
    }
    let transcript = JrpProof {
        relation_proof,
        commitment,
    };
    if transcript.transmitted_len() > crate::frame::MAX_STREAM_BYTES as usize {
        return Err(Error::TooLarge {
            len: transcript.transmitted_len() as u64,
            max: crate::frame::MAX_STREAM_BYTES,
        });
    }
    Ok(transcript)
}

/// Verify the relation proof against its complete public input.
pub fn verify_ext<P: RelationProofSystem + ?Sized>(
    system: &P,
    ek: &JudgePublicKey,
    statement: &[u8],
    proof: &JrpProof,
) -> bool {
    crate::jrc::verify_ext(&proof.commitment.commitment, &proof.commitment.aux)
        && system.verify(
            JrpPublicInput {
                judge_key: ek,
                statement,
                commitment: &proof.commitment,
            },
            &proof.relation_proof,
        )
}

/// Verify a JRP transcript and recover its output with the judge key.
pub fn judge_recover<P: RelationProofSystem + ?Sized>(
    system: &P,
    dk: &JudgeSecretKey,
    statement: &[u8],
    proof: &JrpProof,
) -> Result<Vec<u8>> {
    let ek = dk.to_public();
    if !verify_ext(system, &ek, statement, proof) {
        return Err(Error::InvalidProof);
    }
    jrc_judge_recover(dk, &proof.commitment.commitment, &proof.commitment.aux)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jrc::{commit_with_ephemeral, keygen};

    // This transparent backend exists only to test composition mechanics. It
    // proves the relation correctly but is intentionally not zero knowledge.
    struct TransparentTestBackend;

    impl RelationProofSystem for TransparentTestBackend {
        type Witness = [u8];

        fn prove(
            &self,
            _public: JrpPublicInput<'_>,
            witness: &[u8],
            output: &[u8],
            opening: &JrcProverOpening,
        ) -> Result<Vec<u8>> {
            let mut proof = Vec::new();
            proof.extend_from_slice(&(witness.len() as u32).to_le_bytes());
            proof.extend_from_slice(&(output.len() as u32).to_le_bytes());
            proof.extend_from_slice(witness);
            proof.extend_from_slice(output);
            proof.extend_from_slice(opening.ephemeral_secret());
            proof.extend_from_slice(opening.nonce());
            Ok(proof)
        }

        fn verify(&self, public: JrpPublicInput<'_>, proof: &[u8]) -> bool {
            verify_transparent(public, proof)
        }
    }

    fn verify_transparent(public: JrpPublicInput<'_>, proof: &[u8]) -> bool {
        if proof.len() < 8 + 32 + NONCE_LEN {
            return false;
        }
        let witness_len = u32::from_le_bytes(match proof[0..4].try_into() {
            Ok(v) => v,
            Err(_) => return false,
        }) as usize;
        let output_len = u32::from_le_bytes(match proof[4..8].try_into() {
            Ok(v) => v,
            Err(_) => return false,
        }) as usize;
        let witness_end = match 8usize.checked_add(witness_len) {
            Some(v) => v,
            None => return false,
        };
        let output_end = match witness_end.checked_add(output_len) {
            Some(v) => v,
            None => return false,
        };
        if output_end.checked_add(32 + NONCE_LEN) != Some(proof.len()) {
            return false;
        }
        let witness = &proof[8..witness_end];
        let output = &proof[witness_end..output_end];
        let e_sk: [u8; 32] = match proof[output_end..output_end + 32].try_into() {
            Ok(v) => v,
            Err(_) => return false,
        };
        let nonce: [u8; NONCE_LEN] = match proof[output_end + 32..].try_into() {
            Ok(v) => v,
            Err(_) => return false,
        };

        let mut relation = blake3::Hasher::new();
        relation.update(public.statement);
        relation.update(witness);
        if relation.finalize().as_bytes() != output {
            return false;
        }
        commit_with_ephemeral(public.judge_key, output, &nonce, &e_sk)
            .is_ok_and(|expected| expected == *public.commitment)
    }

    fn output(statement: &[u8], witness: &[u8]) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(statement);
        h.update(witness);
        *h.finalize().as_bytes()
    }

    #[test]
    fn valid_relation_verifies_and_recovers() {
        let kp = keygen().expect("keygen");
        let statement = b"audit relation v1";
        let witness = b"private witness";
        let expected = output(statement, witness);
        let proof = prove(
            &TransparentTestBackend,
            &kp.ek,
            statement,
            witness,
            &expected,
            &[0x42; NONCE_LEN],
        )
        .expect("prove");
        assert!(verify_ext(
            &TransparentTestBackend,
            &kp.ek,
            statement,
            &proof
        ));
        assert_eq!(
            judge_recover(&TransparentTestBackend, &kp.dk, statement, &proof).expect("recover"),
            expected
        );
    }

    #[test]
    fn false_relation_cannot_be_constructed() {
        let kp = keygen().expect("keygen");
        let result = prove(
            &TransparentTestBackend,
            &kp.ek,
            b"x",
            b"w",
            b"not f(x,w)",
            &[0x42; NONCE_LEN],
        );
        assert!(matches!(result, Err(Error::InvalidProof)));
    }

    #[test]
    fn statement_key_and_transcript_tampering_are_rejected() {
        let kp = keygen().expect("keygen");
        let other = keygen().expect("other keygen");
        let statement = b"x";
        let witness = b"w";
        let expected = output(statement, witness);
        let proof = prove(
            &TransparentTestBackend,
            &kp.ek,
            statement,
            witness,
            &expected,
            &[7; NONCE_LEN],
        )
        .expect("prove");
        assert!(!verify_ext(
            &TransparentTestBackend,
            &kp.ek,
            b"other",
            &proof
        ));
        assert!(matches!(
            judge_recover(&TransparentTestBackend, &kp.dk, b"other", &proof),
            Err(Error::InvalidProof)
        ));
        assert!(!verify_ext(
            &TransparentTestBackend,
            &other.ek,
            statement,
            &proof
        ));

        let mut bytes = proof.to_bytes();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        let tampered = JrpProof::from_bytes(&bytes).expect("structurally valid");
        assert!(!verify_ext(
            &TransparentTestBackend,
            &kp.ek,
            statement,
            &tampered
        ));
    }

    #[test]
    fn wire_format_is_bounded_and_round_trips() {
        let kp = keygen().expect("keygen");
        let statement = b"x";
        let witness = b"w";
        let expected = output(statement, witness);
        let proof = prove(
            &TransparentTestBackend,
            &kp.ek,
            statement,
            witness,
            &expected,
            &[9; NONCE_LEN],
        )
        .expect("prove");
        let bytes = proof.to_bytes();
        assert_eq!(bytes.len(), proof.transmitted_len());
        assert_eq!(JrpProof::from_bytes(&bytes).expect("parse"), proof);
        assert!(JrpProof::from_bytes(&bytes[4..]).is_err());

        let mut impossible = bytes.clone();
        impossible[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(JrpProof::from_bytes(&impossible).is_err());
    }
}
