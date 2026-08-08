#[cfg(feature = "encryption")]
use alloc::vec::Vec;

#[cfg(feature = "encryption")]
use crate::error::{Error, Result};

pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;

pub struct EncryptionKey([u8; 32]);

impl EncryptionKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_password(password: &[u8]) -> Self {
        Self(blake3::derive_key("deopti-transfer container v2", password))
    }

    #[cfg(feature = "encryption")]
    pub(crate) fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Clone for EncryptionKey {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl core::fmt::Debug for EncryptionKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("EncryptionKey([redacted])")
    }
}

#[cfg(all(feature = "encryption", feature = "std"))]
pub fn random_nonce() -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    getrandom::fill(&mut n).expect("OS randomness unavailable");
    n
}

#[cfg(feature = "encryption")]
pub fn encrypt(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    use chacha20poly1305::aead::{Aead, Payload};
    use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let n = XNonce::from_slice(nonce);
    cipher
        .encrypt(n, Payload { msg: plaintext, aad })
        .map_err(|_| Error::Crypto)
}

#[cfg(feature = "encryption")]
pub fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    use chacha20poly1305::aead::{Aead, Payload};
    use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let n = XNonce::from_slice(nonce);
    cipher
        .decrypt(n, Payload { msg: ciphertext, aad })
        .map_err(|_| Error::Crypto)
}
