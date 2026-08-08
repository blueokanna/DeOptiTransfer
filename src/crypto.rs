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

    #[cfg(feature = "encryption")]
    pub fn from_password(password: &[u8], salt: &[u8; NONCE_LEN]) -> Result<Self> {
        use argon2::{Algorithm, Argon2, Params, Version};

        const MEMORY_KIB: u32 = 19 * 1024;
        const ITERATIONS: u32 = 2;
        let params = Params::new(MEMORY_KIB, ITERATIONS, 1, Some(32)).map_err(|_| Error::Crypto)?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key = [0u8; 32];
        argon
            .hash_password_into(password, salt, &mut key)
            .map_err(|_| Error::Crypto)?;
        Ok(Self(key))
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

#[cfg(feature = "encryption")]
impl Drop for EncryptionKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
    }
}

impl core::fmt::Debug for EncryptionKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("EncryptionKey([redacted])")
    }
}

#[cfg(all(feature = "encryption", feature = "std"))]
pub fn random_nonce() -> Result<[u8; NONCE_LEN]> {
    let mut n = [0u8; NONCE_LEN];
    getrandom::fill(&mut n).map_err(|_| Error::Crypto)?;
    Ok(n)
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
    let key = Key::from(*key);
    let cipher = XChaCha20Poly1305::new(&key);
    let n = XNonce::from(*nonce);
    cipher
        .encrypt(
            &n,
            Payload {
                msg: plaintext,
                aad,
            },
        )
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
    let key = Key::from(*key);
    let cipher = XChaCha20Poly1305::new(&key);
    let n = XNonce::from(*nonce);
    cipher
        .decrypt(
            &n,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::Crypto)
}
