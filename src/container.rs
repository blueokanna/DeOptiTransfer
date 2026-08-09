//! The DCF3 file container: filename + media type + bytes + BLAKE3 digest,
//! with gzip and optional authenticated encryption.
//!
//! [`pack_file`] / [`unpack_file`] are the plain path;
//! [`pack_file_encrypted`] / [`unpack_file_with_key`] add
//! XChaCha20-Poly1305 AEAD (feature `encryption`). Every length field from
//! the wire is validated, gzip inflate is hard-bounded, and filenames are
//! sanitised on receipt.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use rustbinary::Config;
use serde::{Deserialize, Serialize};

use crate::crypto::NONCE_LEN;
#[cfg(feature = "encryption")]
use crate::crypto::{decrypt, encrypt, EncryptionKey, TAG_LEN};
use crate::error::{Error, Result};
use crate::frame::MAX_FILE_BYTES;
#[cfg(feature = "encryption")]
use crate::frame::MAX_STREAM_BYTES;
#[cfg(feature = "encryption")]
use crate::jrc::{
    commit, judge_recover, JrcCommitment, JudgePublicKey, JudgeSecretKey, MAX_MESSAGE_LEN,
};

pub const FILE_HEADER_LEN: usize = 73;
const FILE_MAGIC: [u8; 4] = [0x44, 0x43, 0x46, 0x33];
const FLAG_GZIP: u8 = 1;
const FLAG_CRYPT: u8 = 2;
#[cfg(feature = "std")]
const GZIP_MIN: usize = 768;
#[cfg(feature = "std")]
const GZIP_ROOM: usize = 64;
#[cfg(feature = "std")]
const GZIP_MIN_LEN: usize = 18;
const DEFAULT_NAME: &str = "transfer.bin";
const DEFAULT_MIME: &str = "application/octet-stream";

const CFG: Config = Config::legacy()
    .with_little_endian()
    .with_fixint_encoding()
    .reject_trailing_bytes()
    .with_limit(128);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    None,
    Gzip,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackedOpticalFile {
    pub container: Vec<u8>,
    pub compression: Compression,
    pub encrypted: bool,
    pub original_size: usize,
    pub transmitted_size: usize,
}

/// A file packed for judge-recoverable optical transfer (`JRC` mode).
///
/// `envelope` is the serialized JRC transcript
/// (`magic ‖ c ‖ aux`) that flows through the fountain stream unchanged.
/// An external observer reconstructing the stream sees only the hiding
/// commitment and ciphertext; the designated judge recovers the plaintext
/// DCF3 container with [`unpack_file_jrc`] and verifies it end to end.
#[cfg(feature = "encryption")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JrcPackedFile {
    pub envelope: Vec<u8>,
    pub original_size: usize,
    pub transmitted_size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpticalFile {
    pub name: String,
    pub mime_type: String,
    pub bytes: Vec<u8>,
    pub digest: [u8; 32],
    pub compression: Compression,
    pub encrypted: bool,
    pub transmitted_size: usize,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct Header {
    magic: [u8; 4],
    flags: u8,
    name_len: u16,
    type_len: u16,
    file_len: u32,
    xmit_len: u32,
    digest: [u8; 32],
    nonce: [u8; NONCE_LEN],
}

/// Pack a file into a self-describing DCF3 container.
///
/// gzip is applied only when it wins by a margin and the media type is not
/// already compressed. Returns `Error::Empty` / `Error::TooLarge` for
/// out-of-range inputs.
pub fn pack_file(name: &str, mime_type: &str, bytes: &[u8]) -> Result<PackedOpticalFile> {
    let (name_bytes, type_bytes, plain, compression, digest) = prepare(name, mime_type, bytes)?;
    let flags = if compression == Compression::Gzip {
        FLAG_GZIP
    } else {
        0
    };
    let container = assemble(
        flags,
        &name_bytes,
        &type_bytes,
        &plain,
        bytes.len(),
        &digest,
        &[0u8; NONCE_LEN],
    )?;
    Ok(PackedOpticalFile {
        container,
        compression,
        encrypted: false,
        original_size: bytes.len(),
        transmitted_size: plain.len(),
    })
}

#[cfg(feature = "encryption")]
pub fn pack_file_encrypted(
    name: &str,
    mime_type: &str,
    bytes: &[u8],
    key: &EncryptionKey,
    nonce: &[u8; NONCE_LEN],
) -> Result<PackedOpticalFile> {
    let (name_bytes, type_bytes, plain, compression, digest) = prepare(name, mime_type, bytes)?;
    let flags = (if compression == Compression::Gzip {
        FLAG_GZIP
    } else {
        0
    }) | FLAG_CRYPT;
    let aad = aad(
        flags,
        &name_bytes,
        &type_bytes,
        bytes.len(),
        plain.len() + TAG_LEN,
        &digest,
    );
    let ciphertext = encrypt(key.bytes(), nonce, &plain, &aad)?;
    let container = assemble(
        flags,
        &name_bytes,
        &type_bytes,
        &ciphertext,
        bytes.len(),
        &digest,
        nonce,
    )?;
    Ok(PackedOpticalFile {
        container,
        compression,
        encrypted: true,
        original_size: bytes.len(),
        transmitted_size: ciphertext.len(),
    })
}

#[cfg(feature = "encryption")]
pub fn pack_file_encrypted_with_password(
    name: &str,
    mime_type: &str,
    bytes: &[u8],
    password: &[u8],
    nonce: &[u8; NONCE_LEN],
) -> Result<PackedOpticalFile> {
    let key = EncryptionKey::from_password(password, nonce)?;
    pack_file_encrypted(name, mime_type, bytes, &key, nonce)
}

type Prepared = (Vec<u8>, Vec<u8>, Vec<u8>, Compression, [u8; 32]);

fn prepare(name: &str, mime_type: &str, bytes: &[u8]) -> Result<Prepared> {
    if bytes.is_empty() {
        return Err(Error::Empty);
    }
    if (bytes.len() as u64) > MAX_FILE_BYTES {
        return Err(Error::TooLarge {
            len: bytes.len() as u64,
            max: MAX_FILE_BYTES,
        });
    }
    let name_bytes = safe_file_name(name).into_bytes();
    let type_bytes = normalize_mime_type(mime_type)?.into_bytes();
    if name_bytes.len() > u16::MAX as usize || type_bytes.len() > u16::MAX as usize {
        return Err(Error::Meta);
    }
    let digest = *blake3::hash(bytes).as_bytes();

    #[cfg(feature = "std")]
    let compressed: Option<Vec<u8>> =
        if bytes.len() >= GZIP_MIN && !is_precompressed_type(mime_type) {
            let c = gzip(bytes)?;
            (c.len() + GZIP_ROOM < bytes.len()).then_some(c)
        } else {
            None
        };
    #[cfg(not(feature = "std"))]
    let compressed: Option<Vec<u8>> = None;

    let compression = if compressed.is_some() {
        Compression::Gzip
    } else {
        Compression::None
    };
    let plain = match compressed {
        Some(c) => c,
        None => bytes.to_vec(),
    };
    Ok((name_bytes, type_bytes, plain, compression, digest))
}

fn assemble(
    flags: u8,
    name_bytes: &[u8],
    type_bytes: &[u8],
    transmitted: &[u8],
    file_len: usize,
    digest: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>> {
    let header = Header {
        magic: FILE_MAGIC,
        flags,
        name_len: name_bytes.len() as u16,
        type_len: type_bytes.len() as u16,
        file_len: file_len as u32,
        xmit_len: transmitted.len() as u32,
        digest: *digest,
        nonce: *nonce,
    };
    let mut container = CFG
        .serialize(&header)
        .map_err(|e| Error::Codec { msg: e.to_string() })?;
    container.extend_from_slice(name_bytes);
    container.extend_from_slice(type_bytes);
    container.extend_from_slice(transmitted);
    Ok(container)
}

/// Unpack and verify a DCF3 container, recovering the original file.
///
/// Every field is validated before use; gzip inflate is hard-bounded. An
/// encrypted container requires `unpack_file_with_key` (or the password
/// variant) and returns `Error::NoEncryption` here.
pub fn unpack_file(container: &[u8]) -> Result<OpticalFile> {
    unpack_impl(container, None)
}

#[cfg(feature = "encryption")]
pub fn unpack_file_with_key(container: &[u8], key: &EncryptionKey) -> Result<OpticalFile> {
    unpack_impl(container, Some(key.bytes()))
}

#[cfg(feature = "encryption")]
pub fn unpack_file_with_password(container: &[u8], password: &[u8]) -> Result<OpticalFile> {
    let header = read_header(container)?;
    if header.flags & FLAG_CRYPT == 0 {
        return Err(Error::NoEncryption);
    }
    validate_layout(&header, container.len())?;
    let key = EncryptionKey::from_password(password, &header.nonce)?;
    unpack_impl(container, Some(key.bytes()))
}

/// Pack a file for judge-recoverable optical transfer.
///
/// The file is first packed into a plaintext DCF3 container, then committed
/// with the JRC primitive against the judge's public key. The returned
/// `envelope` is fed to a [`Sender`](crate::session::Sender) as the
/// transmitted container. Co-receiving cameras see only the hiding
/// commitment and ciphertext; the judge recovers the container with
/// [`unpack_file_jrc`].
///
/// A random nonce is recommended for transcript unlinkability. JRC derives a
/// fresh key from a fresh ephemeral X25519 secret on every call, so nonce
/// uniqueness is not required for AEAD safety in this API.
#[cfg(feature = "encryption")]
pub fn pack_file_jrc(
    name: &str,
    mime_type: &str,
    bytes: &[u8],
    judge_pk: &JudgePublicKey,
    nonce: &[u8; NONCE_LEN],
) -> Result<JrcPackedFile> {
    let inner = pack_file(name, mime_type, bytes)?;
    if inner.container.len() > MAX_MESSAGE_LEN {
        return Err(Error::TooLarge {
            len: inner.container.len() as u64,
            max: MAX_MESSAGE_LEN as u64,
        });
    }
    let committed = commit(judge_pk, &inner.container, nonce)?;
    let envelope = committed.to_bytes();
    if envelope.len() as u64 > MAX_STREAM_BYTES {
        return Err(Error::TooLarge {
            len: envelope.len() as u64,
            max: MAX_STREAM_BYTES,
        });
    }
    let transmitted_size = envelope.len();
    Ok(JrcPackedFile {
        envelope,
        original_size: bytes.len(),
        transmitted_size,
    })
}

/// Recover a file from a judge-recoverable envelope with the judge's secret
/// key.
///
/// The JRC binding check and the DCF3 digest both verify the recovered
/// container before any metadata is trusted: a wrong judge key, a tampered
/// envelope, or a single flipped byte is rejected.
#[cfg(feature = "encryption")]
pub fn unpack_file_jrc(envelope: &[u8], dk: &JudgeSecretKey) -> Result<OpticalFile> {
    let committed = JrcCommitment::from_bytes(envelope)?;
    let container = judge_recover(dk, &committed.commitment, &committed.aux)?;
    unpack_file(&container)
}

fn unpack_impl(container: &[u8], key: Option<&[u8; 32]>) -> Result<OpticalFile> {
    #[cfg(not(feature = "encryption"))]
    let _ = key;
    let h = read_header(container)?;
    let compressed = h.flags & FLAG_GZIP != 0;
    let encrypted = h.flags & FLAG_CRYPT != 0;

    validate_layout(&h, container.len())?;
    let data_offset = FILE_HEADER_LEN + h.name_len as usize + h.type_len as usize;
    let name_bytes = &container[FILE_HEADER_LEN..FILE_HEADER_LEN + h.name_len as usize];
    let type_bytes = &container[FILE_HEADER_LEN + h.name_len as usize..data_offset];
    let transmitted = &container[data_offset..];

    if encrypted {
        #[cfg(not(feature = "encryption"))]
        {
            return Err(Error::NoEncryption);
        }
    }

    let plain: Vec<u8> = if encrypted {
        #[cfg(feature = "encryption")]
        {
            let key = key.ok_or(Error::NoEncryption)?;
            let aad = aad(
                h.flags,
                name_bytes,
                type_bytes,
                h.file_len as usize,
                h.xmit_len as usize,
                &h.digest,
            );
            decrypt(key, &h.nonce, transmitted, &aad)?
        }
        #[cfg(not(feature = "encryption"))]
        {
            unreachable!("encrypted containers are rejected above without the encryption feature")
        }
    } else {
        transmitted.to_vec()
    };

    let bytes = if compressed {
        #[cfg(feature = "std")]
        {
            if plain.len() < GZIP_MIN_LEN {
                return Err(Error::GzipIncomplete);
            }
            let t = &plain[plain.len() - 4..];
            if u32::from_le_bytes([t[0], t[1], t[2], t[3]]) != h.file_len {
                return Err(Error::GzipSize);
            }
            let out = gunzip(&plain, h.file_len as usize)?;
            if out.len() != h.file_len as usize {
                return Err(Error::Inflate {
                    msg: "recovered length mismatch".into(),
                });
            }
            out
        }
        #[cfg(not(feature = "std"))]
        {
            return Err(Error::NoCompression);
        }
    } else {
        plain
    };

    if bytes.len() != h.file_len as usize {
        return Err(Error::Lengths);
    }
    if blake3::hash(&bytes).as_bytes() != &h.digest {
        return Err(Error::Crypto);
    }

    let mime = core::str::from_utf8(type_bytes).map_err(|_| Error::Meta)?;
    let mime_type = normalize_mime_type(mime)?;

    Ok(OpticalFile {
        name: safe_file_name(&String::from_utf8_lossy(name_bytes)),
        mime_type,
        bytes,
        digest: h.digest,
        compression: if compressed {
            Compression::Gzip
        } else {
            Compression::None
        },
        encrypted,
        transmitted_size: h.xmit_len as usize,
    })
}

fn read_header(container: &[u8]) -> Result<Header> {
    if container.len() < FILE_HEADER_LEN {
        return Err(Error::Truncated);
    }
    let header: Header = CFG
        .deserialize(&container[..FILE_HEADER_LEN])
        .map_err(|e| Error::Codec { msg: e.to_string() })?;
    if header.magic != FILE_MAGIC || header.flags & !(FLAG_GZIP | FLAG_CRYPT) != 0 {
        return Err(Error::BadMagic);
    }
    Ok(header)
}

fn validate_layout(header: &Header, container_len: usize) -> Result<()> {
    let encrypted = header.flags & FLAG_CRYPT != 0;
    let data_offset = FILE_HEADER_LEN + header.name_len as usize + header.type_len as usize;
    let max_xmit_len = MAX_FILE_BYTES
        + if encrypted {
            crate::crypto::TAG_LEN as u64
        } else {
            0
        };
    if header.file_len == 0
        || header.file_len as u64 > MAX_FILE_BYTES
        || header.xmit_len == 0
        || header.xmit_len as u64 > max_xmit_len
        || data_offset + header.xmit_len as usize != container_len
    {
        return Err(Error::Lengths);
    }
    Ok(())
}

#[cfg(feature = "encryption")]
fn aad(
    flags: u8,
    name_bytes: &[u8],
    type_bytes: &[u8],
    file_len: usize,
    xmit_len: usize,
    digest: &[u8; 32],
) -> Vec<u8> {
    let mut a = Vec::with_capacity(1 + 2 + 2 + 4 + 4 + 32 + name_bytes.len() + type_bytes.len());
    a.push(flags);
    a.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
    a.extend_from_slice(&(type_bytes.len() as u16).to_le_bytes());
    a.extend_from_slice(&(file_len as u32).to_le_bytes());
    a.extend_from_slice(&(xmit_len as u32).to_le_bytes());
    a.extend_from_slice(digest);
    a.extend_from_slice(name_bytes);
    a.extend_from_slice(type_bytes);
    a
}

pub fn verify_file(file: &OpticalFile) -> bool {
    blake3::hash(&file.bytes).as_bytes() == &file.digest
}

pub fn safe_file_name(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or("");
    let mut cleaned = base
        .chars()
        .filter(|c| !is_control(*c) && !is_bidi_control(*c))
        .map(|c| {
            if matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*') {
                '_'
            } else {
                c
            }
        })
        .collect::<String>()
        .trim()
        .trim_end_matches(['.', ' '])
        .to_string();
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        DEFAULT_NAME.to_string()
    } else {
        let stem = cleaned.split('.').next().unwrap_or("");
        if is_windows_device_name(stem) {
            cleaned.insert(0, '_');
        }
        cleaned
    }
}

#[inline]
fn is_control(c: char) -> bool {
    let v = c as u32;
    v <= 0x1f || v == 0x7f
}

#[inline]
fn is_bidi_control(c: char) -> bool {
    matches!(
        c as u32,
        0x061c | 0x200e | 0x200f | 0x202a..=0x202e | 0x2066..=0x2069
    )
}

fn is_windows_device_name(stem: &str) -> bool {
    let upper = stem.to_ascii_uppercase();
    matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (upper.len() == 4
            && (upper.starts_with("COM") || upper.starts_with("LPT"))
            && matches!(upper.as_bytes()[3], b'1'..=b'9'))
}

fn normalize_mime_type(mime_type: &str) -> Result<String> {
    let value = mime_type.trim();
    if value.is_empty() {
        return Ok(DEFAULT_MIME.to_string());
    }
    if !value.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        return Err(Error::Meta);
    }
    let media = value.split(';').next().unwrap_or("").trim();
    let Some((type_name, subtype)) = media.split_once('/') else {
        return Err(Error::Meta);
    };
    if type_name.is_empty()
        || subtype.is_empty()
        || !type_name.bytes().all(is_mime_token_byte)
        || !subtype.bytes().all(is_mime_token_byte)
    {
        return Err(Error::Meta);
    }
    Ok(value.to_string())
}

#[inline]
fn is_mime_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

pub fn is_precompressed_type(mime_type: &str) -> bool {
    let media = mime_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if let Some(subtype) = media.strip_prefix("image/") {
        return !matches!(
            subtype,
            "bmp" | "x-ms-bmp" | "svg+xml" | "tiff" | "x-icon" | "vnd.microsoft.icon"
        );
    }
    if let Some(subtype) = media.strip_prefix("audio/") {
        return !matches!(
            subtype,
            "wav" | "x-wav" | "wave" | "vnd.wave" | "aiff" | "x-aiff" | "basic" | "l16"
        );
    }
    if media.starts_with("video/")
        || media.starts_with("application/vnd.openxmlformats-officedocument.")
        || media.starts_with("application/vnd.oasis.opendocument.")
        || media.ends_with("+zip")
    {
        return true;
    }
    matches!(
        media.as_str(),
        "application/gzip"
            | "application/java-archive"
            | "application/vnd.rar"
            | "application/x-7z-compressed"
            | "application/x-brotli"
            | "application/x-bzip"
            | "application/x-bzip2"
            | "application/x-gzip"
            | "application/x-lzma"
            | "application/x-rar-compressed"
            | "application/x-xz"
            | "application/x-zip-compressed"
            | "application/zip"
            | "application/zstd"
    )
}

#[cfg(feature = "std")]
fn gzip(bytes: &[u8]) -> Result<Vec<u8>> {
    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes).map_err(|e| Error::Inflate {
        msg: format!("compress: {e}"),
    })?;
    encoder.finish().map_err(|e| Error::Inflate {
        msg: format!("compress: {e}"),
    })
}

#[cfg(feature = "std")]
fn gunzip(bytes: &[u8], max_bytes: usize) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut decoder = flate2::read::GzDecoder::new(bytes);
    let mut out = Vec::new();
    let mut buf = [0u8; 32 * 1024];
    loop {
        let n = decoder
            .read(&mut buf)
            .map_err(|e| Error::Inflate { msg: e.to_string() })?;
        if n == 0 {
            break;
        }
        if out.len() + n > max_bytes {
            return Err(Error::Inflate {
                msg: "expands past declared length".into(),
            });
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}
