use alloc::string::{String, ToString};
use alloc::vec::Vec;
use rustbinary::Config;
use serde::{Deserialize, Serialize};

#[cfg(feature = "encryption")]
use crate::crypto::{decrypt, encrypt, EncryptionKey, TAG_LEN};
use crate::crypto::NONCE_LEN;
use crate::error::{Error, Result};
use crate::frame::MAX_FILE_BYTES;

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

pub fn pack_file(name: &str, mime_type: &str, bytes: &[u8]) -> Result<PackedOpticalFile> {
    let (name_bytes, type_bytes, plain, compression, digest) = prepare(name, mime_type, bytes)?;
    let flags = if compression == Compression::Gzip { FLAG_GZIP } else { 0 };
    let container = assemble(flags, &name_bytes, &type_bytes, &plain, bytes.len(), &digest, &[0u8; NONCE_LEN])?;
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
    let flags = (if compression == Compression::Gzip { FLAG_GZIP } else { 0 }) | FLAG_CRYPT;
    let aad = aad(flags, &name_bytes, &type_bytes, bytes.len(), plain.len() + TAG_LEN, &digest);
    let ciphertext = encrypt(key.bytes(), nonce, &plain, &aad)?;
    let container = assemble(flags, &name_bytes, &type_bytes, &ciphertext, bytes.len(), &digest, nonce)?;
    Ok(PackedOpticalFile {
        container,
        compression,
        encrypted: true,
        original_size: bytes.len(),
        transmitted_size: ciphertext.len(),
    })
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
    let type_bytes = if mime_type.is_empty() {
        b"application/octet-stream".to_vec()
    } else {
        mime_type.as_bytes().to_vec()
    };
    if name_bytes.len() > u16::MAX as usize || type_bytes.len() > u16::MAX as usize {
        return Err(Error::Meta);
    }
    let digest = *blake3::hash(bytes).as_bytes();

    #[cfg(feature = "std")]
    let compressed: Option<Vec<u8>> = if bytes.len() >= GZIP_MIN && !is_precompressed_type(mime_type)
    {
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
        .map_err(|e| Error::Codec {
            msg: e.to_string(),
        })?;
    container.extend_from_slice(name_bytes);
    container.extend_from_slice(type_bytes);
    container.extend_from_slice(transmitted);
    Ok(container)
}

pub fn unpack_file(container: &[u8]) -> Result<OpticalFile> {
    unpack_impl(container, None)
}

#[cfg(feature = "encryption")]
pub fn unpack_file_with_key(container: &[u8], key: &EncryptionKey) -> Result<OpticalFile> {
    unpack_impl(container, Some(key.bytes()))
}

fn unpack_impl(container: &[u8], key: Option<&[u8; 32]>) -> Result<OpticalFile> {
    #[cfg(not(feature = "encryption"))]
    let _ = key;
    if container.len() < FILE_HEADER_LEN {
        return Err(Error::Truncated);
    }
    let h: Header = CFG
        .deserialize(&container[..FILE_HEADER_LEN])
        .map_err(|e| Error::Codec {
            msg: e.to_string(),
        })?;
    if h.magic != FILE_MAGIC {
        return Err(Error::BadMagic);
    }
    if h.flags & !(FLAG_GZIP | FLAG_CRYPT) != 0 {
        return Err(Error::BadMagic);
    }
    let compressed = h.flags & FLAG_GZIP != 0;
    let encrypted = h.flags & FLAG_CRYPT != 0;

    let data_offset = FILE_HEADER_LEN + h.name_len as usize + h.type_len as usize;
    if h.file_len == 0
        || (h.file_len as u64) > MAX_FILE_BYTES
        || h.xmit_len == 0
        || (h.xmit_len as u64) > MAX_FILE_BYTES
        || data_offset + h.xmit_len as usize != container.len()
    {
        return Err(Error::Lengths);
    }
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
            let aad = aad(h.flags, name_bytes, type_bytes, h.file_len as usize, h.xmit_len as usize, &h.digest);
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

    if blake3::hash(&bytes).as_bytes() != &h.digest {
        return Err(Error::Crypto);
    }

    let mime = String::from_utf8_lossy(type_bytes);
    let mime_type = if mime.is_empty() {
        "application/octet-stream".to_string()
    } else {
        mime.into_owned()
    };

    Ok(OpticalFile {
        name: safe_file_name(&String::from_utf8_lossy(name_bytes)),
        mime_type,
        bytes,
        digest: h.digest,
        compression: if compressed { Compression::Gzip } else { Compression::None },
        encrypted,
        transmitted_size: h.xmit_len as usize,
    })
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
    let cleaned = base
        .chars()
        .filter(|c| !is_control(*c))
        .collect::<String>()
        .trim()
        .to_string();
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        DEFAULT_NAME.to_string()
    } else {
        cleaned
    }
}

#[inline]
fn is_control(c: char) -> bool {
    let v = c as u32;
    v <= 0x1f || v == 0x7f
}

pub fn is_precompressed_type(mime_type: &str) -> bool {
    let media = mime_type.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
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
        let n = decoder.read(&mut buf).map_err(|e| Error::Inflate {
            msg: e.to_string(),
        })?;
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
