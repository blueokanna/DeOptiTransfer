use alloc::string::String;
use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    Empty,
    TooLarge { len: u64, max: u64 },
    Meta,
    Truncated,
    BadMagic,
    Compression(u8),
    Lengths,
    InvalidStream,
    InvalidFrameSize { actual: usize, expected: usize },
    SequenceExhausted,
    CorruptFrame,
    StreamConflict,
    GzipIncomplete,
    GzipSize,
    Inflate { msg: String },
    Codec { msg: String },
    NoCompression,
    NoEncryption,
    Crypto,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Empty => write!(f, "empty payload"),
            Error::TooLarge { len, max } => write!(f, "{len} bytes exceeds {max}"),
            Error::Meta => write!(f, "metadata too long"),
            Error::Truncated => write!(f, "truncated header"),
            Error::BadMagic => write!(f, "invalid magic"),
            Error::Compression(m) => write!(f, "unsupported compression {m}"),
            Error::Lengths => write!(f, "length mismatch"),
            Error::InvalidStream => write!(f, "inconsistent stream header"),
            Error::InvalidFrameSize { actual, expected } => {
                write!(f, "invalid frame size {actual}, expected {expected}")
            }
            Error::SequenceExhausted => write!(f, "frame sequence exhausted"),
            Error::CorruptFrame => write!(f, "frame integrity check failed"),
            Error::StreamConflict => write!(f, "receiver is locked to another stream"),
            Error::GzipIncomplete => write!(f, "gzip payload incomplete"),
            Error::GzipSize => write!(f, "gzip size mismatch"),
            Error::Inflate { msg } => write!(f, "inflate: {msg}"),
            Error::Codec { msg } => write!(f, "codec: {msg}"),
            Error::NoCompression => write!(f, "compression disabled in no_std build"),
            Error::NoEncryption => write!(f, "encryption disabled in this build"),
            Error::Crypto => write!(f, "authenticated decryption failed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;
