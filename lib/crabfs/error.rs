use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    BufferTooSmall { expected: usize, actual: usize },
    InvalidMagic { expected: u32, actual: u32 },
    UnsupportedVersion(u32),
    InvalidField { field: &'static str, value: u64 },
    CrcMismatch { what: &'static str },
    InvalidInt(core::num::TryFromIntError),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooSmall { expected, actual } => {
                write!(f, "buffer too small: expected at least {expected} bytes, got {actual}")
            }
            Self::InvalidMagic { expected, actual } => {
                write!(f, "invalid magic: expected 0x{expected:08x}, got 0x{actual:08x}")
            }
            Self::UnsupportedVersion(version) => write!(f, "unsupported version: {version}"),
            Self::InvalidField { field, value } => {
                write!(f, "invalid field {field}: {value}")
            }
            Self::CrcMismatch { what } => write!(f, "crc mismatch in {what}"),
            Self::InvalidInt(err) => write!(f, "invalid integer conversion: {err}"),
        }
    }
}

impl core::error::Error for ParseError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceError {
    Io,
    ShortRead { expected: usize, actual: usize },
    ShortWrite { expected: usize, actual: usize },
    OutOfRange,
}

impl fmt::Display for DeviceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io => f.write_str("I/O error"),
            Self::ShortRead { expected, actual } => {
                write!(f, "short read: expected {expected} bytes, got {actual}")
            }
            Self::ShortWrite { expected, actual } => {
                write!(f, "short write: expected {expected} bytes, got {actual}")
            }
            Self::OutOfRange => f.write_str("offset out of range"),
        }
    }
}

impl core::error::Error for DeviceError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadError {
    Device(DeviceError),
    Parse(ParseError),
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Device(err) => fmt::Display::fmt(err, f),
            Self::Parse(err) => fmt::Display::fmt(err, f),
        }
    }
}

impl core::error::Error for ReadError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteError {
    Device(DeviceError),
    Parse(ParseError),
    TryFromInt(core::num::TryFromIntError),
}

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Device(err) => fmt::Display::fmt(err, f),
            Self::Parse(err) => fmt::Display::fmt(err, f),
            Self::TryFromInt(err) => write!(f, "invalid integer conversion: {err}"),
        }
    }
}

impl core::error::Error for WriteError {}

impl From<DeviceError> for ReadError {
    fn from(value: DeviceError) -> Self {
        Self::Device(value)
    }
}

impl From<ParseError> for ReadError {
    fn from(value: ParseError) -> Self {
        Self::Parse(value)
    }
}

impl From<DeviceError> for WriteError {
    fn from(value: DeviceError) -> Self {
        Self::Device(value)
    }
}

impl From<ParseError> for WriteError {
    fn from(value: ParseError) -> Self {
        Self::Parse(value)
    }
}

impl From<core::num::TryFromIntError> for WriteError {
    fn from(value: core::num::TryFromIntError) -> Self {
        Self::TryFromInt(value)
    }
}
