use core::fmt;

/// Trident errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Input had the wrong length.
    InvalidLength,
    /// An encapsulation key component failed validation.
    InvalidKey,
}

impl core::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength => f.write_str("invalid length"),
            Self::InvalidKey => f.write_str("invalid key"),
        }
    }
}
