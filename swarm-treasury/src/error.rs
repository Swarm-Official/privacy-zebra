//! The one error type this crate returns.
//!
//! Every message is written for the person holding the device: it says what was refused and why,
//! and it never contains key material.

use std::fmt;

/// The result of a custody operation.
pub type Result<T> = std::result::Result<T, Error>;

/// Something the tool refused, or could not do.
#[derive(Debug)]
pub struct Error {
    message: String,
}

impl Error {
    /// Builds an error from anything printable.
    pub fn new(message: impl Into<String>) -> Self {
        Error {
            message: message.into(),
        }
    }

    /// The message, without any trailing context.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

impl From<String> for Error {
    fn from(message: String) -> Self {
        Error::new(message)
    }
}

impl From<&str> for Error {
    fn from(message: &str) -> Self {
        Error::new(message)
    }
}

/// Builds an [`Error`] with `format!` syntax.
#[macro_export]
macro_rules! refuse {
    ($($argument:tt)*) => {
        $crate::error::Error::new(format!($($argument)*))
    };
}
