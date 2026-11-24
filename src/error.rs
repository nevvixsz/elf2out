//! Error type used everywhere in the converter.
//!
//! The goal here is not to be clever, but to produce messages that tell the
//! user what to change in the Zig build command when something goes wrong.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    Io,
    Format,
    Unsupported,
    Layout,
    Relocation,
    Usage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorKind,
    pub message: String,
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn io(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Io, message)
    }

    pub fn format(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Format, message)
    }

    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Unsupported, message)
    }

    pub fn layout(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Layout, message)
    }

    pub fn relocation(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Relocation, message)
    }

    pub fn usage(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Usage, message)
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tag = match self.kind {
            ErrorKind::Io => "I/O error",
            ErrorKind::Format => "malformed input",
            ErrorKind::Unsupported => "unsupported feature",
            ErrorKind::Layout => "layout error",
            ErrorKind::Relocation => "relocation error",
            ErrorKind::Usage => "usage error",
        };
        write!(f, "{}: {}", tag, self.message)
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::io(format!("{}", err))
    }
}

/// Small helper macros so the rest of the code reads like a spec.
#[macro_export]
macro_rules! bail {
    ($kind:expr, $($arg:tt)*) => {
        return ::std::result::Result::Err($crate::error::Error::new(
            $kind,
            ::std::format!($($arg)*),
        ))
    };
}

#[macro_export]
macro_rules! ensure {
    ($cond:expr, $kind:expr, $($arg:tt)*) => {
        if !($cond) {
            $crate::bail!($kind, $($arg)*);
        }
    };
}
