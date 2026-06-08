//! Minimal error type. We avoid pulling in `anyhow`/`thiserror` to keep the
//! dependency surface to `windows-sys` only.

use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct Error {
    context: String,
    hr: Option<i32>,
}

impl Error {
    pub fn msg(context: impl Into<String>) -> Self {
        Error { context: context.into(), hr: None }
    }

    pub fn with_hr(context: impl Into<String>, hr: i32) -> Self {
        Error { context: context.into(), hr: Some(hr) }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.hr {
            Some(hr) => write!(f, "{}: HRESULT=0x{:08X}", self.context, hr as u32),
            None => write!(f, "{}", self.context),
        }
    }
}

impl std::error::Error for Error {}

/// SUCCEEDED(hr) in Win32 terms: the sign bit clear means success.
#[inline]
pub fn succeeded(hr: i32) -> bool {
    hr >= 0
}

/// Convert a failing HRESULT into an `Err`, otherwise `Ok(())`.
#[inline]
pub fn check_hr(hr: i32, what: &str) -> Result<()> {
    if succeeded(hr) {
        Ok(())
    } else {
        Err(Error::with_hr(what.to_string(), hr))
    }
}
