//! Error and result types for paramant-core.

use thiserror::Error;

/// Errors returned by paramant-core operations.
///
/// Marked `#[non_exhaustive]`: new variants may be added without a breaking
/// change, so downstream `match` must include a wildcard arm.
///
/// # Examples
///
/// ```
/// use paramant_core::error::CoreError;
/// let e = CoreError::InvalidLength { expected: 32, got: 31 };
/// assert!(e.to_string().contains("expected 32"));
/// ```
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CoreError {
    /// A liboqs KEM primitive returned an error.
    #[error("KEM operation failed: {0}")]
    Kem(&'static str),

    /// A liboqs signature primitive returned an error.
    #[error("signature operation failed: {0}")]
    Sig(&'static str),

    /// An AEAD (AES-256-GCM) operation failed.
    #[error("AEAD operation failed: {0}")]
    Aead(&'static str),

    /// An input buffer had an unexpected length.
    #[error("invalid length: expected {expected}, got {got}")]
    InvalidLength {
        /// The length the operation required.
        expected: usize,
        /// The length actually supplied.
        got: usize,
    },
}

/// Convenience alias for results returned by paramant-core.
///
/// # Examples
///
/// ```
/// use paramant_core::error::{CoreError, CoreResult};
/// fn check(len: usize) -> CoreResult<()> {
///     if len == 32 { Ok(()) } else { Err(CoreError::InvalidLength { expected: 32, got: len }) }
/// }
/// assert!(check(32).is_ok());
/// ```
pub type CoreResult<T> = Result<T, CoreError>;
