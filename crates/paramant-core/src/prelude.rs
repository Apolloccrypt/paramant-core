//! Common imports. Bring everyday types into scope with one line:
//!
//! ```
//! use paramant_core::prelude::*;
//! ```

pub use crate::error::{CoreError, CoreResult};
pub use crate::kem::{self, Ciphertext, PublicKey, SecretKey, SharedSecret};
