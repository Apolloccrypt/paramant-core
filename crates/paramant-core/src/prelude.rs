//! Common imports. Bring everyday types into scope with one line:
//!
//! ```
//! use paramant_core::prelude::*;
//! ```

pub use crate::aead;
pub use crate::error::{CoreError, CoreResult};
pub use crate::kdf;
pub use crate::kem::{self, Ciphertext, PublicKey, SecretKey, SharedSecret};
pub use crate::sig;
