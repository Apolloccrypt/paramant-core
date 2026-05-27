//! Common imports. Bring everyday types into scope with one line:
//!
//! ```
//! use paramant_core::prelude::*;
//! ```

pub use crate::aead;
pub use crate::envelope::send;
pub use crate::error::{CoreError, CoreResult};
pub use crate::kdf;
pub use crate::kem::{self, Ciphertext, PublicKey, SecretKey, SharedSecret};
pub use crate::merkle::{MerkleTree, SignedTreeHead};
pub use crate::mnemonic::{self, Mnemonic};
pub use crate::padding::{pad, unpad, PaddingScheme};
pub use crate::sig;
pub use crate::wire::{Envelope, Header, KemId, SigId, WIRE_MAGIC, WIRE_VERSION_V1};
