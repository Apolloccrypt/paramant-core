//! Paramant Core: post-quantum cryptographic substrate.
//!
//! See `BLUEPRINT.md` for the full design and milestone plan. The cryptographic
//! surface grows one milestone at a time so every line lands with tests:
//!
//! - **M1** [`kem`] — ML-KEM-768 (FIPS 203)
//! - **M2** [`sig`] — ML-DSA-65 (FIPS 204), SLH-DSA, Falcon
//! - **M3** [`aead`] — AES-256-GCM (KDF + mnemonic to follow)
//! - **M4** Merkle, padding, envelope, wire format v1
//!
//! `paramant-relay` (build 2.5.0) is the reference implementation; primitives are
//! checked against it via the tests in `tests/`.
//!
//! ```
//! use paramant_core::prelude::*;
//! let (pk, sk) = kem::keygen()?;
//! let (ct, ss_a) = kem::encaps(&pk)?;
//! let ss_b = kem::decaps(&sk, &ct)?;
//! assert_eq!(ss_a.as_bytes(), ss_b.as_bytes());
//! # Ok::<(), CoreError>(())
//! ```

#![warn(missing_docs)]

pub mod aead;
pub mod error;
pub mod kem;
pub mod prelude;
pub mod sig;
