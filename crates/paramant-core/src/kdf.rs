//! Key derivation: Argon2id password hashing and HKDF-SHA256.
//!
//! Two distinct jobs, deliberately not interchangeable:
//!
//! - [`argon2id`] — slow, memory-hard hashing for **low-entropy secrets**
//!   (passwords). Fixed OWASP-2024 parameters (see ADR-0011); the salt is the
//!   caller's responsibility and must be unique per password.
//! - [`hkdf`] — fast extract-and-expand for **high-entropy keying material**
//!   (e.g. a KEM shared secret). Never feed a password to HKDF.
//!
//! Derived password tags are returned in [`Zeroizing`] storage, matching the
//! secret-wiping discipline used by `kem` and `sig`.
//!
//! # Examples
//! ```
//! use paramant_core::kdf;
//! // HKDF: derive 64 bytes of keystream from a shared secret.
//! let prk = kdf::hkdf::extract(b"salt", b"high-entropy shared secret");
//! let okm = kdf::hkdf::expand(&prk, b"context", 64).unwrap();
//! assert_eq!(okm.len(), 64);
//!
//! // Argon2id: hash a password, then verify in constant time.
//! let salt = b"sixteen-byte-salt";
//! let tag = kdf::argon2id::hash_password(b"correct horse", salt).unwrap();
//! assert!(kdf::argon2id::verify_password(b"correct horse", salt, &tag));
//! assert!(!kdf::argon2id::verify_password(b"wrong", salt, &tag));
//! ```

use argon2::{Algorithm, Argon2, Params, Version};
// Leading `::` selects the extern `hkdf` crate; the `hkdf` submodule below
// (the public KDF API) would otherwise shadow it inside this module.
use ::hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::{CoreError, CoreResult};

/// Argon2id password hashing at fixed OWASP-2024 parameters.
///
/// Argon2id is the hybrid variant recommended for password storage; the
/// parameters below come from the OWASP 2024 Password Storage Cheat Sheet and
/// are not configurable, so every caller gets the vetted cost. See ADR-0011.
pub mod argon2id {
    use super::*;

    /// Memory cost in KiB (19 MiB). OWASP 2024.
    pub const M_COST_KIB: u32 = 19456;
    /// Time cost, in iterations. OWASP 2024.
    pub const T_COST: u32 = 2;
    /// Parallelism (lanes). OWASP 2024.
    pub const P_COST: u32 = 1;
    /// Derived tag length, in bytes.
    pub const TAG_LEN: usize = 32;

    fn context() -> CoreResult<Argon2<'static>> {
        let params = Params::new(M_COST_KIB, T_COST, P_COST, Some(TAG_LEN))
            .map_err(|_| CoreError::Kdf("invalid Argon2 parameters"))?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }

    /// Hash `password` with `salt`, returning the raw 32-byte Argon2id tag.
    ///
    /// `salt` must be at least 8 bytes (the Argon2 minimum) and should be unique
    /// per password. The returned tag is wiped on drop.
    ///
    /// # Errors
    /// [`CoreError::Kdf`] if `salt` is too short or the hashing call fails.
    pub fn hash_password(password: &[u8], salt: &[u8]) -> CoreResult<Zeroizing<[u8; TAG_LEN]>> {
        let mut tag = Zeroizing::new([0u8; TAG_LEN]);
        context()?
            .hash_password_into(password, salt, &mut tag[..])
            .map_err(|_| CoreError::Kdf("Argon2id hashing failed"))?;
        Ok(tag)
    }

    /// Verify `password`/`salt` against an `expected` tag in constant time.
    ///
    /// Re-derives the tag and compares with [`subtle::ConstantTimeEq`], so the
    /// time taken does not depend on how many bytes match. Returns `false` on
    /// any hashing error (e.g. a too-short salt).
    pub fn verify_password(password: &[u8], salt: &[u8], expected: &[u8; TAG_LEN]) -> bool {
        match hash_password(password, salt) {
            Ok(tag) => tag[..].ct_eq(&expected[..]).into(),
            Err(_) => false,
        }
    }
}

/// HKDF-SHA256 extract-and-expand (RFC 5869).
///
/// Use this for high-entropy keying material only; for passwords use
/// [`argon2id`].
pub mod hkdf {
    use super::*;

    /// Length of the pseudorandom key and of SHA-256 output, in bytes.
    pub const PRK_LEN: usize = 32;

    /// HKDF-Extract: derive a 32-byte pseudorandom key from `salt` and `ikm`.
    ///
    /// An empty `salt` is treated as `HashLen` zero bytes, per RFC 5869 §2.2.
    pub fn extract(salt: &[u8], ikm: &[u8]) -> [u8; PRK_LEN] {
        let salt = if salt.is_empty() { None } else { Some(salt) };
        let (prk, _hk) = Hkdf::<Sha256>::extract(salt, ikm);
        let mut out = [0u8; PRK_LEN];
        out.copy_from_slice(&prk);
        out
    }

    /// HKDF-Expand: stretch `prk` to `len` bytes, bound to `info`.
    ///
    /// # Errors
    /// [`CoreError::Kdf`] if `len` exceeds `255 * 32 = 8160` bytes, the RFC 5869
    /// maximum for SHA-256.
    pub fn expand(prk: &[u8; PRK_LEN], info: &[u8], len: usize) -> CoreResult<Vec<u8>> {
        let hk = Hkdf::<Sha256>::from_prk(prk).map_err(|_| CoreError::Kdf("invalid PRK length"))?;
        let mut okm = vec![0u8; len];
        hk.expand(info, &mut okm)
            .map_err(|_| CoreError::Kdf("HKDF expand length too large"))?;
        Ok(okm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2id_roundtrip_and_verify() {
        let salt = b"sixteen-byte-salt";
        let tag = argon2id::hash_password(b"hunter2", salt).unwrap();
        // Deterministic for fixed (password, salt, params).
        let again = argon2id::hash_password(b"hunter2", salt).unwrap();
        assert_eq!(tag[..], again[..]);
        assert!(argon2id::verify_password(b"hunter2", salt, &tag));
        assert!(!argon2id::verify_password(b"hunter3", salt, &tag));
    }

    #[test]
    fn argon2id_short_salt_errs_and_verify_is_false() {
        assert!(argon2id::hash_password(b"pw", b"short").is_err()); // < 8 bytes
        assert!(!argon2id::verify_password(b"pw", b"short", &[0u8; 32]));
    }

    #[test]
    fn hkdf_expand_length_bounds() {
        let prk = hkdf::extract(b"salt", b"ikm");
        assert_eq!(hkdf::expand(&prk, b"", 8160).unwrap().len(), 8160); // max
        assert!(hkdf::expand(&prk, b"", 8161).is_err()); // one over
        assert_eq!(hkdf::expand(&prk, b"info", 0).unwrap().len(), 0);
    }

    #[test]
    fn hkdf_empty_salt_matches_none() {
        // RFC 5869 §2.2: empty salt == HashLen zeros == the crate's `None`.
        let a = hkdf::extract(b"", b"ikm");
        let (prk, _) = Hkdf::<Sha256>::extract(None, b"ikm");
        assert_eq!(a, prk.as_slice());
    }
}
