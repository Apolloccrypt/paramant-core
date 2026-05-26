//! ML-KEM-768 (FIPS 203) key encapsulation, backed by liboqs via the `oqs` crate.
//!
//! Three operations: [`keygen`] makes a keypair, [`encaps`] wraps a fresh shared
//! secret to a public key, and [`decaps`] recovers it with the secret key.
//!
//! Randomness comes from liboqs' system RNG. Deterministic (seed-based) keygen is
//! intentionally absent: the `oqs` stack does not expose liboqs' `derand` entry
//! points, so byte-for-byte parity with `paramant-relay` is proven on the
//! deterministic operation (decapsulation) plus cross-implementation interop,
//! not by replaying keygen. See `docs/adrs/0005-kem-kat-strategy.md`.
//!
//! # Examples
//!
//! ```
//! use paramant_core::kem;
//! let (pk, sk) = kem::keygen().unwrap();
//! let (ct, ss_sender) = kem::encaps(&pk).unwrap();
//! let ss_receiver = kem::decaps(&sk, &ct).unwrap();
//! assert_eq!(ss_sender.as_bytes(), ss_receiver.as_bytes());
//! ```

use oqs::kem::{Algorithm, Kem};
use zeroize::Zeroizing;

use crate::error::{CoreError, CoreResult};

/// Length of an ML-KEM-768 public key, in bytes.
pub const PUBLIC_KEY_LEN: usize = 1184;
/// Length of an ML-KEM-768 secret key, in bytes.
pub const SECRET_KEY_LEN: usize = 2400;
/// Length of an ML-KEM-768 ciphertext, in bytes.
pub const CIPHERTEXT_LEN: usize = 1088;
/// Length of an ML-KEM-768 shared secret, in bytes.
pub const SHARED_SECRET_LEN: usize = 32;

/// An ML-KEM-768 public key.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey(Vec<u8>);

/// An ML-KEM-768 secret key. Wiped from memory on drop; never `Debug`-printed.
#[derive(Clone)]
pub struct SecretKey(Zeroizing<Vec<u8>>);

/// An ML-KEM-768 ciphertext (the encapsulation sent to the receiver).
#[derive(Clone, PartialEq, Eq)]
pub struct Ciphertext(Vec<u8>);

/// A 32-byte shared secret. Wiped from memory on drop; never `Debug`-printed.
#[derive(Clone)]
pub struct SharedSecret(Zeroizing<Vec<u8>>);

impl PublicKey {
    /// Borrow the key as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    /// Build a public key from bytes, validating the length.
    ///
    /// # Errors
    /// [`CoreError::InvalidLength`] if `bytes` is not [`PUBLIC_KEY_LEN`] long.
    pub fn from_bytes(bytes: &[u8]) -> CoreResult<Self> {
        check_len(bytes.len(), PUBLIC_KEY_LEN)?;
        Ok(Self(bytes.to_vec()))
    }
}

impl Ciphertext {
    /// Borrow the ciphertext as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    /// Build a ciphertext from bytes, validating the length.
    ///
    /// # Errors
    /// [`CoreError::InvalidLength`] if `bytes` is not [`CIPHERTEXT_LEN`] long.
    pub fn from_bytes(bytes: &[u8]) -> CoreResult<Self> {
        check_len(bytes.len(), CIPHERTEXT_LEN)?;
        Ok(Self(bytes.to_vec()))
    }
}

impl SecretKey {
    /// Borrow the secret key as bytes. Handle with care; do not log or persist
    /// in the clear.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    /// Build a secret key from bytes, validating the length.
    ///
    /// # Errors
    /// [`CoreError::InvalidLength`] if `bytes` is not [`SECRET_KEY_LEN`] long.
    pub fn from_bytes(bytes: &[u8]) -> CoreResult<Self> {
        check_len(bytes.len(), SECRET_KEY_LEN)?;
        Ok(Self(Zeroizing::new(bytes.to_vec())))
    }
}

impl SharedSecret {
    /// Borrow the shared secret as bytes. Handle with care.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Generate a fresh ML-KEM-768 keypair using the system RNG.
///
/// # Errors
/// [`CoreError::Kem`] if liboqs fails to initialise or generate the keypair.
///
/// # Examples
/// ```
/// let (pk, sk) = paramant_core::kem::keygen().unwrap();
/// assert_eq!(pk.as_bytes().len(), paramant_core::kem::PUBLIC_KEY_LEN);
/// ```
pub fn keygen() -> CoreResult<(PublicKey, SecretKey)> {
    let kem = ml_kem_768()?;
    let (pk, sk) = kem
        .keypair()
        .map_err(|_| CoreError::Kem("ML-KEM-768 keypair generation failed"))?;
    Ok((
        PublicKey(pk.into_vec()),
        SecretKey(Zeroizing::new(sk.into_vec())),
    ))
}

/// Encapsulate to `pk`, returning the ciphertext and the sender's copy of the
/// shared secret.
///
/// # Errors
/// [`CoreError`] if `pk` has the wrong length or liboqs fails.
pub fn encaps(pk: &PublicKey) -> CoreResult<(Ciphertext, SharedSecret)> {
    let kem = ml_kem_768()?;
    let pk_ref = kem
        .public_key_from_bytes(&pk.0)
        .ok_or(CoreError::InvalidLength {
            expected: PUBLIC_KEY_LEN,
            got: pk.0.len(),
        })?;
    let (ct, ss) = kem
        .encapsulate(pk_ref)
        .map_err(|_| CoreError::Kem("ML-KEM-768 encapsulation failed"))?;
    Ok((
        Ciphertext(ct.into_vec()),
        SharedSecret(Zeroizing::new(ss.into_vec())),
    ))
}

/// Decapsulate `ct` with `sk`, returning the receiver's copy of the shared
/// secret.
///
/// # Errors
/// [`CoreError`] if `sk`/`ct` have the wrong length or liboqs fails.
pub fn decaps(sk: &SecretKey, ct: &Ciphertext) -> CoreResult<SharedSecret> {
    let kem = ml_kem_768()?;
    let sk_ref = kem
        .secret_key_from_bytes(&sk.0)
        .ok_or(CoreError::InvalidLength {
            expected: SECRET_KEY_LEN,
            got: sk.0.len(),
        })?;
    let ct_ref = kem
        .ciphertext_from_bytes(&ct.0)
        .ok_or(CoreError::InvalidLength {
            expected: CIPHERTEXT_LEN,
            got: ct.0.len(),
        })?;
    let ss = kem
        .decapsulate(sk_ref, ct_ref)
        .map_err(|_| CoreError::Kem("ML-KEM-768 decapsulation failed"))?;
    Ok(SharedSecret(Zeroizing::new(ss.into_vec())))
}

/// Construct a liboqs ML-KEM-768 handle.
fn ml_kem_768() -> CoreResult<Kem> {
    Kem::new(Algorithm::MlKem768).map_err(|_| CoreError::Kem("ML-KEM-768 unavailable in liboqs"))
}

/// Length guard shared by the `from_bytes` constructors.
fn check_len(got: usize, expected: usize) -> CoreResult<()> {
    if got == expected {
        Ok(())
    } else {
        Err(CoreError::InvalidLength { expected, got })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_recovers_shared_secret() {
        let (pk, sk) = keygen().unwrap();
        assert_eq!(pk.as_bytes().len(), PUBLIC_KEY_LEN);
        assert_eq!(sk.as_bytes().len(), SECRET_KEY_LEN);

        let (ct, ss_sender) = encaps(&pk).unwrap();
        assert_eq!(ct.as_bytes().len(), CIPHERTEXT_LEN);

        let ss_receiver = decaps(&sk, &ct).unwrap();
        assert_eq!(ss_sender.as_bytes(), ss_receiver.as_bytes());
        assert_eq!(ss_sender.as_bytes().len(), SHARED_SECRET_LEN);
    }

    #[test]
    fn wrong_length_public_key_is_rejected() {
        assert!(matches!(
            PublicKey::from_bytes(&[0u8; 10]),
            Err(CoreError::InvalidLength { .. })
        ));
    }

    #[test]
    fn distinct_keypairs_each_roundtrip() {
        let (pk1, sk1) = keygen().unwrap();
        let (pk2, _sk2) = keygen().unwrap();
        assert_ne!(pk1.as_bytes(), pk2.as_bytes());
        let (ct, ss) = encaps(&pk1).unwrap();
        assert_eq!(decaps(&sk1, &ct).unwrap().as_bytes(), ss.as_bytes());
    }
}
