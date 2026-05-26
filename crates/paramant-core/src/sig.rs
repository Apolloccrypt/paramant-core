//! Post-quantum digital signatures via liboqs.
//!
//! Each algorithm gets its own key/signature types (see
//! `docs/adrs/0007-signature-type-pattern.md`) so an ML-DSA key can never be
//! passed where a Falcon key is expected. The default for Paramant is
//! **ML-DSA-65** (`docs/adrs/0008-default-signature.md`), which is also what
//! `paramant-relay` uses.
//!
//! As with the KEM (`docs/adrs/0005-kem-kat-strategy.md`), oqs exposes no
//! deterministic keygen, so parity with `paramant-relay` (`@noble`) is proven by
//! verifying @noble-produced signatures, plus sign/verify round-trips.

use oqs::sig::{Algorithm, Sig};
use zeroize::Zeroizing;

use crate::error::{CoreError, CoreResult};

fn handle(alg: Algorithm) -> CoreResult<Sig> {
    Sig::new(alg).map_err(|_| CoreError::Sig("algorithm unavailable in liboqs"))
}

fn raw_keygen(alg: Algorithm) -> CoreResult<(Vec<u8>, Vec<u8>)> {
    let s = handle(alg)?;
    let (pk, sk) = s
        .keypair()
        .map_err(|_| CoreError::Sig("keypair generation failed"))?;
    Ok((pk.into_vec(), sk.into_vec()))
}

fn raw_sign(alg: Algorithm, sk: &[u8], msg: &[u8]) -> CoreResult<Vec<u8>> {
    let s = handle(alg)?;
    let sk_ref = s
        .secret_key_from_bytes(sk)
        .ok_or(CoreError::Sig("invalid secret key length"))?;
    let sig = s
        .sign(msg, sk_ref)
        .map_err(|_| CoreError::Sig("signing failed"))?;
    Ok(sig.into_vec())
}

fn raw_verify(alg: Algorithm, pk: &[u8], msg: &[u8], sig: &[u8]) -> CoreResult<bool> {
    let s = handle(alg)?;
    let pk_ref = s
        .public_key_from_bytes(pk)
        .ok_or(CoreError::Sig("invalid public key length"))?;
    let sig_ref = match s.signature_from_bytes(sig) {
        Some(r) => r,
        None => return Ok(false), // wrong-length signature is simply invalid
    };
    Ok(s.verify(msg, sig_ref, pk_ref).is_ok())
}

/// ML-DSA-65 (FIPS 204) — Paramant's default signature scheme.
pub mod ml_dsa_65 {
    use super::{raw_keygen, raw_sign, raw_verify, Algorithm, CoreError, CoreResult, Zeroizing};

    /// Length of an ML-DSA-65 public key, in bytes.
    pub const PUBLIC_KEY_LEN: usize = 1952;
    /// Length of an ML-DSA-65 secret key, in bytes.
    pub const SECRET_KEY_LEN: usize = 4032;
    /// Length of an ML-DSA-65 signature, in bytes.
    pub const SIGNATURE_LEN: usize = 3309;

    const ALG: Algorithm = Algorithm::MlDsa65;

    /// An ML-DSA-65 public (verification) key.
    #[derive(Clone, PartialEq, Eq)]
    pub struct PublicKey(Vec<u8>);
    /// An ML-DSA-65 secret (signing) key. Wiped on drop; never `Debug`-printed.
    #[derive(Clone)]
    pub struct SecretKey(Zeroizing<Vec<u8>>);
    /// An ML-DSA-65 signature.
    #[derive(Clone, PartialEq, Eq)]
    pub struct Signature(Vec<u8>);

    impl PublicKey {
        /// Borrow the key as bytes.
        pub fn as_bytes(&self) -> &[u8] {
            &self.0
        }
        /// Build from bytes, validating the length.
        ///
        /// # Errors
        /// [`CoreError::Sig`] if `bytes` is not [`PUBLIC_KEY_LEN`] long.
        pub fn from_bytes(bytes: &[u8]) -> CoreResult<Self> {
            if bytes.len() != PUBLIC_KEY_LEN {
                return Err(CoreError::Sig("invalid public key length"));
            }
            Ok(Self(bytes.to_vec()))
        }
    }

    impl SecretKey {
        /// Borrow the key as bytes. Handle with care.
        pub fn as_bytes(&self) -> &[u8] {
            &self.0
        }
        /// Build from bytes, validating the length.
        ///
        /// # Errors
        /// [`CoreError::Sig`] if `bytes` is not [`SECRET_KEY_LEN`] long.
        pub fn from_bytes(bytes: &[u8]) -> CoreResult<Self> {
            if bytes.len() != SECRET_KEY_LEN {
                return Err(CoreError::Sig("invalid secret key length"));
            }
            Ok(Self(Zeroizing::new(bytes.to_vec())))
        }
    }

    impl Signature {
        /// Borrow the signature as bytes.
        pub fn as_bytes(&self) -> &[u8] {
            &self.0
        }
        /// Build from bytes, validating the length.
        ///
        /// # Errors
        /// [`CoreError::Sig`] if `bytes` is not [`SIGNATURE_LEN`] long.
        pub fn from_bytes(bytes: &[u8]) -> CoreResult<Self> {
            if bytes.len() != SIGNATURE_LEN {
                return Err(CoreError::Sig("invalid signature length"));
            }
            Ok(Self(bytes.to_vec()))
        }
    }

    /// Generate an ML-DSA-65 keypair using the system RNG.
    ///
    /// # Errors
    /// [`CoreError::Sig`] if liboqs fails.
    ///
    /// # Examples
    /// ```
    /// use paramant_core::sig::ml_dsa_65;
    /// let (pk, sk) = ml_dsa_65::keygen().unwrap();
    /// let sig = ml_dsa_65::sign(&sk, b"hello").unwrap();
    /// assert!(ml_dsa_65::verify(&pk, b"hello", &sig).unwrap());
    /// assert!(!ml_dsa_65::verify(&pk, b"tampered", &sig).unwrap());
    /// ```
    pub fn keygen() -> CoreResult<(PublicKey, SecretKey)> {
        let (pk, sk) = raw_keygen(ALG)?;
        Ok((PublicKey(pk), SecretKey(Zeroizing::new(sk))))
    }

    /// Sign `msg` with `sk`.
    ///
    /// # Errors
    /// [`CoreError::Sig`] if liboqs fails.
    pub fn sign(sk: &SecretKey, msg: &[u8]) -> CoreResult<Signature> {
        Ok(Signature(raw_sign(ALG, &sk.0, msg)?))
    }

    /// Verify `sig` over `msg` against `pk`. Returns `Ok(false)` for a bad
    /// signature, `Err` only for an internal failure.
    pub fn verify(pk: &PublicKey, msg: &[u8], sig: &Signature) -> CoreResult<bool> {
        raw_verify(ALG, &pk.0, msg, &sig.0)
    }
}

#[cfg(test)]
mod tests {
    use super::ml_dsa_65;

    #[test]
    fn sign_verify_roundtrip() {
        let (pk, sk) = ml_dsa_65::keygen().unwrap();
        assert_eq!(pk.as_bytes().len(), ml_dsa_65::PUBLIC_KEY_LEN);
        assert_eq!(sk.as_bytes().len(), ml_dsa_65::SECRET_KEY_LEN);
        let sig = ml_dsa_65::sign(&sk, b"paramant").unwrap();
        assert_eq!(sig.as_bytes().len(), ml_dsa_65::SIGNATURE_LEN);
        assert!(ml_dsa_65::verify(&pk, b"paramant", &sig).unwrap());
    }

    #[test]
    fn rejects_tampered_message_and_wrong_key() {
        let (pk, sk) = ml_dsa_65::keygen().unwrap();
        let (other_pk, _) = ml_dsa_65::keygen().unwrap();
        let sig = ml_dsa_65::sign(&sk, b"paramant").unwrap();
        assert!(!ml_dsa_65::verify(&pk, b"paramant!", &sig).unwrap());
        assert!(!ml_dsa_65::verify(&other_pk, b"paramant", &sig).unwrap());
    }
}
