//! Hybrid KEM: ML-KEM-768 ⊕ ECDH P-256.
//!
//! The shared secret is derived from both a post-quantum (ML-KEM-768) and a
//! classical (ECDH P-256) KEM, so it stays secure as long as *either* holds.
//! The combiner follows `draft-ietf-tls-hybrid-design`:
//!
//! ```text
//! ss = HKDF-Extract( salt = ml_kem_ct ‖ ecdh_ephemeral_pub,
//!                    ikm  = ml_kem_ss ‖ ecdh_ss )            // HMAC-SHA-256, 32 bytes
//! ```
//!
//! Wire layout: a public key is `ml_kem_pk ‖ ecdh_pub` (SEC1 uncompressed), a
//! ciphertext is `ml_kem_ct ‖ ecdh_ephemeral_pub`. See
//! `docs/adrs/0010-hybrid-kem-construction.md`. ECDH is provided by AWS-LC
//! (`aws-lc-rs`); ML-KEM by liboqs (`super`). No `unsafe`.
//!
//! # Examples
//! ```
//! use paramant_core::kem::hybrid;
//! let (pk, sk) = hybrid::keygen().unwrap();
//! let (ct, ss_a) = hybrid::encaps(&pk).unwrap();
//! let ss_b = hybrid::decaps(&sk, &ct).unwrap();
//! assert_eq!(ss_a.as_bytes(), ss_b.as_bytes());
//! ```

use aws_lc_rs::agreement::{agree, PrivateKey, UnparsedPublicKey, ECDH_P256};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::{self as kem};
use crate::error::{CoreError, CoreResult};

/// ECDH P-256 scalar length (big-endian), in bytes.
const ECDH_SCALAR_LEN: usize = 32;
/// ECDH P-256 public point length (SEC1 uncompressed, `0x04‖X‖Y`), in bytes.
const ECDH_POINT_LEN: usize = 65;

/// Hybrid public key length: ML-KEM-768 public key ‖ ECDH P-256 point.
pub const PUBLIC_KEY_LEN: usize = kem::PUBLIC_KEY_LEN + ECDH_POINT_LEN;
/// Hybrid secret key length: ML-KEM-768 secret key ‖ ECDH P-256 scalar.
pub const SECRET_KEY_LEN: usize = kem::SECRET_KEY_LEN + ECDH_SCALAR_LEN;
/// Hybrid ciphertext length: ML-KEM-768 ciphertext ‖ ECDH ephemeral point.
pub const CIPHERTEXT_LEN: usize = kem::CIPHERTEXT_LEN + ECDH_POINT_LEN;
/// Hybrid shared-secret length, in bytes.
pub const SHARED_SECRET_LEN: usize = 32;

/// A hybrid public key (`ml_kem_pk ‖ ecdh_pub`).
#[derive(Clone, PartialEq, Eq)]
pub struct HybridPublicKey(Vec<u8>);
/// A hybrid secret key (`ml_kem_sk ‖ ecdh_scalar`). Wiped on drop.
#[derive(Clone)]
pub struct HybridSecretKey(Zeroizing<Vec<u8>>);
/// A hybrid ciphertext (`ml_kem_ct ‖ ecdh_ephemeral_pub`).
#[derive(Clone, PartialEq, Eq)]
pub struct HybridCiphertext(Vec<u8>);
/// A hybrid shared secret. Wiped on drop.
#[derive(Clone)]
pub struct HybridSharedSecret(Zeroizing<Vec<u8>>);

impl HybridPublicKey {
    /// Borrow the key as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    /// Build from bytes, validating the length.
    ///
    /// # Errors
    /// [`CoreError::InvalidLength`] if `bytes` is not [`PUBLIC_KEY_LEN`] long.
    pub fn from_bytes(bytes: &[u8]) -> CoreResult<Self> {
        check_len(bytes.len(), PUBLIC_KEY_LEN)?;
        Ok(Self(bytes.to_vec()))
    }
}
impl HybridCiphertext {
    /// Borrow the ciphertext as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    /// Build from bytes, validating the length.
    ///
    /// # Errors
    /// [`CoreError::InvalidLength`] if `bytes` is not [`CIPHERTEXT_LEN`] long.
    pub fn from_bytes(bytes: &[u8]) -> CoreResult<Self> {
        check_len(bytes.len(), CIPHERTEXT_LEN)?;
        Ok(Self(bytes.to_vec()))
    }
}
impl HybridSecretKey {
    /// Borrow the key as bytes. Handle with care.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    /// Build from bytes, validating the length.
    ///
    /// # Errors
    /// [`CoreError::InvalidLength`] if `bytes` is not [`SECRET_KEY_LEN`] long.
    pub fn from_bytes(bytes: &[u8]) -> CoreResult<Self> {
        check_len(bytes.len(), SECRET_KEY_LEN)?;
        Ok(Self(Zeroizing::new(bytes.to_vec())))
    }
}
impl HybridSharedSecret {
    /// Borrow the shared secret as bytes. Handle with care.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Generate a hybrid keypair using the system RNG.
///
/// # Errors
/// [`CoreError`] if liboqs or AWS-LC fails.
pub fn keygen() -> CoreResult<(HybridPublicKey, HybridSecretKey)> {
    let (kem_pk, kem_sk) = kem::keygen()?;
    let (ecdh_priv, ecdh_scalar) = ecdh_keygen()?;
    let ecdh_pub = ecdh_public(&ecdh_priv)?;

    let mut pk = Vec::with_capacity(PUBLIC_KEY_LEN);
    pk.extend_from_slice(kem_pk.as_bytes());
    pk.extend_from_slice(&ecdh_pub);

    let mut sk = Vec::with_capacity(SECRET_KEY_LEN);
    sk.extend_from_slice(kem_sk.as_bytes());
    sk.extend_from_slice(&ecdh_scalar);

    Ok((HybridPublicKey(pk), HybridSecretKey(Zeroizing::new(sk))))
}

/// Encapsulate to `pk`, returning the ciphertext and the sender's shared secret.
///
/// # Errors
/// [`CoreError`] if `pk` is malformed or liboqs/AWS-LC fails.
pub fn encaps(pk: &HybridPublicKey) -> CoreResult<(HybridCiphertext, HybridSharedSecret)> {
    let (kem_pk_bytes, recipient_ecdh_pub) = pk.0.split_at(kem::PUBLIC_KEY_LEN);
    let kem_pk = kem::PublicKey::from_bytes(kem_pk_bytes)?;
    let (kem_ct, kem_ss) = kem::encaps(&kem_pk)?;

    let (eph_priv, _eph_scalar) = ecdh_keygen()?;
    let eph_pub = ecdh_public(&eph_priv)?;
    let ecdh_ss = ecdh_agree(&eph_priv, recipient_ecdh_pub)?;

    let ss = combine(kem_ct.as_bytes(), &eph_pub, kem_ss.as_bytes(), &ecdh_ss);

    let mut ct = Vec::with_capacity(CIPHERTEXT_LEN);
    ct.extend_from_slice(kem_ct.as_bytes());
    ct.extend_from_slice(&eph_pub);

    Ok((
        HybridCiphertext(ct),
        HybridSharedSecret(Zeroizing::new(ss.to_vec())),
    ))
}

/// Decapsulate `ct` with `sk`, returning the receiver's shared secret.
///
/// # Errors
/// [`CoreError`] if `sk`/`ct` are malformed or liboqs/AWS-LC fails.
pub fn decaps(sk: &HybridSecretKey, ct: &HybridCiphertext) -> CoreResult<HybridSharedSecret> {
    let (kem_sk_bytes, ecdh_scalar) = sk.0.split_at(kem::SECRET_KEY_LEN);
    let (kem_ct_bytes, eph_pub) = ct.0.split_at(kem::CIPHERTEXT_LEN);

    let kem_sk = kem::SecretKey::from_bytes(kem_sk_bytes)?;
    let kem_ct = kem::Ciphertext::from_bytes(kem_ct_bytes)?;
    let kem_ss = kem::decaps(&kem_sk, &kem_ct)?;

    let ecdh_priv = PrivateKey::from_private_key(&ECDH_P256, ecdh_scalar)
        .map_err(|_| CoreError::Kem("invalid ECDH scalar"))?;
    let ecdh_ss = ecdh_agree(&ecdh_priv, eph_pub)?;

    let ss = combine(kem_ct_bytes, eph_pub, kem_ss.as_bytes(), &ecdh_ss);
    Ok(HybridSharedSecret(Zeroizing::new(ss.to_vec())))
}

/// HKDF-Extract(SHA-256) over the concatenated ciphertexts (salt) and shared
/// secrets (ikm), per draft-ietf-tls-hybrid-design.
fn combine(kem_ct: &[u8], eph_pub: &[u8], kem_ss: &[u8], ecdh_ss: &[u8]) -> [u8; 32] {
    let mut salt = Vec::with_capacity(kem_ct.len() + eph_pub.len());
    salt.extend_from_slice(kem_ct);
    salt.extend_from_slice(eph_pub);

    let mut ikm = Zeroizing::new(Vec::with_capacity(kem_ss.len() + ecdh_ss.len()));
    ikm.extend_from_slice(kem_ss);
    ikm.extend_from_slice(ecdh_ss);

    let (prk, _hk) = Hkdf::<Sha256>::extract(Some(&salt), &ikm);
    let mut out = [0u8; 32];
    out.copy_from_slice(&prk);
    out
}

/// Generate a fresh ECDH P-256 keypair, returning the imported key and its raw
/// 32-byte scalar (so the secret key can be serialized).
fn ecdh_keygen() -> CoreResult<(PrivateKey, [u8; ECDH_SCALAR_LEN])> {
    let rng = SystemRandom::new();
    for _ in 0..8 {
        let mut scalar = [0u8; ECDH_SCALAR_LEN];
        rng.fill(&mut scalar)
            .map_err(|_| CoreError::Kem("RNG failure"))?;
        if let Ok(key) = PrivateKey::from_private_key(&ECDH_P256, &scalar) {
            return Ok((key, scalar));
        }
    }
    Err(CoreError::Kem("ECDH key generation failed"))
}

/// SEC1 uncompressed public point for an ECDH private key.
fn ecdh_public(key: &PrivateKey) -> CoreResult<Vec<u8>> {
    let pubkey = key
        .compute_public_key()
        .map_err(|_| CoreError::Kem("ECDH public key derivation failed"))?;
    Ok(pubkey.as_ref().to_vec())
}

/// Raw ECDH shared secret (P-256 x-coordinate, 32 bytes), wiped on drop.
fn ecdh_agree(key: &PrivateKey, peer_pub: &[u8]) -> CoreResult<Zeroizing<Vec<u8>>> {
    agree(
        key,
        UnparsedPublicKey::new(&ECDH_P256, peer_pub),
        CoreError::Kem("ECDH agreement failed"),
        |secret| Ok(Zeroizing::new(secret.to_vec())),
    )
}

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
    fn distinct_keypairs_do_not_share_secret() {
        let (pk1, sk1) = keygen().unwrap();
        let (_pk2, sk2) = keygen().unwrap();
        let (ct, ss) = encaps(&pk1).unwrap();
        assert_eq!(decaps(&sk1, &ct).unwrap().as_bytes(), ss.as_bytes());
        // Wrong secret key yields a different shared secret (not the sender's).
        assert_ne!(decaps(&sk2, &ct).unwrap().as_bytes(), ss.as_bytes());
    }

    #[test]
    fn wrong_length_inputs_rejected() {
        assert!(HybridPublicKey::from_bytes(&[0u8; 10]).is_err());
        assert!(HybridCiphertext::from_bytes(&[0u8; 10]).is_err());
        assert!(HybridSecretKey::from_bytes(&[0u8; 10]).is_err());
    }
}
