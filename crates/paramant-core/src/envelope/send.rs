//! Anonymous Send-mode envelope (relay `sendAnonymous`, `SIG_ID = 0x0000`).
//!
//! A sender encapsulates to the recipient's ML-KEM-768 public key, derives an
//! AES-256-GCM key from the KEM shared secret, and encrypts the (unpadded)
//! plaintext with the 10-byte PQHB header bound as AAD. There is no signature
//! and no sender identity beyond the opaque `sender_pub` field.
//!
//! Key derivation mirrors `paramant-relay/sdk-js/index.js` exactly (verified
//! byte-equivalent against its WebCrypto path in `scripts/derisk-send.mjs`):
//!
//! ```text
//! aes_key = HKDF-SHA256(ikm = shared_secret, salt = ct_kem[0..32],
//!                       info = "paramant-v1-aes-key", len = 32)
//! ```
//!
//! The on-wire blob is the encoded envelope followed by random padding up to a
//! caller-chosen block size; the boundary is recovered with
//! [`Envelope::decode_prefix`]. Because ML-KEM encapsulation, the nonce and the
//! padding are all randomised (and `oqs` exposes no derandomised encapsulate,
//! ADR-0005), full envelopes are non-deterministic  --  the deterministic
//! [`seal_core`]/[`open_core`] pair carries the KAT (fixed `ct_kem` +
//! `shared_secret`), see [ADR-0015](../../docs/adrs/0015-send-mode-key-derivation.md).

use aws_lc_rs::rand::{SecureRandom, SystemRandom};

use crate::aead;
use crate::error::{CoreError, CoreResult};
use crate::kdf::hkdf;
use crate::kem;
use crate::wire::{Envelope, Header, KemId, SigId, NONCE_SIZE};

/// HKDF `info` string, identical to the relay (`paramant-v1-aes-key`).
const HKDF_INFO: &[u8] = b"paramant-v1-aes-key";
/// HKDF salt length: the first 32 bytes of the KEM ciphertext.
const SALT_LEN: usize = 32;

/// Derive the AES-256-GCM key from the KEM shared secret and ciphertext.
///
/// `salt = ct_kem[0..32]`, `ikm = shared_secret`, `info = "paramant-v1-aes-key"`.
pub fn derive_key(ct_kem: &[u8], shared_secret: &[u8]) -> CoreResult<[u8; aead::KEY_LEN]> {
    if ct_kem.len() < SALT_LEN {
        return Err(CoreError::Wire("ct_kem shorter than HKDF salt"));
    }
    let prk = hkdf::extract(&ct_kem[..SALT_LEN], shared_secret);
    let okm = hkdf::expand(&prk, HKDF_INFO, aead::KEY_LEN)?;
    let mut key = [0u8; aead::KEY_LEN];
    key.copy_from_slice(&okm);
    Ok(key)
}

/// Build the deterministic Send-mode envelope from a known KEM result.
///
/// This is the unit the KAT pins: given `ct_kem`, `shared_secret`, `sender_pub`
/// and `nonce`, the output bytes are fixed.
pub fn seal_core(
    kem_id: KemId,
    ct_kem: &[u8],
    shared_secret: &[u8],
    sender_pub: &[u8],
    nonce: &[u8; NONCE_SIZE],
    plaintext: &[u8],
) -> CoreResult<Envelope> {
    let key = derive_key(ct_kem, shared_secret)?;
    let mut envelope = Envelope {
        header: Header {
            kem_id,
            sig_id: SigId::None,
            flags: 0x00,
        },
        ct_kem: ct_kem.to_vec(),
        sender_pub: sender_pub.to_vec(),
        signature: None,
        nonce: *nonce,
        ciphertext: Vec::new(),
    };
    let aad = envelope.aad_for_chunk(0);
    envelope.ciphertext = aead::encrypt(&key, nonce, &aad, plaintext)?;
    Ok(envelope)
}

/// Recover the plaintext from a Send-mode envelope given the KEM shared secret.
pub fn open_core(envelope: &Envelope, shared_secret: &[u8]) -> CoreResult<Vec<u8>> {
    if !envelope.header.sig_id.is_none() {
        return Err(CoreError::Wire("not an anonymous Send envelope"));
    }
    let key = derive_key(&envelope.ct_kem, shared_secret)?;
    let aad = envelope.aad_for_chunk(0);
    aead::decrypt(&key, &envelope.nonce, &aad, &envelope.ciphertext)
}

/// Encrypt `plaintext` to `recipient` and return the wire blob padded with
/// random bytes to exactly `pad_block`. `sender_pub` is an opaque stable
/// identifier (the relay uses the sender's own KEM public key).
///
/// # Errors
/// [`CoreError::Wire`] if the encoded core exceeds `pad_block`.
pub fn encrypt(
    recipient: &kem::PublicKey,
    sender_pub: &[u8],
    plaintext: &[u8],
    pad_block: usize,
) -> CoreResult<Vec<u8>> {
    let (ct_kem, shared_secret) = kem::encaps(recipient)?;
    let nonce = random_nonce();
    let envelope = seal_core(
        KemId::MlKem768,
        ct_kem.as_bytes(),
        shared_secret.as_bytes(),
        sender_pub,
        &nonce,
        plaintext,
    )?;
    let mut blob = envelope.encode()?;
    if blob.len() > pad_block {
        return Err(CoreError::Wire("encoded core larger than pad_block"));
    }
    let pad_from = blob.len();
    blob.resize(pad_block, 0);
    SystemRandom::new()
        .fill(&mut blob[pad_from..])
        .map_err(|_| CoreError::Wire("padding RNG failure"))?;
    Ok(blob)
}

/// Decrypt a Send-mode wire blob (tolerating trailing padding) with the
/// recipient's KEM secret key.
pub fn decrypt(recipient_sk: &kem::SecretKey, blob: &[u8]) -> CoreResult<Vec<u8>> {
    let (envelope, _consumed) = Envelope::decode_prefix(blob)?;
    let ct = kem::Ciphertext::from_bytes(&envelope.ct_kem)?;
    let shared_secret = kem::decaps(recipient_sk, &ct)?;
    open_core(&envelope, shared_secret.as_bytes())
}

/// 12 random bytes from the system CSPRNG for use as an AES-GCM nonce.
fn random_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    // SystemRandom::fill only fails on catastrophic OS RNG failure; like
    // padding.rs we treat that as unrecoverable.
    SystemRandom::new()
        .fill(&mut nonce)
        .expect("system RNG failure");
    nonce
}
