//! Anonymous BIP-39 drop (ParaDrop): relay `drop` / `pickup`.
//!
//! ParaDrop does NOT use the PQHB wire format. A sender generates 16 bytes of
//! BIP-39 entropy (a 12-word mnemonic the recipient receives out of band), and
//! both sides derive symmetric material straight from that entropy:
//!
//! ```text
//! prk        = HKDF-Extract(salt = "paramant-drop-v1", ikm = entropy)
//! aes_key    = HKDF-Expand(prk, "aes-key",   32)
//! lookup_id  = SHA-256(HKDF-Expand(prk, "lookup-id", 32))   // relay storage key
//! ```
//!
//! The payload is AES-256-GCM with **no AAD**, framed as
//!
//! ```text
//! packet = nonce(12) || ct_len_be32 || ciphertext      (ciphertext = ct || tag)
//! ```
//!
//! padded with random bytes to a caller block size; the boundary is the explicit
//! `ct_len`, so trailing padding is ignored on open. The entropy itself (not the
//! BIP-39 seed) is the HKDF input. Verified byte-equivalent against the relay's
//! WebCrypto path in `scripts/derisk-paradrop.mjs`; see
//! [ADR-0017](../../docs/adrs/0017-paradrop-mnemonic-derivation.md).
//!
//! Unlike Send/ParaShare there is no KEM and no signature, so a full packet is
//! deterministic given `(entropy, nonce, plaintext)` and the KAT pins full-packet
//! SHA-256 anchors.

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::aead;
use crate::envelope::{pad_to_block, random_nonce};
use crate::error::{CoreError, CoreResult};
use crate::kdf::hkdf;
use crate::mnemonic::Mnemonic;

const SALT: &[u8] = b"paramant-drop-v1";
const INFO_AES: &[u8] = b"aes-key";
const INFO_ID: &[u8] = b"lookup-id";
const ENTROPY_LEN: usize = 16;
const NONCE_SIZE: usize = 12;
const LEN_PREFIX: usize = 4;

/// Derive the AES-256-GCM key and the relay lookup id from BIP-39 `entropy`.
///
/// `lookup_id = SHA-256(HKDF-Expand(prk, "lookup-id", 32))`; the relay uses its
/// hex form as the storage/retrieval key.
pub fn derive(entropy: &[u8]) -> CoreResult<(Zeroizing<[u8; aead::KEY_LEN]>, [u8; 32])> {
    let prk = hkdf::extract(SALT, entropy);
    let mut aes_key = Zeroizing::new([0u8; aead::KEY_LEN]);
    aes_key.copy_from_slice(&hkdf::expand(&prk, INFO_AES, aead::KEY_LEN)?);
    let id_bytes = hkdf::expand(&prk, INFO_ID, 32)?;
    let lookup_id: [u8; 32] = Sha256::digest(&id_bytes).into();
    Ok((aes_key, lookup_id))
}

/// The relay lookup id for `entropy` (the storage key; hex-encode for the API).
pub fn lookup_id(entropy: &[u8]) -> CoreResult<[u8; 32]> {
    Ok(derive(entropy)?.1)
}

/// Build the deterministic drop packet from known `entropy`, `nonce` and
/// plaintext: `nonce || ct_len_be32 || AES-256-GCM(no AAD)`.
pub fn seal(entropy: &[u8], nonce: &[u8; NONCE_SIZE], plaintext: &[u8]) -> CoreResult<Vec<u8>> {
    let (aes_key, _) = derive(entropy)?;
    let ct = aead::encrypt(&aes_key, nonce, &[], plaintext)?;
    let mut packet = Vec::with_capacity(NONCE_SIZE + LEN_PREFIX + ct.len());
    packet.extend_from_slice(nonce);
    packet.extend_from_slice(&(ct.len() as u32).to_be_bytes());
    packet.extend_from_slice(&ct);
    Ok(packet)
}

/// Recover the plaintext from a drop packet (tolerating trailing padding) with
/// the BIP-39 `entropy`.
///
/// # Errors
/// [`CoreError::Wire`] if the packet is truncated; [`CoreError::Aead`] if the
/// key (wrong mnemonic) or ciphertext does not authenticate.
pub fn open(entropy: &[u8], packet: &[u8]) -> CoreResult<Vec<u8>> {
    if packet.len() < NONCE_SIZE + LEN_PREFIX {
        return Err(CoreError::Wire("drop packet shorter than header"));
    }
    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(&packet[..NONCE_SIZE]);
    let ct_len = u32::from_be_bytes([
        packet[NONCE_SIZE],
        packet[NONCE_SIZE + 1],
        packet[NONCE_SIZE + 2],
        packet[NONCE_SIZE + 3],
    ]) as usize;
    let start = NONCE_SIZE + LEN_PREFIX;
    let ct = packet
        .get(
            start
                ..start
                    .checked_add(ct_len)
                    .ok_or(CoreError::Wire("ct_len overflow"))?,
        )
        .ok_or(CoreError::Wire("ct_len exceeds packet"))?;
    let (aes_key, _) = derive(entropy)?;
    aead::decrypt(&aes_key, &nonce, &[], ct)
}

/// Drop `plaintext`: generate a fresh 12-word mnemonic, seal the packet, and pad
/// it to `pad_block`. Returns the mnemonic (to share out of band) and the blob.
pub fn drop(plaintext: &[u8], pad_block: usize) -> CoreResult<(Mnemonic, Vec<u8>)> {
    let mut entropy = Zeroizing::new([0u8; ENTROPY_LEN]);
    SystemRandom::new()
        .fill(entropy.as_mut())
        .map_err(|_| CoreError::Mnemonic("entropy RNG failure"))?;
    let mnemonic = Mnemonic::generate_from_entropy(*entropy)?;
    let nonce = random_nonce();
    let packet = seal(entropy.as_ref(), &nonce, plaintext)?;
    let blob = pad_to_block(packet, pad_block)?;
    Ok((mnemonic, blob))
}

/// Pick up a drop: derive the entropy from `mnemonic` and open the blob.
pub fn pickup(mnemonic: &Mnemonic, blob: &[u8]) -> CoreResult<Vec<u8>> {
    let entropy = mnemonic.to_entropy();
    open(&entropy, blob)
}
