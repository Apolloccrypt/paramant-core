//! Signed, device-paired send (ParaShare): relay `send` / `_encrypt` with
//! `SIG_ID = 0x0002` (ML-DSA-65).
//!
//! Identical to [`super::send`] in its key encapsulation and AEAD -- single
//! ML-KEM-768 (NOT the hybrid KEM; the relay's `_encrypt` uses `kemEngine(kemId)`,
//! one KEM), `HKDF-SHA256(ikm = shared_secret, salt = ct_kem[0..32],
//! info = "paramant-v1-aes-key")`, AES-256-GCM with the PQHB header as AAD --
//! plus an ML-DSA-65 signature. The signed message is
//!
//! ```text
//! msg = ct_kem || sender_pub || nonce || ciphertext || aad
//! ```
//!
//! where `sender_pub` is the sender's ML-DSA-65 *public* key (carried in the
//! `SENDER_PUB` field) and `aad = HEADER(10) || chunk_index_be32`. Verified
//! byte-equivalent against the relay in `scripts/derisk-parashare.mjs`; see
//! [ADR-0016](../../docs/adrs/0016-parashare-signature.md).
//!
//! Signing is randomised (`oqs` ML-DSA is hedged), so a full envelope is not
//! reproducible byte-for-byte. The KAT therefore takes the signature as an input
//! (a deterministic @noble ML-DSA-65 signature), pins the deterministic framing
//! via [`seal_core`], and checks that [`crate::sig::ml_dsa_65::verify`] accepts
//! it -- the cross-implementation link, like `ml-dsa-65.json`.

use crate::aead;
use crate::envelope::send::derive_key;
use crate::envelope::{pad_to_block, random_nonce};
use crate::error::{CoreError, CoreResult};
use crate::kem;
use crate::sig::ml_dsa_65;
use crate::wire::{Envelope, Header, KemId, SigId};

/// The ML-DSA-65 signed message: `ct_kem || sender_pub || nonce || ciphertext || aad`.
pub fn signing_message(
    ct_kem: &[u8],
    sender_pub: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(
        ct_kem.len() + sender_pub.len() + nonce.len() + ciphertext.len() + aad.len(),
    );
    msg.extend_from_slice(ct_kem);
    msg.extend_from_slice(sender_pub);
    msg.extend_from_slice(nonce);
    msg.extend_from_slice(ciphertext);
    msg.extend_from_slice(aad);
    msg
}

/// Build the deterministic ParaShare envelope from a known KEM result and a
/// precomputed ML-DSA-65 `signature` over [`signing_message`].
///
/// This is the unit the KAT pins: given identical inputs (including the
/// signature) the output bytes are fixed.
pub fn seal_core(
    ct_kem: &[u8],
    shared_secret: &[u8],
    sender_sig_pub: &[u8],
    nonce: &[u8; 12],
    plaintext: &[u8],
    signature: &[u8],
) -> CoreResult<Envelope> {
    let key = derive_key(ct_kem, shared_secret)?;
    let mut envelope = Envelope {
        header: Header {
            kem_id: KemId::MlKem768,
            sig_id: SigId::MlDsa65,
            flags: 0x00,
        },
        ct_kem: ct_kem.to_vec(),
        sender_pub: sender_sig_pub.to_vec(),
        signature: Some(signature.to_vec()),
        nonce: *nonce,
        ciphertext: Vec::new(),
    };
    let aad = envelope.aad_for_chunk(0);
    envelope.ciphertext = aead::encrypt(&key, nonce, &aad, plaintext)?;
    Ok(envelope)
}

/// Verify the ML-DSA-65 signature against the `SENDER_PUB` carried in the
/// envelope, then decrypt. Returns the plaintext.
///
/// Like the relay, this enforces only that the signature is cryptographically
/// valid for the carried sender key; pinning that key (TOFU) is the caller's job.
///
/// # Errors
/// [`CoreError::Sig`] if the envelope is unsigned or the signature does not
/// verify; [`CoreError::Aead`] if decryption fails.
pub fn open_core(envelope: &Envelope, shared_secret: &[u8]) -> CoreResult<Vec<u8>> {
    let signature = match (envelope.header.sig_id, &envelope.signature) {
        (SigId::MlDsa65, Some(sig)) => sig,
        _ => return Err(CoreError::Sig("not a ML-DSA-65 ParaShare envelope")),
    };
    let aad = envelope.aad_for_chunk(0);
    let msg = signing_message(
        &envelope.ct_kem,
        &envelope.sender_pub,
        &envelope.nonce,
        &envelope.ciphertext,
        &aad,
    );
    let pk = ml_dsa_65::PublicKey::from_bytes(&envelope.sender_pub)?;
    let sig = ml_dsa_65::Signature::from_bytes(signature)?;
    if !ml_dsa_65::verify(&pk, &msg, &sig)? {
        return Err(CoreError::Sig(
            "signature did not verify against sender_pub",
        ));
    }
    let key = derive_key(&envelope.ct_kem, shared_secret)?;
    aead::decrypt(&key, &envelope.nonce, &aad, &envelope.ciphertext)
}

/// Encrypt `plaintext` to `recipient`, signing with the sender's ML-DSA-65 key,
/// and return the wire blob padded with random bytes to `pad_block`.
pub fn encrypt(
    recipient: &kem::PublicKey,
    signer_sk: &ml_dsa_65::SecretKey,
    signer_pub: &ml_dsa_65::PublicKey,
    plaintext: &[u8],
    pad_block: usize,
) -> CoreResult<Vec<u8>> {
    let (ct_kem, shared_secret) = kem::encaps(recipient)?;
    let nonce = random_nonce();
    let key = derive_key(ct_kem.as_bytes(), shared_secret.as_bytes())?;

    // Build the header so its AAD can be computed before the ciphertext exists.
    let mut envelope = Envelope {
        header: Header {
            kem_id: KemId::MlKem768,
            sig_id: SigId::MlDsa65,
            flags: 0x00,
        },
        ct_kem: ct_kem.as_bytes().to_vec(),
        sender_pub: signer_pub.as_bytes().to_vec(),
        signature: None,
        nonce,
        ciphertext: Vec::new(),
    };
    let aad = envelope.aad_for_chunk(0);
    envelope.ciphertext = aead::encrypt(&key, &nonce, &aad, plaintext)?;

    let msg = signing_message(
        &envelope.ct_kem,
        &envelope.sender_pub,
        &envelope.nonce,
        &envelope.ciphertext,
        &aad,
    );
    envelope.signature = Some(ml_dsa_65::sign(signer_sk, &msg)?.as_bytes().to_vec());

    pad_to_block(envelope.encode()?, pad_block)
}

/// Decrypt a ParaShare wire blob (tolerating trailing padding) with the
/// recipient's KEM secret key. Returns `(plaintext, sender_pub)` so the caller
/// can pin the sender's verified ML-DSA-65 public key.
pub fn decrypt(recipient_sk: &kem::SecretKey, blob: &[u8]) -> CoreResult<(Vec<u8>, Vec<u8>)> {
    let (envelope, _consumed) = Envelope::decode_prefix(blob)?;
    let ct = kem::Ciphertext::from_bytes(&envelope.ct_kem)?;
    let shared_secret = kem::decaps(recipient_sk, &ct)?;
    let plaintext = open_core(&envelope, shared_secret.as_bytes())?;
    Ok((plaintext, envelope.sender_pub))
}
