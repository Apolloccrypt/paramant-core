//! Node-API binding for paramant-core, published as `@paramant/core`.
//!
//! Each export is a thin wrapper over one paramant-core public function: inputs
//! and outputs are Node `Buffer`s, errors become JS `Error`s, and no batching or
//! logic lives here (the crypto is all in paramant-core). paramant-relay calls
//! these instead of its own JS crypto; see `docs/deploy-bridge.md` and ADR-0019.

// napi exports take their `Buffer` arguments by value, which is the binding's
// calling convention, not an oversight.
#![allow(clippy::needless_pass_by_value)]

use napi::bindgen_prelude::Buffer;
use napi_derive::napi;

use paramant_core::envelope::{para_drop, para_share, send};
use paramant_core::mnemonic::Mnemonic;
use paramant_core::sig::ml_dsa_65;
use paramant_core::{aead, kem};

/// Map any paramant-core error to a JS `Error`.
fn js_err<E: std::fmt::Display>(e: E) -> napi::Error {
    napi::Error::from_reason(e.to_string())
}

fn buf(bytes: Vec<u8>) -> Buffer {
    Buffer::from(bytes)
}

fn fixed<const N: usize>(b: &Buffer, what: &str) -> napi::Result<[u8; N]> {
    b.as_ref()
        .try_into()
        .map_err(|_| napi::Error::from_reason(format!("{what} must be {N} bytes")))
}

/// A public/secret key pair, each as raw bytes.
#[napi(object)]
pub struct Keypair {
    pub public_key: Buffer,
    pub secret_key: Buffer,
}

/// A KEM encapsulation: the ciphertext to send and the shared secret to keep.
#[napi(object)]
pub struct Encapsulation {
    pub ciphertext: Buffer,
    pub shared_secret: Buffer,
}

/// A decrypted ParaShare envelope and the verified sender public key.
#[napi(object)]
pub struct ParashareOpen {
    pub plaintext: Buffer,
    pub sender_pub: Buffer,
}

/// A ParaDrop result: the 12-word mnemonic to share and the padded blob.
#[napi(object)]
pub struct DropResult {
    pub mnemonic: String,
    pub blob: Buffer,
}

// -- ML-KEM-768 --------------------------------------------------------------

#[napi]
pub fn kem_keygen() -> napi::Result<Keypair> {
    let (pk, sk) = kem::keygen().map_err(js_err)?;
    Ok(Keypair {
        public_key: buf(pk.as_bytes().to_vec()),
        secret_key: buf(sk.as_bytes().to_vec()),
    })
}

#[napi]
pub fn kem_encaps(public_key: Buffer) -> napi::Result<Encapsulation> {
    let pk = kem::PublicKey::from_bytes(public_key.as_ref()).map_err(js_err)?;
    let (ct, ss) = kem::encaps(&pk).map_err(js_err)?;
    Ok(Encapsulation {
        ciphertext: buf(ct.as_bytes().to_vec()),
        shared_secret: buf(ss.as_bytes().to_vec()),
    })
}

#[napi]
pub fn kem_decaps(secret_key: Buffer, ciphertext: Buffer) -> napi::Result<Buffer> {
    let sk = kem::SecretKey::from_bytes(secret_key.as_ref()).map_err(js_err)?;
    let ct = kem::Ciphertext::from_bytes(ciphertext.as_ref()).map_err(js_err)?;
    let ss = kem::decaps(&sk, &ct).map_err(js_err)?;
    Ok(buf(ss.as_bytes().to_vec()))
}

// -- ML-DSA-65 ---------------------------------------------------------------

#[napi]
pub fn mldsa_keygen() -> napi::Result<Keypair> {
    let (pk, sk) = ml_dsa_65::keygen().map_err(js_err)?;
    Ok(Keypair {
        public_key: buf(pk.as_bytes().to_vec()),
        secret_key: buf(sk.as_bytes().to_vec()),
    })
}

#[napi]
pub fn mldsa_sign(secret_key: Buffer, msg: Buffer) -> napi::Result<Buffer> {
    let sk = ml_dsa_65::SecretKey::from_bytes(secret_key.as_ref()).map_err(js_err)?;
    let sig = ml_dsa_65::sign(&sk, msg.as_ref()).map_err(js_err)?;
    Ok(buf(sig.as_bytes().to_vec()))
}

#[napi]
pub fn mldsa_verify(public_key: Buffer, msg: Buffer, signature: Buffer) -> napi::Result<bool> {
    let pk = ml_dsa_65::PublicKey::from_bytes(public_key.as_ref()).map_err(js_err)?;
    let sig = ml_dsa_65::Signature::from_bytes(signature.as_ref()).map_err(js_err)?;
    ml_dsa_65::verify(&pk, msg.as_ref(), &sig).map_err(js_err)
}

// -- AES-256-GCM -------------------------------------------------------------

#[napi]
pub fn aead_encrypt(
    key: Buffer,
    nonce: Buffer,
    aad: Buffer,
    plaintext: Buffer,
) -> napi::Result<Buffer> {
    let key = fixed::<32>(&key, "key")?;
    let nonce = fixed::<12>(&nonce, "nonce")?;
    aead::encrypt(&key, &nonce, aad.as_ref(), plaintext.as_ref())
        .map(buf)
        .map_err(js_err)
}

#[napi]
pub fn aead_decrypt(
    key: Buffer,
    nonce: Buffer,
    aad: Buffer,
    ciphertext: Buffer,
) -> napi::Result<Buffer> {
    let key = fixed::<32>(&key, "key")?;
    let nonce = fixed::<12>(&nonce, "nonce")?;
    aead::decrypt(&key, &nonce, aad.as_ref(), ciphertext.as_ref())
        .map(buf)
        .map_err(js_err)
}

// -- Envelope: Send (anonymous) ----------------------------------------------

#[napi]
pub fn send_encrypt(
    recipient_kem_pub: Buffer,
    sender_pub: Buffer,
    plaintext: Buffer,
    pad_block: u32,
) -> napi::Result<Buffer> {
    let pk = kem::PublicKey::from_bytes(recipient_kem_pub.as_ref()).map_err(js_err)?;
    send::encrypt(
        &pk,
        sender_pub.as_ref(),
        plaintext.as_ref(),
        pad_block as usize,
    )
    .map(buf)
    .map_err(js_err)
}

#[napi]
pub fn send_decrypt(recipient_kem_sk: Buffer, blob: Buffer) -> napi::Result<Buffer> {
    let sk = kem::SecretKey::from_bytes(recipient_kem_sk.as_ref()).map_err(js_err)?;
    send::decrypt(&sk, blob.as_ref()).map(buf).map_err(js_err)
}

// -- Envelope: ParaShare (signed) --------------------------------------------

#[napi]
pub fn parashare_encrypt(
    recipient_kem_pub: Buffer,
    signer_sk: Buffer,
    signer_pub: Buffer,
    plaintext: Buffer,
    pad_block: u32,
) -> napi::Result<Buffer> {
    let pk = kem::PublicKey::from_bytes(recipient_kem_pub.as_ref()).map_err(js_err)?;
    let ssk = ml_dsa_65::SecretKey::from_bytes(signer_sk.as_ref()).map_err(js_err)?;
    let spk = ml_dsa_65::PublicKey::from_bytes(signer_pub.as_ref()).map_err(js_err)?;
    para_share::encrypt(&pk, &ssk, &spk, plaintext.as_ref(), pad_block as usize)
        .map(buf)
        .map_err(js_err)
}

#[napi]
pub fn parashare_decrypt(recipient_kem_sk: Buffer, blob: Buffer) -> napi::Result<ParashareOpen> {
    let sk = kem::SecretKey::from_bytes(recipient_kem_sk.as_ref()).map_err(js_err)?;
    let (plaintext, sender_pub) = para_share::decrypt(&sk, blob.as_ref()).map_err(js_err)?;
    Ok(ParashareOpen {
        plaintext: buf(plaintext),
        sender_pub: buf(sender_pub),
    })
}

// -- Envelope: ParaDrop (BIP-39 mnemonic) ------------------------------------

#[napi]
pub fn paradrop_drop(plaintext: Buffer, pad_block: u32) -> napi::Result<DropResult> {
    let (mnemonic, blob) =
        para_drop::drop(plaintext.as_ref(), pad_block as usize).map_err(js_err)?;
    Ok(DropResult {
        mnemonic: mnemonic.phrase(),
        blob: buf(blob),
    })
}

#[napi]
pub fn paradrop_pickup(mnemonic: String, blob: Buffer) -> napi::Result<Buffer> {
    let m = Mnemonic::parse(&mnemonic).map_err(js_err)?;
    para_drop::pickup(&m, blob.as_ref())
        .map(buf)
        .map_err(js_err)
}
