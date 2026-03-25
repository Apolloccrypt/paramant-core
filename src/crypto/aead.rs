use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use rand_core::{OsRng, RngCore};
use crate::{Result, ParamantError};

pub const NONCE_SIZE: usize = 12;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EncryptedMessage {
    pub nonce: String,
    pub ciphertext: String,
    pub seq: u64,
}

pub fn encrypt(key: &[u8; 32], plaintext: &[u8], seq: u64, msg_type: &str) -> Result<EncryptedMessage> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let aad = format!("paramant:{seq}:{msg_type}");
    let ct = cipher.encrypt(nonce, Payload { msg: plaintext, aad: aad.as_bytes() })
        .map_err(|_| ParamantError::Encryption("AES-GCM encrypt mislukt".into()))?;
    Ok(EncryptedMessage { nonce: hex::encode(nonce_bytes), ciphertext: hex::encode(ct), seq })
}

pub fn decrypt(key: &[u8; 32], msg: &EncryptedMessage, msg_type: &str) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce_bytes = hex::decode(&msg.nonce).map_err(|_| ParamantError::DecryptionFailed)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = hex::decode(&msg.ciphertext).map_err(|_| ParamantError::DecryptionFailed)?;
    let aad = format!("paramant:{}:{msg_type}", msg.seq);
    cipher.decrypt(nonce, Payload { msg: &ct, aad: aad.as_bytes() })
        .map_err(|_| ParamantError::DecryptionFailed)
}
