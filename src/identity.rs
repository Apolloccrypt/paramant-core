use sha2::{Sha256, Digest};
use zeroize::ZeroizeOnDrop;
use crate::crypto::{ecdh::EcdhKeyPair, kem::KemKeyPair};
use crate::Result;

#[derive(ZeroizeOnDrop)]
pub struct Identity {
    pub ecdh: EcdhKeyPair,
    pub kem: KemKeyPair,
}

impl Identity {
    pub fn generate() -> Result<Self> {
        Ok(Self { ecdh: EcdhKeyPair::generate(), kem: KemKeyPair::generate()? })
    }
    pub fn public_address(&self) -> String {
        serde_json::json!({
            "ecdh": hex::encode(&self.ecdh.public_key_bytes),
            "kem":  hex::encode(&self.kem.public_key),
        }).to_string()
    }
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(&self.ecdh.public_key_bytes);
        h.update(&self.kem.public_key);
        h.finalize().into()
    }
}

pub struct PeerPublicKeys { pub ecdh: Vec<u8>, pub kem: Vec<u8> }
impl PeerPublicKeys {
    pub fn from_address(address: &str) -> Result<Self> {
        let v: serde_json::Value = serde_json::from_str(address)?;
        let ecdh = hex::decode(v["ecdh"].as_str().unwrap_or(""))
            .map_err(|_| crate::ParamantError::InvalidKey("Ongeldige ECDH hex".into()))?;
        let kem = hex::decode(v["kem"].as_str().unwrap_or(""))
            .map_err(|_| crate::ParamantError::InvalidKey("Ongeldige KEM hex".into()))?;
        Ok(Self { ecdh, kem })
    }
}
