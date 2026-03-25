use p256::ecdh::EphemeralSecret;
use p256::{PublicKey, EncodedPoint};
use rand_core::OsRng;
use zeroize::ZeroizeOnDrop;
use crate::{Result, ParamantError};

#[derive(ZeroizeOnDrop)]
pub struct EcdhKeyPair {
    secret: EphemeralSecret,
    pub public_key_bytes: Vec<u8>,
}

impl EcdhKeyPair {
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random(&mut OsRng);
        let public_key = EncodedPoint::from(secret.public_key());
        Self { public_key_bytes: public_key.as_bytes().to_vec(), secret }
    }
    pub fn diffie_hellman(&self, their_public_key: &[u8]) -> Result<EcdhShared> {
        let their_pk = PublicKey::from_sec1_bytes(their_public_key)
            .map_err(|_| ParamantError::InvalidKey("Ongeldige ECDH public key".into()))?;
        let shared = self.secret.diffie_hellman(&their_pk);
        Ok(EcdhShared(shared.raw_secret_bytes().to_vec()))
    }
}

use zeroize::Zeroize;
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EcdhShared(pub Vec<u8>);
