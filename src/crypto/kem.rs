// ML-KEM-768 via pqcrypto-kyber (Kyber768 = ML-KEM-768)
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{PublicKey, SecretKey, Ciphertext, SharedSecret as PqSharedSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::{Result, ParamantError};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KemKeyPair {
    pub public_key: Vec<u8>,
    secret_key_bytes: Vec<u8>,
}

impl KemKeyPair {
    pub fn generate() -> Result<Self> {
        let (pk, sk) = kyber768::keypair();
        Ok(Self {
            public_key: pk.as_bytes().to_vec(),
            secret_key_bytes: sk.as_bytes().to_vec(),
        })
    }

    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<SharedSecret> {
        let sk = kyber768::SecretKey::from_bytes(&self.secret_key_bytes)
            .map_err(|_| ParamantError::InvalidKey("Ongeldige KEM secret key".into()))?;
        let ct = kyber768::Ciphertext::from_bytes(ciphertext)
            .map_err(|_| ParamantError::Kem("Ongeldige ciphertext".into()))?;
        let shared = kyber768::decapsulate(&ct, &sk);
        Ok(SharedSecret(shared.as_bytes().to_vec()))
    }
}

pub fn encapsulate(public_key_bytes: &[u8]) -> Result<(Vec<u8>, SharedSecret)> {
    let pk = kyber768::PublicKey::from_bytes(public_key_bytes)
        .map_err(|_| ParamantError::InvalidKey("Ongeldige KEM public key".into()))?;
    let (shared, ct) = kyber768::encapsulate(&pk);
    Ok((ct.as_bytes().to_vec(), SharedSecret(shared.as_bytes().to_vec())))
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret(pub Vec<u8>);

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_kem_roundtrip() {
        let alice = KemKeyPair::generate().unwrap();
        let (ct, bob_secret) = encapsulate(&alice.public_key).unwrap();
        let alice_secret = alice.decapsulate(&ct).unwrap();
        assert_eq!(alice_secret.0, bob_secret.0);
        assert_eq!(alice_secret.0.len(), 32);
    }
}
