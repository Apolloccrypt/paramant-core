use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey(pub [u8; 32]);

pub fn derive_master(ecdh_shared: &[u8], kem_shared: &[u8]) -> MasterKey {
    let mut ikm = Vec::with_capacity(ecdh_shared.len() + kem_shared.len());
    ikm.extend_from_slice(ecdh_shared);
    ikm.extend_from_slice(kem_shared);
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = [0u8; 32];
    hk.expand(b"paramant-master-v1", &mut okm).unwrap();
    ikm.zeroize();
    MasterKey(okm)
}

pub fn derive_chain_key(master: &MasterKey, label: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, &master.0);
    let mut out = [0u8; 32];
    hk.expand(label, &mut out).unwrap();
    out
}

pub fn derive_message_key(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk_msg = Hkdf::<Sha256>::new(None, chain_key);
    let mut msg_key = [0u8; 32];
    hk_msg.expand(b"msg", &mut msg_key).unwrap();
    let hk_chain = Hkdf::<Sha256>::new(None, chain_key);
    let mut next_chain = [0u8; 32];
    hk_chain.expand(b"chain", &mut next_chain).unwrap();
    (msg_key, next_chain)
}
