// PARAMANT Dubbel Ratchet Protocol
// Identiek aan browser implementatie:
//   - Chain-A-v2 (initiator → responder)
//   - Chain-B-v2 (responder → initiator)
//   - KEM injectie elke KEM_IV=8 berichten

use std::collections::HashSet;
use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::crypto::{aead, kdf};
use crate::{Result, ParamantError};

/// KEM injectie elke 8 berichten (identiek aan browser KEM_IV=8)
pub const KEM_IV: u64 = 8;

/// Ratchet richting
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Direction {
    /// Chain-A-v2: initiator → responder
    Send,
    /// Chain-B-v2: responder → initiator
    Receive,
}

/// Ratchet keten — beheert chain keys en message keys
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RatchetChain {
    chain_key: [u8; 32],
    pub seq: u64,
    #[zeroize(skip)]
    seen_nonces: HashSet<String>,
}

impl RatchetChain {
    /// Initialiseer vanuit master key
    pub fn new(master: &kdf::MasterKey, label: &[u8]) -> Self {
        Self {
            chain_key: kdf::derive_chain_key(master, label),
            seq: 0,
            seen_nonces: HashSet::new(),
        }
    }

    /// Versleutel een bericht — ratchet vooruit
    pub fn encrypt(&mut self, plaintext: &[u8], msg_type: &str) -> Result<aead::EncryptedMessage> {
        let (msg_key, next_chain) = kdf::derive_message_key(&self.chain_key);
        
        let encrypted = aead::encrypt(&msg_key, plaintext, self.seq, msg_type)?;
        
        // Ratchet vooruit — chain key vervangen
        self.chain_key = next_chain;
        self.seq += 1;
        
        Ok(encrypted)
    }

    /// Ontsleutel een bericht — replay check + ratchet vooruit
    pub fn decrypt(&mut self, msg: &aead::EncryptedMessage, msg_type: &str) -> Result<Vec<u8>> {
        // Replay bescherming: nonce prefix s: (send) of r: (receive)
        let nonce_key = format!("r:{}", hex::encode(msg.nonce.clone()));
        if self.seen_nonces.contains(&nonce_key) {
            return Err(ParamantError::ReplayDetected);
        }

        let (msg_key, next_chain) = kdf::derive_message_key(&self.chain_key);
        let plaintext = aead::decrypt(&msg_key, msg, msg_type)?;

        // Ratchet vooruit na succesvolle decryptie
        self.chain_key = next_chain;
        self.seq += 1;
        self.seen_nonces.insert(nonce_key);

        Ok(plaintext)
    }
}

/// Volledige ratchet staat voor een gesprek
pub struct RatchetState {
    /// Chain-A-v2: onze send chain
    pub send_chain: RatchetChain,
    /// Chain-B-v2: onze receive chain
    pub receive_chain: RatchetChain,
    /// Aantal berichten voor KEM injectie teller
    pub kem_count: u64,
}

impl RatchetState {
    /// Initialiseer als initiator (wij verbonden als eerste)
    pub fn new_initiator(master: &kdf::MasterKey) -> Self {
        Self {
            send_chain: RatchetChain::new(master, b"chain-A-v2"),
            receive_chain: RatchetChain::new(master, b"chain-B-v2"),
            kem_count: 0,
        }
    }

    /// Initialiseer als responder
    pub fn new_responder(master: &kdf::MasterKey) -> Self {
        Self {
            // Responder: send = chain-B, receive = chain-A (gespiegeld)
            send_chain: RatchetChain::new(master, b"chain-B-v2"),
            receive_chain: RatchetChain::new(master, b"chain-A-v2"),
            kem_count: 0,
        }
    }

    /// Moet KEM injection plaatsvinden?
    pub fn needs_kem_injection(&self) -> bool {
        self.send_chain.seq > 0 && self.send_chain.seq % KEM_IV == 0
    }

    /// Verwerk KEM injectie — update master en herinitialiseer chains
    pub fn inject_kem(&mut self, new_kem_shared: &[u8], new_ecdh_shared: &[u8]) {
        let new_master = kdf::derive_master(new_ecdh_shared, new_kem_shared);
        // Herinitialiseer chains met nieuw master (chains blijven in sync via seq)
        let new_send_chain = kdf::derive_chain_key(&new_master, b"kem-inject-send");
        let new_recv_chain = kdf::derive_chain_key(&new_master, b"kem-inject-recv");
        self.send_chain.chain_key = new_send_chain;
        self.receive_chain.chain_key = new_recv_chain;
        self.kem_count += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::derive_master;

    fn test_master() -> kdf::MasterKey {
        derive_master(&[1u8; 32], &[2u8; 32])
    }

    #[test]
    fn test_ratchet_roundtrip() {
        let master = test_master();
        let mut alice = RatchetState::new_initiator(&master);
        let mut bob = RatchetState::new_responder(&master);

        // Alice stuurt naar Bob
        let msg = b"Hallo Bob!";
        let encrypted = alice.send_chain.encrypt(msg, "msg").unwrap();
        let decrypted = bob.receive_chain.decrypt(&encrypted, "msg").unwrap();
        assert_eq!(decrypted, msg);

        // Bob stuurt terug naar Alice
        let reply = b"Hallo Alice!";
        let encrypted2 = bob.send_chain.encrypt(reply, "msg").unwrap();
        let decrypted2 = alice.receive_chain.decrypt(&encrypted2, "msg").unwrap();
        assert_eq!(decrypted2, reply);
    }

    #[test]
    fn test_replay_rejected() {
        let master = test_master();
        let mut sender = RatchetChain::new(&master, b"chain-A-v2");
        let mut receiver = RatchetChain::new(&master, b"chain-A-v2");

        let encrypted = sender.encrypt(b"test", "msg").unwrap();
        let _ = receiver.decrypt(&encrypted, "msg").unwrap();
        
        // Hetzelfde pakket nog een keer → replay error
        assert!(matches!(
            receiver.decrypt(&encrypted, "msg"),
            Err(ParamantError::ReplayDetected)
        ));
    }

    #[test]
    fn test_kem_injection_trigger() {
        let master = test_master();
        let mut state = RatchetState::new_initiator(&master);
        
        // Nog niet na KEM_IV berichten
        assert!(!state.needs_kem_injection());
        
        // Simuleer KEM_IV berichten
        state.send_chain.seq = KEM_IV;
        assert!(state.needs_kem_injection());
    }
}
