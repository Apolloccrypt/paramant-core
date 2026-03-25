// PARAMANT Sessie
// Volledige chat sessie: sleuteluitwisseling + ratchet + berichten

use crate::crypto::{kem, ecdh::EcdhKeyPair, kdf::derive_master};
use crate::identity::{Identity, PeerPublicKeys};
use crate::ratchet::RatchetState;
use crate::crypto::aead::EncryptedMessage;
use crate::{Result, ParamantError};
use serde::{Serialize, Deserialize};

/// Handshake pakket — verstuurd bij verbinding
#[derive(Debug, Serialize, Deserialize)]
pub struct HandshakePacket {
    /// Onze ECDH public key (hex)
    pub ecdh_pub: String,
    /// Onze KEM public key (hex)
    pub kem_pub: String,
    /// KEM ciphertext (als responder) — None als initiator
    pub kem_ct: Option<String>,
}

/// Chat sessie
pub struct Session {
    pub identity: Identity,
    pub ratchet: Option<RatchetState>,
    pub is_initiator: bool,
    /// Pending ECDH key voor handshake (tijdelijk)
    pending_ecdh: Option<EcdhKeyPair>,
}

impl Session {
    /// Maak nieuwe sessie aan
    pub fn new(identity: Identity) -> Self {
        Self {
            identity,
            ratchet: None,
            is_initiator: false,
            pending_ecdh: None,
        }
    }

    /// Stap 1 (initiator): maak handshake pakket
    pub fn initiate(&mut self) -> HandshakePacket {
        self.is_initiator = true;
        let ecdh = EcdhKeyPair::generate();
        let ecdh_pub = hex::encode(&ecdh.public_key_bytes);
        let kem_pub = hex::encode(&self.identity.kem.public_key);
        self.pending_ecdh = Some(ecdh);
        HandshakePacket { ecdh_pub, kem_pub, kem_ct: None }
    }

    /// Stap 2 (responder): verwerk handshake van initiator + stuur terug
    pub fn respond(&mut self, packet: &HandshakePacket) -> Result<HandshakePacket> {
        self.is_initiator = false;
        
        // ECDH shared secret
        let their_ecdh = hex::decode(&packet.ecdh_pub)
            .map_err(|_| ParamantError::InvalidKey("Ongeldige ECDH hex".into()))?;
        let our_ecdh = EcdhKeyPair::generate();
        let ecdh_shared = our_ecdh.diffie_hellman(&their_ecdh)?;

        // KEM: encapsuleer hun public key
        let their_kem = hex::decode(&packet.kem_pub)
            .map_err(|_| ParamantError::InvalidKey("Ongeldige KEM hex".into()))?;
        let (kem_ct, kem_shared) = kem::encapsulate(&their_kem)?;

        // Afleid master sleutel
        let master = derive_master(&ecdh_shared.0, &kem_shared.0);

        // Initialiseer ratchet als responder
        self.ratchet = Some(RatchetState::new_responder(&master));

        Ok(HandshakePacket {
            ecdh_pub: hex::encode(&our_ecdh.public_key_bytes),
            kem_pub: hex::encode(&self.identity.kem.public_key),
            kem_ct: Some(hex::encode(&kem_ct)),
        })
    }

    /// Stap 3 (initiator): verwerk respons — compleet handshake
    pub fn complete(&mut self, packet: &HandshakePacket) -> Result<()> {
        let pending_ecdh = self.pending_ecdh.take()
            .ok_or(ParamantError::SessionNotInitialized)?;

        // ECDH shared secret
        let their_ecdh = hex::decode(&packet.ecdh_pub)
            .map_err(|_| ParamantError::InvalidKey("Ongeldige ECDH hex".into()))?;
        let ecdh_shared = pending_ecdh.diffie_hellman(&their_ecdh)?;

        // KEM: decapsuleer hun ciphertext
        let kem_ct_hex = packet.kem_ct.as_ref()
            .ok_or(ParamantError::InvalidKey("Geen KEM ciphertext in respons".into()))?;
        let kem_ct = hex::decode(kem_ct_hex)
            .map_err(|_| ParamantError::InvalidKey("Ongeldige KEM CT hex".into()))?;
        let kem_shared = self.identity.kem.decapsulate(&kem_ct)?;

        // Afleid master sleutel
        let master = derive_master(&ecdh_shared.0, &kem_shared.0);

        // Initialiseer ratchet als initiator
        self.ratchet = Some(RatchetState::new_initiator(&master));
        Ok(())
    }

    /// Versleutel een bericht
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<EncryptedMessage> {
        self.ratchet.as_mut()
            .ok_or(ParamantError::SessionNotInitialized)?
            .send_chain.encrypt(plaintext, "msg")
    }

    /// Ontsleutel een bericht
    pub fn decrypt(&mut self, msg: &EncryptedMessage) -> Result<Vec<u8>> {
        self.ratchet.as_mut()
            .ok_or(ParamantError::SessionNotInitialized)?
            .receive_chain.decrypt(msg, "msg")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_handshake_and_messaging() {
        let alice_id = Identity::generate().unwrap();
        let bob_id = Identity::generate().unwrap();

        let mut alice = Session::new(alice_id);
        let mut bob = Session::new(bob_id);

        // Handshake
        let alice_hello = alice.initiate();
        let bob_response = bob.respond(&alice_hello).unwrap();
        alice.complete(&bob_response).unwrap();

        // Alice → Bob
        let msg = b"Geheime boodschap";
        let encrypted = alice.encrypt(msg).unwrap();
        let decrypted = bob.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, msg);

        // Bob → Alice
        let reply = b"Ontvangen!";
        let encrypted2 = bob.encrypt(reply).unwrap();
        let decrypted2 = alice.decrypt(&encrypted2).unwrap();
        assert_eq!(decrypted2, reply);
    }
}
