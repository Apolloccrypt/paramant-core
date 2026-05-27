//! Known-Answer Tests for the ParaDrop packet (BIP-39 mnemonic drop).
//!
//! ParaDrop has no KEM and no signature, so the packet is fully deterministic
//! given `(entropy, nonce, plaintext)` and these vectors pin full-packet SHA-256
//! anchors (generated in `scripts/extract-kat.mjs`, de-risked in
//! `scripts/derisk-paradrop.mjs`). The entropy<->mnemonic mapping is BIP-39
//! (covered by `bip39.json`); here we self-check the round-trip and that
//! `pickup` via a mnemonic recovers the plaintext.

use paramant_core::envelope::para_drop;
use paramant_core::mnemonic::Mnemonic;
use serde_json::Value;
use sha2::{Digest, Sha256};

const KAT_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/kat/envelope-paradrop.json"
));

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex in KAT")
}

fn pattern_plaintext(len: usize) -> Vec<u8> {
    (0..len).map(|j| (j % 251) as u8).collect()
}

#[test]
fn paradrop_vectors_match_and_roundtrip() {
    let kat: Value = serde_json::from_str(KAT_JSON).expect("parse paradrop KAT");
    let vectors = kat["vectors"].as_array().expect("vectors array");
    assert_eq!(vectors.len(), 15, "expected 15 ParaDrop KAT vectors");

    for v in vectors {
        let id = v["test_id"].as_str().unwrap_or("?");
        let inp = &v["input"];
        let exp = &v["expected"];

        let entropy = unhex(inp["entropy_hex"].as_str().unwrap());
        let nonce_v = unhex(inp["nonce_hex"].as_str().unwrap());
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_v);
        let plen = inp["plaintext"]["len"].as_u64().unwrap() as usize;
        let plaintext = pattern_plaintext(plen);

        // Key + lookup-id derivation.
        let (aes_key, lookup_id) = para_drop::derive(&entropy).expect("derive");
        assert_eq!(
            hex::encode(*aes_key),
            exp["aes_key_hex"].as_str().unwrap(),
            "aes {id}"
        );
        assert_eq!(
            hex::encode(lookup_id),
            exp["lookup_id_hex"].as_str().unwrap(),
            "lookup {id}"
        );

        // Packet framing is byte-identical (full-packet anchor).
        let packet = para_drop::seal(&entropy, &nonce, &plaintext).expect("seal");
        assert_eq!(
            packet.len() as u64,
            exp["packet_len"].as_u64().unwrap(),
            "packet_len {id}"
        );
        assert_eq!(
            hex::encode(Sha256::digest(&packet)),
            exp["packet_sha256_hex"].as_str().unwrap(),
            "packet sha256 {id}"
        );

        // open recovers the plaintext; trailing padding is tolerated.
        assert_eq!(
            para_drop::open(&entropy, &packet).expect("open"),
            plaintext,
            "open {id}"
        );
        let mut padded = packet.clone();
        padded.extend_from_slice(&[0x77u8; 64]);
        assert_eq!(
            para_drop::open(&entropy, &padded).expect("open padded"),
            plaintext,
            "padded {id}"
        );

        // Mnemonic round-trip and pickup (entropy is 16 bytes -> 12 words).
        let mut e16 = [0u8; 16];
        e16.copy_from_slice(&entropy);
        let m = Mnemonic::generate_from_entropy(e16).expect("mnemonic");
        assert_eq!(
            &m.to_entropy()[..],
            &entropy[..],
            "mnemonic round-trip {id}"
        );
        assert_eq!(
            para_drop::pickup(&m, &packet).expect("pickup"),
            plaintext,
            "pickup {id}"
        );

        // Wrong entropy and a tampered ciphertext both fail.
        let mut bad_entropy = entropy.clone();
        bad_entropy[0] ^= 0x01;
        assert!(
            para_drop::open(&bad_entropy, &packet).is_err(),
            "wrong entropy {id}"
        );
        let mut tampered = packet.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(
            para_drop::open(&entropy, &tampered).is_err(),
            "tampered {id}"
        );
    }
}
