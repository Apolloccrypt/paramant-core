//! aes-gcm (RustCrypto, the crate crypto-wasm uses) must produce the same
//! ciphertext||tag as the @noble-anchored AES-256-GCM vectors paramant-core
//! checks its aws-lc-rs backend against.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use serde_json::Value;

const KAT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/kat/aes-256-gcm.json"
));

#[test]
fn rustcrypto_aes_256_gcm_matches_noble_vectors() {
    let kat: Value = serde_json::from_str(KAT).expect("parse aes-gcm KAT");
    let vectors = kat["vectors"].as_array().expect("vectors");
    assert!(!vectors.is_empty(), "no vectors");

    for v in vectors {
        let id = v["test_id"].as_str().unwrap_or("?");
        let key = hex::decode(v["input"]["key_hex"].as_str().unwrap()).unwrap();
        let nonce = hex::decode(v["input"]["nonce_hex"].as_str().unwrap()).unwrap();
        let aad = hex::decode(v["input"]["aad_hex"].as_str().unwrap()).unwrap();
        let pt = hex::decode(v["input"]["plaintext_hex"].as_str().unwrap()).unwrap();
        let want = hex::decode(v["expected"]["ciphertext_hex"].as_str().unwrap()).unwrap();

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
        let got = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &pt,
                    aad: &aad,
                },
            )
            .expect("encrypt");
        assert_eq!(got, want, "aes-gcm ct||tag mismatch {id}");

        // And it round-trips.
        let back = cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &got,
                    aad: &aad,
                },
            )
            .expect("decrypt");
        assert_eq!(back, pt, "aes-gcm decrypt mismatch {id}");
    }
}
