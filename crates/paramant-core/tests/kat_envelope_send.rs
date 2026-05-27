//! Known-Answer Tests for the anonymous Send-mode envelope.
//!
//! Vectors are generated from paramant-relay's `sendAnonymous` crypto (see
//! `scripts/extract-kat.mjs`), with the WebCrypto-vs-pure-Node equivalence
//! proven separately in `scripts/derisk-send.mjs`. `ct_kem`/`shared_secret` come
//! from @noble ML-KEM-768 (deterministic) and are taken as inputs, because
//! `oqs` cannot derandomise encapsulation (ADR-0005) — exactly as in
//! `kat_ml_kem_768.rs`. The `decaps(secret_key, ct_kem) == shared_secret` check
//! links the Rust `oqs` KEM to the @noble-produced vectors end to end.

use paramant_core::envelope::send;
use paramant_core::kem;
use paramant_core::wire::{Envelope, KemId};
use serde_json::Value;
use sha2::{Digest, Sha256};

const KAT_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/kat/envelope-send.json"
));

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex in KAT")
}

/// The `j % 251` plaintext pattern the generator commits to.
fn pattern_plaintext(len: usize) -> Vec<u8> {
    (0..len).map(|j| (j % 251) as u8).collect()
}

#[test]
fn send_vectors_match_and_roundtrip() {
    let kat: Value = serde_json::from_str(KAT_JSON).expect("parse send KAT");
    let vectors = kat["vectors"].as_array().expect("vectors array");
    assert_eq!(vectors.len(), 20, "expected 20 Send-mode KAT vectors");

    for v in vectors {
        let id = v["test_id"].as_str().unwrap_or("?");
        let inp = &v["input"];
        let exp = &v["expected"];

        let ct_kem = unhex(inp["ct_kem_hex"].as_str().unwrap());
        let shared_secret = unhex(inp["shared_secret_hex"].as_str().unwrap());
        let secret_key = unhex(inp["secret_key_hex"].as_str().unwrap());
        let sender_pub = unhex(inp["sender_pub_hex"].as_str().unwrap());
        let nonce_v = unhex(inp["nonce_hex"].as_str().unwrap());
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_v);
        let plen = inp["plaintext"]["len"].as_u64().unwrap() as usize;
        let plaintext = pattern_plaintext(plen);

        // 1. Key derivation matches the relay.
        let key = send::derive_key(&ct_kem, &shared_secret).expect("derive_key");
        assert_eq!(
            hex::encode(key),
            exp["aes_key_hex"].as_str().unwrap(),
            "aes key {id}"
        );

        // 2. seal_core is byte-identical (core length, header, SHA-256).
        let env = send::seal_core(
            KemId::MlKem768,
            &ct_kem,
            &shared_secret,
            &sender_pub,
            &nonce,
            &plaintext,
        )
        .expect("seal_core");
        let core = env.encode().expect("encode");
        assert_eq!(
            core.len() as u64,
            exp["core_len"].as_u64().unwrap(),
            "core_len {id}"
        );
        assert_eq!(
            hex::encode(&core[..10]),
            exp["header_hex"].as_str().unwrap(),
            "header {id}"
        );
        assert_eq!(
            hex::encode(Sha256::digest(&core)),
            exp["core_sha256_hex"].as_str().unwrap(),
            "core sha256 {id}"
        );

        // 3. decaps links oqs to the @noble vector, then open_core recovers it.
        let sk = kem::SecretKey::from_bytes(&secret_key).expect("secret key");
        let ct = kem::Ciphertext::from_bytes(&ct_kem).expect("ct");
        let ss = kem::decaps(&sk, &ct).expect("decaps");
        assert_eq!(
            ss.as_bytes(),
            &shared_secret[..],
            "decaps == shared_secret {id}"
        );
        assert_eq!(
            send::open_core(&env, ss.as_bytes()).expect("open"),
            plaintext,
            "open {id}"
        );

        // 4. trailing padding is tolerated by decode_prefix.
        let mut padded = core.clone();
        padded.extend_from_slice(&[0xABu8; 37]);
        let (env2, consumed) = Envelope::decode_prefix(&padded).expect("decode_prefix");
        assert_eq!(consumed, core.len(), "consumed {id}");
        assert_eq!(env2, env, "prefix-decoded envelope {id}");

        // 5. wrong shared secret and a tampered ciphertext both fail to open.
        let mut bad_ss = shared_secret.clone();
        bad_ss[0] ^= 0x01;
        assert!(
            send::open_core(&env, &bad_ss).is_err(),
            "wrong shared secret {id}"
        );
        let mut tampered = env.clone();
        let last = tampered.ciphertext.len() - 1;
        tampered.ciphertext[last] ^= 0x01;
        assert!(
            send::open_core(&tampered, ss.as_bytes()).is_err(),
            "tampered ciphertext {id}"
        );
    }
}
