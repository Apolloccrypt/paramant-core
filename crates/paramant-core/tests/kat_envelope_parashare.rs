//! Known-Answer Tests for the signed ParaShare envelope (ML-DSA-65).
//!
//! Generated from paramant-relay's `send`/`_encrypt` signed path (see
//! `scripts/extract-kat.mjs`), de-risked in `scripts/derisk-parashare.mjs`.
//! `ct_kem`/`shared_secret`/`signature` come from @noble (deterministic
//! ML-KEM-768 + ML-DSA-65) and are KAT inputs -- `oqs` derandomises neither
//! encapsulation (ADR-0005) nor its hedged ML-DSA signing -- so the test pins
//! the deterministic framing via `seal_core`, confirms `decaps` links the Rust
//! KEM to the vector, and confirms `open_core` (which runs the Rust ML-DSA-65
//! verifier on the @noble signature) recovers the plaintext.

use paramant_core::envelope::{para_share, send};
use paramant_core::kem;
use paramant_core::wire::Envelope;
use serde_json::Value;
use sha2::{Digest, Sha256};

const KAT_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/kat/envelope-parashare.json"
));

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex in KAT")
}

fn pattern_plaintext(len: usize) -> Vec<u8> {
    (0..len).map(|j| (j % 251) as u8).collect()
}

#[test]
fn parashare_vectors_match_and_roundtrip() {
    let kat: Value = serde_json::from_str(KAT_JSON).expect("parse parashare KAT");
    let vectors = kat["vectors"].as_array().expect("vectors array");
    assert_eq!(vectors.len(), 15, "expected 15 ParaShare KAT vectors");

    for v in vectors {
        let id = v["test_id"].as_str().unwrap_or("?");
        let inp = &v["input"];
        let exp = &v["expected"];

        let ct_kem = unhex(inp["ct_kem_hex"].as_str().unwrap());
        let shared_secret = unhex(inp["shared_secret_hex"].as_str().unwrap());
        let kem_secret_key = unhex(inp["kem_secret_key_hex"].as_str().unwrap());
        let sender_pub = unhex(inp["sender_sig_pub_hex"].as_str().unwrap());
        let signature = unhex(inp["signature_hex"].as_str().unwrap());
        let nonce_v = unhex(inp["nonce_hex"].as_str().unwrap());
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_v);
        let plen = inp["plaintext"]["len"].as_u64().unwrap() as usize;
        let plaintext = pattern_plaintext(plen);

        // Key derivation is shared with Send mode.
        let key = send::derive_key(&ct_kem, &shared_secret).expect("derive_key");
        assert_eq!(
            hex::encode(key),
            exp["aes_key_hex"].as_str().unwrap(),
            "aes key {id}"
        );

        // seal_core (given the @noble signature) is byte-identical.
        let env = para_share::seal_core(
            &ct_kem,
            &shared_secret,
            &sender_pub,
            &nonce,
            &plaintext,
            &signature,
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

        // decaps links the Rust oqs KEM to the @noble vector.
        let sk = kem::SecretKey::from_bytes(&kem_secret_key).expect("kem sk");
        let ct = kem::Ciphertext::from_bytes(&ct_kem).expect("ct");
        let ss = kem::decaps(&sk, &ct).expect("decaps");
        assert_eq!(
            ss.as_bytes(),
            &shared_secret[..],
            "decaps == shared_secret {id}"
        );

        // open_core verifies the @noble ML-DSA-65 signature with the Rust
        // verifier (cross-impl link) and recovers the plaintext.
        assert_eq!(
            para_share::open_core(&env, ss.as_bytes()).expect("open"),
            plaintext,
            "open {id}"
        );

        // Tampering with the signature or the ciphertext both fail open_core.
        let mut bad_sig = env.clone();
        let s = bad_sig.signature.as_mut().unwrap();
        s[0] ^= 0x01;
        assert!(
            para_share::open_core(&bad_sig, ss.as_bytes()).is_err(),
            "tampered signature {id}"
        );
        let mut bad_ct = env.clone();
        let last = bad_ct.ciphertext.len() - 1;
        bad_ct.ciphertext[last] ^= 0x01;
        assert!(
            para_share::open_core(&bad_ct, ss.as_bytes()).is_err(),
            "tampered ciphertext {id}"
        );

        // Trailing padding is tolerated by decode_prefix.
        let mut padded = core.clone();
        padded.extend_from_slice(&[0xCDu8; 19]);
        let (env2, consumed) = Envelope::decode_prefix(&padded).expect("decode_prefix");
        assert_eq!(consumed, core.len(), "consumed {id}");
        assert_eq!(env2, env, "prefix-decoded envelope {id}");
    }
}
