//! Known-Answer Tests for AES-256-GCM against @noble/ciphers.
//!
//! AES-GCM is deterministic given (key, nonce, aad, plaintext), so this is a
//! true byte-for-byte cross-implementation KAT: paramant-core's `encrypt` must
//! reproduce @noble's `ciphertext ‖ tag` exactly, `decrypt` must recover the
//! plaintext, and a tampered tag must be rejected.

use paramant_core::aead;

const KAT_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/kat/aes-256-gcm.json"
));

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex in KAT")
}
fn key32(v: &[u8]) -> [u8; aead::KEY_LEN] {
    v.try_into().expect("32-byte key")
}
fn nonce12(v: &[u8]) -> [u8; aead::NONCE_LEN] {
    v.try_into().expect("12-byte nonce")
}

#[test]
fn encrypt_is_byte_equivalent_with_noble_and_decrypts() {
    let kat: serde_json::Value = serde_json::from_str(KAT_JSON).expect("parse KAT json");
    let vectors = kat["vectors"].as_array().expect("vectors array");
    assert_eq!(vectors.len(), 40, "expected 40 KAT vectors");

    for v in vectors {
        let id = v["test_id"].as_str().unwrap_or("?");
        let inp = &v["input"];
        let key = key32(&unhex(inp["key_hex"].as_str().unwrap()));
        let nonce = nonce12(&unhex(inp["nonce_hex"].as_str().unwrap()));
        let aad = unhex(inp["aad_hex"].as_str().unwrap());
        let pt = unhex(inp["plaintext_hex"].as_str().unwrap());
        let want_ct = unhex(v["expected"]["ciphertext_hex"].as_str().unwrap());

        let got = aead::encrypt(&key, &nonce, &aad, &pt).unwrap();
        assert_eq!(got, want_ct, "ciphertext mismatch for {id}");

        let recovered = aead::decrypt(&key, &nonce, &aad, &want_ct).unwrap();
        assert_eq!(recovered, pt, "decrypt mismatch for {id}");

        let mut tampered = want_ct.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(
            aead::decrypt(&key, &nonce, &aad, &tampered).is_err(),
            "tamper accepted for {id}"
        );
    }
}
