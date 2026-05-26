//! Known-Answer Tests for ML-KEM-768 against @noble/post-quantum (FIPS 203),
//! the implementation paramant-relay uses.
//!
//! oqs exposes no deterministic (derand) keygen, so parity is proven on the
//! deterministic receiver path — `decaps(secret_key, ciphertext) ==
//! shared_secret`, byte-for-byte — plus interop on @noble-generated keypairs.
//! See `docs/adrs/0005-kem-kat-strategy.md`.

use paramant_core::kem::{self, Ciphertext, PublicKey, SecretKey};

const KAT_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/kat/ml-kem-768.json"
));

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex in KAT")
}

#[test]
fn decaps_is_byte_equivalent_with_noble() {
    let kat: serde_json::Value = serde_json::from_str(KAT_JSON).expect("parse KAT json");
    let vectors = kat["vectors"].as_array().expect("vectors array");
    assert_eq!(vectors.len(), 50, "expected 50 KAT vectors");

    for v in vectors {
        let id = v["test_id"].as_str().unwrap_or("?");
        let exp = &v["expected"];
        let sk = SecretKey::from_bytes(&unhex(exp["secret_key_hex"].as_str().unwrap())).unwrap();
        let ct = Ciphertext::from_bytes(&unhex(exp["ciphertext_hex"].as_str().unwrap())).unwrap();
        let want_ss = unhex(exp["shared_secret_hex"].as_str().unwrap());

        // Lengths match the FIPS 203 ML-KEM-768 parameter set.
        assert_eq!(
            unhex(exp["public_key_hex"].as_str().unwrap()).len(),
            kem::PUBLIC_KEY_LEN
        );
        assert_eq!(sk.as_bytes().len(), kem::SECRET_KEY_LEN);
        assert_eq!(ct.as_bytes().len(), kem::CIPHERTEXT_LEN);
        assert_eq!(want_ss.len(), kem::SHARED_SECRET_LEN);

        // The core's decapsulation reproduces @noble's shared secret exactly.
        let got = kem::decaps(&sk, &ct).expect("decaps");
        assert_eq!(
            got.as_bytes(),
            &want_ss[..],
            "shared secret mismatch for {id}"
        );
    }
}

#[test]
fn core_interops_with_noble_keypairs() {
    // Cross-implementation interop: the core encapsulates to a @noble-generated
    // public key and decapsulates with the matching @noble secret key, recovering
    // a consistent shared secret. (Live core->@noble decaps arrives with the NAPI
    // bridge at M5.)
    let kat: serde_json::Value = serde_json::from_str(KAT_JSON).unwrap();
    for v in kat["vectors"].as_array().unwrap() {
        let exp = &v["expected"];
        let pk = PublicKey::from_bytes(&unhex(exp["public_key_hex"].as_str().unwrap())).unwrap();
        let sk = SecretKey::from_bytes(&unhex(exp["secret_key_hex"].as_str().unwrap())).unwrap();

        let (ct, ss_sender) = kem::encaps(&pk).expect("encaps to noble pk");
        let ss_receiver = kem::decaps(&sk, &ct).expect("decaps with noble sk");
        assert_eq!(ss_sender.as_bytes(), ss_receiver.as_bytes());
    }
}
