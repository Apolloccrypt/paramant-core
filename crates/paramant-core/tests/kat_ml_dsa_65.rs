//! Known-Answer Tests for ML-DSA-65 against @noble/post-quantum (FIPS 204),
//! the implementation paramant-relay uses for signatures.
//!
//! oqs has no deterministic keygen, so parity is proven on the deterministic
//! path — verification of @noble-produced signatures — plus tamper rejection and
//! interop (the core signs and verifies @noble keypairs). See
//! `docs/adrs/0005-kem-kat-strategy.md` and `docs/adrs/0007-signature-type-pattern.md`.

use paramant_core::sig::ml_dsa_65::{self, PublicKey, SecretKey, Signature};

const KAT_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/kat/ml-dsa-65.json"
));

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex in KAT")
}

#[test]
fn verifies_noble_signatures_and_rejects_tampering() {
    let kat: serde_json::Value = serde_json::from_str(KAT_JSON).expect("parse KAT json");
    let vectors = kat["vectors"].as_array().expect("vectors array");
    assert_eq!(vectors.len(), 30, "expected 30 KAT vectors");

    for v in vectors {
        let id = v["test_id"].as_str().unwrap_or("?");
        let exp = &v["expected"];
        let pk = PublicKey::from_bytes(&unhex(exp["public_key_hex"].as_str().unwrap())).unwrap();
        let sig = Signature::from_bytes(&unhex(exp["signature_hex"].as_str().unwrap())).unwrap();
        let msg = unhex(v["input"]["msg_hex"].as_str().unwrap());

        // Lengths match the FIPS 204 ML-DSA-65 parameter set.
        assert_eq!(pk.as_bytes().len(), ml_dsa_65::PUBLIC_KEY_LEN);
        assert_eq!(sig.as_bytes().len(), ml_dsa_65::SIGNATURE_LEN);

        // The core accepts @noble's signature, and rejects a flipped message.
        assert!(
            ml_dsa_65::verify(&pk, &msg, &sig).unwrap(),
            "verify failed for {id}"
        );
        let mut tampered = msg.clone();
        tampered[0] ^= 0x01;
        assert!(
            !ml_dsa_65::verify(&pk, &tampered, &sig).unwrap(),
            "tamper accepted for {id}"
        );
    }
}

#[test]
fn core_signs_and_verifies_noble_keypairs() {
    // Interop: load @noble's keypair, sign with the core, verify with the core.
    let kat: serde_json::Value = serde_json::from_str(KAT_JSON).unwrap();
    for v in kat["vectors"].as_array().unwrap() {
        let exp = &v["expected"];
        let pk = PublicKey::from_bytes(&unhex(exp["public_key_hex"].as_str().unwrap())).unwrap();
        let sk = SecretKey::from_bytes(&unhex(exp["secret_key_hex"].as_str().unwrap())).unwrap();
        let msg = unhex(v["input"]["msg_hex"].as_str().unwrap());

        let sig = ml_dsa_65::sign(&sk, &msg).unwrap();
        assert!(ml_dsa_65::verify(&pk, &msg, &sig).unwrap());
    }
}
