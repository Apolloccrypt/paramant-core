//! ml-dsa (RustCrypto 0.1.0, the crate ParaSign will use in crypto-wasm) must
//! agree with the @noble-anchored ML-DSA-65 vectors that paramant-core validates
//! oqs against (tests/kat/ml-dsa-65.json, 50 vectors, deterministic signing).
//!
//! Two checks:
//!  - verify-KAT: ml-dsa verifies every @noble signature (true). Signing is
//!    randomised so sign-output bytes are not comparable; verification is the
//!    cross-impl equivalence proof (a divergent impl would reject valid sigs).
//!  - seeded-keygen-KAT: SigningKey::from_seed(xi).verifying_key() reproduces the
//!    @noble public key for the same 32-byte seed -- the byte-equivalence that
//!    ParaSign's mnemonic-deterministic key (Sg0 ADR-3) depends on.

use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, Keypair, MlDsa65, Seed, Signature, SigningKey,
    VerifyingKey,
};
use serde_json::Value;

const KAT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/kat/ml-dsa-65.json"
));

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex in KAT")
}

fn vectors() -> Vec<Value> {
    let kat: Value = serde_json::from_str(KAT).expect("parse ml-dsa KAT");
    kat["vectors"].as_array().expect("vectors").clone()
}

#[test]
fn ml_dsa_65_verify_matches_noble_vectors() {
    let vectors = vectors();
    assert_eq!(vectors.len(), 50, "expected 50 ML-DSA-65 vectors");

    for v in &vectors {
        let id = v["test_id"].as_str().unwrap_or("?");
        let pk = unhex(v["expected"]["public_key_hex"].as_str().unwrap());
        let msg = unhex(v["input"]["msg_hex"].as_str().unwrap());
        let sig_bytes = unhex(v["expected"]["signature_hex"].as_str().unwrap());

        let enc_vk = EncodedVerifyingKey::<MlDsa65>::try_from(pk.as_slice()).expect("1952-byte pk");
        let vk = VerifyingKey::<MlDsa65>::decode(&enc_vk);
        let enc_sig =
            EncodedSignature::<MlDsa65>::try_from(sig_bytes.as_slice()).expect("3309-byte sig");
        let sig = Signature::<MlDsa65>::decode(&enc_sig).expect("decodable signature");

        // @noble / oqs use the external ML-DSA verify with empty context.
        assert!(
            vk.verify_with_context(&msg, &[], &sig),
            "ml-dsa verify rejected a valid @noble signature: {id}"
        );

        // A flipped message must NOT verify (sanity: it is really checking).
        let mut bad = msg.clone();
        bad[0] ^= 0x01;
        assert!(
            !vk.verify_with_context(&bad, &[], &sig),
            "ml-dsa verify accepted a tampered message: {id}"
        );
    }
}

#[test]
fn ml_dsa_65_seeded_keygen_matches_noble_pubkey() {
    // Validates Sg0 ADR-3: SigningKey::from_seed(xi) is byte-equivalent to
    // @noble keygen(xi), so a mnemonic-derived seed yields the same identity.
    for v in &vectors() {
        let id = v["test_id"].as_str().unwrap_or("?");
        let seed_bytes = unhex(v["input"]["seed_hex"].as_str().unwrap());
        let want_pk = unhex(v["expected"]["public_key_hex"].as_str().unwrap());

        let seed = Seed::try_from(seed_bytes.as_slice()).expect("32-byte xi seed");
        let sk = SigningKey::<MlDsa65>::from_seed(&seed);
        let got_pk = sk.verifying_key().encode();

        assert_eq!(
            got_pk.as_slice(),
            &want_pk[..],
            "from_seed(xi) public key diverges from @noble: {id}"
        );
    }
}
