//! ml-kem (RustCrypto, the crate crypto-wasm uses) decapsulation must match the
//! @noble-anchored ML-KEM-768 vectors -- the same vectors paramant-core checks
//! its oqs backend against. Mirrors crypto-wasm's exact API
//! (`from_expanded_bytes` on the 2400-byte NIST dk, then `decapsulate_slice`).
#![allow(deprecated)]

use ml_kem::array::Array;
use ml_kem::kem::Decapsulate;
use ml_kem::{DecapsulationKey768, ExpandedDecapsulationKey, ExpandedKeyEncoding, MlKem768};
use serde_json::Value;

const KAT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/kat/ml-kem-768.json"
));

#[test]
fn rustcrypto_ml_kem_768_decaps_matches_noble_vectors() {
    let kat: Value = serde_json::from_str(KAT).expect("parse ml-kem KAT");
    let vectors = kat["vectors"].as_array().expect("vectors");
    assert!(!vectors.is_empty(), "no vectors");

    for v in vectors {
        let id = v["test_id"].as_str().unwrap_or("?");
        let sk = hex::decode(v["expected"]["secret_key_hex"].as_str().unwrap()).unwrap();
        let ct = hex::decode(v["expected"]["ciphertext_hex"].as_str().unwrap()).unwrap();
        let want = hex::decode(v["expected"]["shared_secret_hex"].as_str().unwrap()).unwrap();

        let dk_arr: ExpandedDecapsulationKey<MlKem768> =
            Array::try_from(sk.as_slice()).expect("2400-byte expanded dk");
        let dk = DecapsulationKey768::from_expanded_bytes(&dk_arr).expect("valid ML-KEM-768 dk");
        let ct_arr = Array::try_from(ct.as_slice()).expect("1088-byte ciphertext");
        // ML-KEM decapsulation is infallible (implicit rejection always returns
        // a value), so this returns the shared key directly, not a Result.
        let got = dk.decapsulate(&ct_arr);

        assert_eq!(got.as_slice(), &want[..], "ml-kem decaps mismatch {id}");
    }
}
