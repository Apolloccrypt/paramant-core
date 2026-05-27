//! hkdf + sha2 (RustCrypto, used by crypto-wasm) must match the RFC 5869
//! Appendix-A-anchored HKDF-SHA256 vectors paramant-core uses.

use hkdf::Hkdf;
use serde_json::Value;
use sha2::Sha256;

const KAT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/kat/hkdf.json"
));

#[test]
fn rustcrypto_hkdf_sha256_matches_vectors() {
    let kat: Value = serde_json::from_str(KAT).expect("parse hkdf KAT");
    let vectors = kat["vectors"].as_array().expect("vectors");
    assert!(!vectors.is_empty(), "no vectors");

    for v in vectors {
        let id = v["test_id"].as_str().unwrap_or("?");
        let ikm = hex::decode(v["input"]["ikm_hex"].as_str().unwrap()).unwrap();
        let salt = hex::decode(v["input"]["salt_hex"].as_str().unwrap()).unwrap();
        let info = hex::decode(v["input"]["info_hex"].as_str().unwrap()).unwrap();
        let len = v["input"]["length"].as_u64().unwrap() as usize;
        let want_prk = hex::decode(v["expected"]["prk_hex"].as_str().unwrap()).unwrap();
        let want_okm = hex::decode(v["expected"]["okm_hex"].as_str().unwrap()).unwrap();

        // RFC 5869 2.2: an empty salt is treated as HashLen zero bytes (None).
        let salt_opt = if salt.is_empty() {
            None
        } else {
            Some(salt.as_slice())
        };
        let (prk, hk) = Hkdf::<Sha256>::extract(salt_opt, &ikm);
        assert_eq!(prk.as_slice(), &want_prk[..], "hkdf prk mismatch {id}");

        let mut okm = vec![0u8; len];
        hk.expand(&info, &mut okm).expect("expand");
        assert_eq!(okm, want_okm, "hkdf okm mismatch {id}");
    }
}
