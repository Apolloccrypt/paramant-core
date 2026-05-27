//! Known-Answer Tests for the KDF module.
//!
//! - HKDF (RFC 5869): `extract`/`expand` must reproduce the published PRK/OKM
//!   bytes, including the RFC 5869 Appendix A cases 1-3.
//! - Argon2id (RFC 9106 / OWASP 2024 params): `hash_password` must reproduce
//!   the reference tag byte-for-byte (the generator validated the reference
//!   against the RFC 9106 Appendix A vector), and `verify_password` must accept
//!   the correct tag while rejecting any single-bit tamper.

use paramant_core::kdf;

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex in KAT")
}
fn arr32(v: &[u8]) -> [u8; 32] {
    v.try_into().expect("32-byte value")
}
fn load(path: &str) -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(path).expect("read KAT json"))
        .expect("parse KAT json")
}

#[test]
fn hkdf_extract_and_expand_match_rfc5869() {
    let kat = load(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/kat/hkdf.json"
    ));
    let vectors = kat["vectors"].as_array().expect("vectors array");
    assert_eq!(vectors.len(), 20, "expected 20 HKDF vectors");

    for v in vectors {
        let id = v["test_id"].as_str().unwrap_or("?");
        let inp = &v["input"];
        let salt = unhex(inp["salt_hex"].as_str().unwrap());
        let ikm = unhex(inp["ikm_hex"].as_str().unwrap());
        let info = unhex(inp["info_hex"].as_str().unwrap());
        let len = inp["length"].as_u64().unwrap() as usize;
        let want_prk = unhex(v["expected"]["prk_hex"].as_str().unwrap());
        let want_okm = unhex(v["expected"]["okm_hex"].as_str().unwrap());

        let prk = kdf::hkdf::extract(&salt, &ikm);
        assert_eq!(prk.as_slice(), want_prk.as_slice(), "PRK mismatch for {id}");

        let okm = kdf::hkdf::expand(&prk, &info, len).expect("expand");
        assert_eq!(okm, want_okm, "OKM mismatch for {id}");
    }
}

#[test]
fn argon2id_hash_and_verify_match_reference() {
    let kat = load(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/kat/argon2id.json"
    ));
    let vectors = kat["vectors"].as_array().expect("vectors array");
    assert_eq!(vectors.len(), 15, "expected 15 Argon2id vectors");

    for v in vectors {
        let id = v["test_id"].as_str().unwrap_or("?");

        // Guard: the vectors must use the same params our hash_password fixes.
        let p = &v["params"];
        assert_eq!(
            p["m_kib"].as_u64().unwrap() as u32,
            kdf::argon2id::M_COST_KIB
        );
        assert_eq!(p["t"].as_u64().unwrap() as u32, kdf::argon2id::T_COST);
        assert_eq!(p["p"].as_u64().unwrap() as u32, kdf::argon2id::P_COST);
        assert_eq!(
            p["dk_len"].as_u64().unwrap() as usize,
            kdf::argon2id::TAG_LEN
        );

        let pw = unhex(v["input"]["password_hex"].as_str().unwrap());
        let salt = unhex(v["input"]["salt_hex"].as_str().unwrap());
        let want_tag = arr32(&unhex(v["expected"]["tag_hex"].as_str().unwrap()));

        let tag = kdf::argon2id::hash_password(&pw, &salt).expect("hash");
        assert_eq!(tag[..], want_tag[..], "tag mismatch for {id}");

        // verify_password accepts the correct tag...
        assert!(
            kdf::argon2id::verify_password(&pw, &salt, &want_tag),
            "verify rejected correct tag for {id}"
        );
        // ...and rejects any single-bit tamper.
        let mut bad = want_tag;
        bad[0] ^= 0x01;
        assert!(
            !kdf::argon2id::verify_password(&pw, &salt, &bad),
            "verify accepted tampered tag for {id}"
        );
    }
}
