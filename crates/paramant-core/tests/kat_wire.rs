//! Known-Answer Tests for wire format v1 (the `PQHB` envelope).
//!
//! Vectors come from paramant-relay's `docs/wire-format-v1.md` (approved
//! 2026-04-24); the two anchor vectors carry the published SHA-256 of a signed
//! (5090 B) and an anonymous (1778 B) envelope. For every vector we rebuild the
//! [`Envelope`], assert `encode` is byte-identical (SHA-256, total length and
//! header), and assert `decode ∘ encode` round-trips. A block of tamper cases
//! confirms the decoder rejects malformed blobs.

use paramant_core::wire::{Envelope, Header, KemId, SigId};
use serde_json::Value;
use sha2::{Digest, Sha256};

const KAT_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/kat/wire-format-v1.json"
));

/// Expand a `{pattern_hex, repeat}` field into its bytes.
fn expand(f: &Value) -> Vec<u8> {
    let pat = hex::decode(f["pattern_hex"].as_str().expect("pattern_hex")).expect("valid hex");
    pat.repeat(f["repeat"].as_u64().expect("repeat") as usize)
}

fn envelope_of(input: &Value) -> Envelope {
    let kem_id = KemId::try_from(input["kem_id"].as_u64().unwrap() as u16).expect("known KEM id");
    let sig_id = SigId::try_from(input["sig_id"].as_u64().unwrap() as u16).expect("known SIG id");
    let flags = input["flags"].as_u64().unwrap() as u8;
    let signature = if input["signature"].is_null() {
        None
    } else {
        Some(expand(&input["signature"]))
    };
    let nonce_v = hex::decode(input["nonce_hex"].as_str().unwrap()).expect("nonce hex");
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_v);
    Envelope {
        header: Header {
            kem_id,
            sig_id,
            flags,
        },
        ct_kem: expand(&input["ct_kem"]),
        sender_pub: expand(&input["sender_pub"]),
        signature,
        nonce,
        ciphertext: expand(&input["ciphertext"]),
    }
}

#[test]
fn encode_matches_vectors_and_decode_roundtrips() {
    let kat: Value = serde_json::from_str(KAT_JSON).expect("parse wire KAT");
    let vectors = kat["vectors"].as_array().expect("vectors array");
    assert_eq!(vectors.len(), 30, "expected 30 wire-format KAT vectors");

    for v in vectors {
        let id = v["test_id"].as_str().unwrap_or("?");
        let env = envelope_of(&v["input"]);
        let blob = env.encode().expect("encode");

        let exp = &v["expected"];
        assert_eq!(
            blob.len() as u64,
            exp["total_len"].as_u64().unwrap(),
            "total_len {id}"
        );
        assert_eq!(
            hex::encode(&blob[..10]),
            exp["header_hex"].as_str().unwrap(),
            "header {id}"
        );
        assert_eq!(
            hex::encode(Sha256::digest(&blob)),
            exp["sha256_hex"].as_str().unwrap(),
            "sha256 {id}"
        );

        // decode ∘ encode is the identity (consuming the whole buffer).
        assert_eq!(
            Envelope::decode(&blob).expect("decode"),
            env,
            "roundtrip {id}"
        );
    }
}

/// Build the signed anchor blob to mutate in the tamper tests.
fn signed_anchor_blob() -> Vec<u8> {
    let kat: Value = serde_json::from_str(KAT_JSON).unwrap();
    let v = kat["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["test_id"] == "wire-anchor-signed")
        .expect("signed anchor present");
    envelope_of(&v["input"]).encode().unwrap()
}

#[test]
fn decode_rejects_tampered_envelopes() {
    let good = signed_anchor_blob();
    assert!(Envelope::decode(&good).is_ok(), "control: anchor decodes");

    let mut bad_magic = good.clone();
    bad_magic[0] ^= 0x01;
    assert!(Envelope::decode(&bad_magic).is_err(), "bad magic");

    let mut bad_version = good.clone();
    bad_version[4] = 0x02;
    assert!(
        Envelope::decode(&bad_version).is_err(),
        "unsupported version"
    );

    let mut bad_flags = good.clone();
    bad_flags[9] = 0x01;
    assert!(Envelope::decode(&bad_flags).is_err(), "non-zero flags");

    let mut bad_kem = good.clone();
    bad_kem[5..7].copy_from_slice(&0x00ffu16.to_be_bytes());
    assert!(Envelope::decode(&bad_kem).is_err(), "unknown KEM id");

    let mut bad_sig = good.clone();
    bad_sig[7..9].copy_from_slice(&0x0fffu16.to_be_bytes());
    assert!(Envelope::decode(&bad_sig).is_err(), "unknown SIG id");

    assert!(
        Envelope::decode(&good[..good.len() - 1]).is_err(),
        "truncated ciphertext"
    );

    let mut trailing = good.clone();
    trailing.push(0x00);
    assert!(Envelope::decode(&trailing).is_err(), "trailing byte");

    assert!(Envelope::decode(&good[..9]).is_err(), "shorter than header");
}
