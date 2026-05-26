//! Known-Answer Tests for BIP-0039 mnemonics against the trezor/python-mnemonic
//! canonical vectors.
//!
//! For 16-byte (12-word) vectors, `generate_from_entropy` must reproduce the
//! canonical phrase. For every vector, `parse(...).to_seed("TREZOR")` must
//! reproduce the canonical 64-byte seed.

use paramant_core::mnemonic::Mnemonic;

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex in KAT")
}

#[test]
fn bip39_entropy_to_mnemonic_to_seed_matches_trezor() {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/kat/bip39.json"
    ))
    .expect("read KAT json");
    let kat: serde_json::Value = serde_json::from_str(&raw).expect("parse KAT json");
    let vectors = kat["vectors"].as_array().expect("vectors array");
    assert_eq!(vectors.len(), 15, "expected 15 BIP-39 vectors");

    let mut twelve_word_seen = 0;
    for v in vectors {
        let id = v["test_id"].as_str().unwrap_or("?");
        let entropy = unhex(v["input"]["entropy_hex"].as_str().unwrap());
        let passphrase = v["input"]["passphrase"].as_str().unwrap();
        let want_mnemonic = v["expected"]["mnemonic"].as_str().unwrap();
        let want_seed = unhex(v["expected"]["seed_hex"].as_str().unwrap());

        // generate_from_entropy is defined for 128-bit (12-word) entropy only.
        if entropy.len() == 16 {
            twelve_word_seen += 1;
            let entropy16: [u8; 16] = entropy.as_slice().try_into().unwrap();
            let m = Mnemonic::generate_from_entropy(entropy16).expect("from entropy");
            assert_eq!(m.phrase(), want_mnemonic, "mnemonic mismatch for {id}");
        }

        // Seed derivation holds for every word count via parse().
        let parsed = Mnemonic::parse(want_mnemonic).expect("parse canonical mnemonic");
        let seed = parsed.to_seed(passphrase);
        assert_eq!(seed[..], want_seed[..], "seed mismatch for {id}");
    }

    assert_eq!(
        twelve_word_seen, 8,
        "expected 8 twelve-word vectors exercising generate_from_entropy"
    );
}
