//! Known-Answer Tests for the RFC 6962 Merkle tree and Signed Tree Head.
//!
//! `merkle.json` is anchored to RFC 6962 (the generator self-checks the empty,
//! 1-leaf, and 8-leaf canonical roots before emitting); paramant-core must
//! reproduce both the root and the inclusion proofs byte-for-byte. `merkle-sth.json`
//! follows the ML-DSA-65 cross-impl pattern (`docs/adrs/0005-kem-kat-strategy.md`):
//! @noble/post-quantum signs the serialized head, paramant-core verifies it.

use paramant_core::merkle::{MerkleTree, SignedTreeHead};
use paramant_core::sig::ml_dsa_65::PublicKey;

const MERKLE_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/kat/merkle.json"
));
const STH_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/kat/merkle-sth.json"
));

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex in KAT")
}

fn unhex32(s: &str) -> [u8; 32] {
    unhex(s).try_into().expect("32-byte hash in KAT")
}

#[test]
fn merkle_roots_and_proofs_match_and_tamper_rejected() {
    let kat: serde_json::Value = serde_json::from_str(MERKLE_JSON).expect("parse merkle KAT");
    let vectors = kat["vectors"].as_array().expect("vectors array");
    assert_eq!(vectors.len(), 20, "expected 20 Merkle KAT vectors");

    for v in vectors {
        let id = v["test_id"].as_str().unwrap_or("?");
        let leaves: Vec<Vec<u8>> = v["input"]["leaves_hex"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| unhex(x.as_str().unwrap()))
            .collect();

        let mut tree = MerkleTree::new();
        for leaf in &leaves {
            tree.append(leaf);
        }
        let exp = &v["expected"];
        assert_eq!(
            tree.size(),
            exp["tree_size"].as_u64().unwrap() as usize,
            "size {id}"
        );

        let root = tree.root();
        assert_eq!(
            hex::encode(root),
            exp["root_hash_hex"].as_str().unwrap(),
            "root {id}"
        );

        for pr in exp["proofs"].as_array().unwrap() {
            let idx = pr["leaf_index"].as_u64().unwrap() as usize;
            let want: Vec<[u8; 32]> = pr["proof_hex"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| unhex32(x.as_str().unwrap()))
                .collect();

            // The proof matches @noble-independent RFC computation byte-for-byte.
            let got = tree.inclusion_proof(idx).unwrap();
            assert_eq!(got, want, "proof bytes for {id}[{idx}]");

            assert!(
                MerkleTree::verify_inclusion(&root, &leaves[idx], idx, tree.size(), &got),
                "verify {id}[{idx}]"
            );

            // A flipped root must never verify (covers empty-leaf vectors too).
            let mut bad_root = root;
            bad_root[0] ^= 0x01;
            assert!(
                !MerkleTree::verify_inclusion(&bad_root, &leaves[idx], idx, tree.size(), &got),
                "tampered root accepted for {id}[{idx}]"
            );
        }
    }
}

#[test]
fn sth_verifies_noble_signature_and_rejects_tampering() {
    let kat: serde_json::Value = serde_json::from_str(STH_JSON).expect("parse STH KAT");
    let vectors = kat["vectors"].as_array().expect("vectors array");
    assert_eq!(vectors.len(), 10, "expected 10 STH KAT vectors");

    for v in vectors {
        let id = v["test_id"].as_str().unwrap_or("?");
        let inp = &v["input"];
        let exp = &v["expected"];

        // Build the tree from the leaves and confirm the committed root.
        let mut tree = MerkleTree::new();
        for leaf in inp["leaves_hex"].as_array().unwrap() {
            tree.append(&unhex(leaf.as_str().unwrap()));
        }
        let root_hash = unhex32(exp["root_hash_hex"].as_str().unwrap());
        assert_eq!(tree.root(), root_hash, "root {id}");

        let pk = PublicKey::from_bytes(&unhex(exp["public_key_hex"].as_str().unwrap())).unwrap();
        let sth = SignedTreeHead {
            tree_size: inp["tree_size"].as_u64().unwrap(),
            timestamp: inp["timestamp"].as_u64().unwrap(),
            root_hash,
            signature: unhex(exp["signature_hex"].as_str().unwrap()),
        };

        assert!(sth.verify(&pk), "STH verify failed for {id}");

        // Flipping any signed field invalidates the signature.
        let mut bad = sth.clone();
        bad.root_hash[0] ^= 0x01;
        assert!(!bad.verify(&pk), "tampered root accepted for {id}");
        let mut bad_size = sth.clone();
        bad_size.tree_size ^= 1;
        assert!(
            !bad_size.verify(&pk),
            "tampered tree_size accepted for {id}"
        );
    }
}
