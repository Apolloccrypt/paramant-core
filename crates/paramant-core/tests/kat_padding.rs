//! Known-Answer Tests for block padding.
//!
//! Padding is deterministic only in the unpad direction (pad uses random filler),
//! so each vector is a recipe: rebuild the block-aligned blob from the committed
//! `length_suffix_hex` (the little-endian u32 length) and assert `unpad` recovers
//! the original `j % 251` plaintext pattern, and that a corrupt suffix is rejected.

use paramant_core::padding::{unpad, PaddingScheme};

const KAT_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/kat/padding.json"
));

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex in KAT")
}

fn scheme_of(name: &str) -> PaddingScheme {
    match name {
        "Block4K" => PaddingScheme::Block4K,
        "Block64K" => PaddingScheme::Block64K,
        "Block512K" => PaddingScheme::Block512K,
        "Block5M" => PaddingScheme::Block5M,
        other => panic!("unknown scheme {other}"),
    }
}

#[test]
fn unpad_recovers_plaintext_and_rejects_corrupt_suffix() {
    let kat: serde_json::Value = serde_json::from_str(KAT_JSON).expect("parse padding KAT");
    let vectors = kat["vectors"].as_array().expect("vectors array");
    assert_eq!(vectors.len(), 25, "expected 25 padding KAT vectors");

    for v in vectors {
        let id = v["test_id"].as_str().unwrap_or("?");
        let inp = &v["input"];
        let scheme = scheme_of(inp["scheme"].as_str().unwrap());
        let len = inp["plaintext_len"].as_u64().unwrap() as usize;
        let padded_len = inp["padded_len"].as_u64().unwrap() as usize;
        let filler = inp["filler_byte"].as_u64().unwrap() as u8;
        let suffix = unhex(v["expected"]["length_suffix_hex"].as_str().unwrap());

        // The committed suffix is the little-endian u32 of the length: locks the
        // endianness against this independent encoding.
        assert_eq!(suffix, (len as u32).to_le_bytes(), "suffix endianness {id}");
        // The scheme's block size aligns the blob: locks the block-size table.
        assert!(
            padded_len.is_multiple_of(scheme.block_size()),
            "alignment {id}"
        );

        let plaintext: Vec<u8> = (0..len).map(|j| (j % 251) as u8).collect();
        let mut padded = vec![filler; padded_len];
        padded[..len].copy_from_slice(&plaintext);
        padded[padded_len - 4..].copy_from_slice(&suffix);

        assert_eq!(unpad(&padded, scheme).unwrap(), plaintext, "unpad {id}");

        // A length suffix larger than the available data must be rejected.
        let mut bad = padded.clone();
        let n = bad.len();
        bad[n - 4..].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(
            unpad(&bad, scheme).is_err(),
            "corrupt suffix accepted for {id}"
        );
    }
}
