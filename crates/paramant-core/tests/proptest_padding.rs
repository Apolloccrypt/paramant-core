//! Property tests for block padding: pad-then-unpad round-trips, the chosen
//! scheme is always the smallest fitting block, and padded output is block-aligned.

use paramant_core::padding::{pad, unpad, PaddingScheme};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    // Round-trip over the 4K/64K/512K tiers (sizes proptest can generate cheaply).
    #[test]
    fn pad_unpad_roundtrips(plaintext in prop::collection::vec(any::<u8>(), 0..=200_000)) {
        let (scheme, padded) = pad(&plaintext);
        prop_assert!(padded.len().is_multiple_of(scheme.block_size()));
        prop_assert!(padded.len() >= plaintext.len() + 4);
        prop_assert_eq!(unpad(&padded, scheme).unwrap(), plaintext);
    }

    // select_for picks the smallest single block that fits length+suffix, or the
    // largest scheme when nothing single-block fits (arithmetic only, so the range
    // can span every tier without allocating).
    #[test]
    fn select_for_picks_smallest_fitting_block(len in 0usize..=6_000_000) {
        let chosen = PaddingScheme::select_for(len);
        let need = len + 4;
        let expected = [
            PaddingScheme::Block4K,
            PaddingScheme::Block64K,
            PaddingScheme::Block512K,
        ]
        .into_iter()
        .find(|b| b.block_size() >= need)
        .unwrap_or(PaddingScheme::Block5M);
        prop_assert_eq!(chosen, expected);
    }
}

/// Explicit 0–10 MiB coverage including a 5 MiB exact block and multi-block
/// outputs — too large for proptest's per-element generation, fast as a pattern.
#[test]
fn large_and_multiblock_roundtrip() {
    for len in [524_285usize, 5_242_876, 6_000_000, 10_000_000] {
        let plaintext: Vec<u8> = (0..len).map(|j| (j % 251) as u8).collect();
        let (scheme, padded) = pad(&plaintext);
        assert!(
            padded.len().is_multiple_of(scheme.block_size()),
            "alignment at len {len}"
        );
        assert_eq!(
            unpad(&padded, scheme).unwrap(),
            plaintext,
            "roundtrip at len {len}"
        );
    }
}
