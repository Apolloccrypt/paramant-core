//! Property tests for ParaDrop: drop->pickup round-trips via the mnemonic, a
//! different mnemonic never decrypts, and a tampered ciphertext is rejected.

use paramant_core::envelope::para_drop;
use paramant_core::mnemonic::Mnemonic;
use proptest::prelude::*;

fn pad_block_for(plaintext_len: usize) -> usize {
    plaintext_len + 1024 // nonce(12) + len(4) + tag(16) fit easily
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn drop_pickup_roundtrips(plaintext in prop::collection::vec(any::<u8>(), 0..16_384)) {
        let pad_block = pad_block_for(plaintext.len());
        let (mnemonic, blob) = para_drop::drop(&plaintext, pad_block).unwrap();
        prop_assert_eq!(blob.len(), pad_block);
        prop_assert_eq!(para_drop::pickup(&mnemonic, &blob).unwrap(), plaintext);
    }

    #[test]
    fn wrong_mnemonic_never_decrypts(plaintext in prop::collection::vec(any::<u8>(), 1..2_048)) {
        let pad_block = pad_block_for(plaintext.len());
        let (_mnemonic, blob) = para_drop::drop(&plaintext, pad_block).unwrap();
        // A freshly generated mnemonic derives a different key.
        let other = Mnemonic::generate().unwrap();
        prop_assert!(para_drop::pickup(&other, &blob).is_err());
    }

    #[test]
    fn tampered_ciphertext_rejected(
        plaintext in prop::collection::vec(any::<u8>(), 0..2_048),
        flip in 1u8..=255,
    ) {
        let pad_block = pad_block_for(plaintext.len());
        let (mnemonic, mut blob) = para_drop::drop(&plaintext, pad_block).unwrap();
        // Byte 16 is the first ciphertext/tag byte (after nonce[12] + len[4]).
        blob[16] ^= flip;
        prop_assert!(para_drop::pickup(&mnemonic, &blob).is_err());
    }
}

/// A multi-megabyte plaintext round-trips (too large for per-case proptest).
#[test]
fn large_plaintext_roundtrips() {
    let plaintext: Vec<u8> = (0..2_000_000usize).map(|j| (j % 251) as u8).collect();
    let (mnemonic, blob) = para_drop::drop(&plaintext, plaintext.len() + 1024).unwrap();
    assert_eq!(para_drop::pickup(&mnemonic, &blob).unwrap(), plaintext);
}
