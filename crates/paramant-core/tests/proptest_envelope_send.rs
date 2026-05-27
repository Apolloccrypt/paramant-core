//! Property tests for the anonymous Send-mode envelope: encrypt -> decrypt
//! round-trips, the wrong recipient key never decrypts, and tampering with the
//! AEAD-protected ciphertext is always rejected.
//!
//! Note: in this mode `sender_pub` is carried but is NOT covered by the AEAD AAD
//! (only the 10-byte header is), mirroring the relay. So the tamper property
//! targets the ciphertext/tag region, which the GCM tag always protects.

use paramant_core::envelope::send;
use paramant_core::kem;
use paramant_core::wire::Envelope;
use proptest::prelude::*;

/// `pad_block` guaranteed to exceed the encoded core (1088-byte ct_kem + 12-byte
/// nonce + 16-byte tag + length prefixes + header < 4 KiB of overhead).
fn pad_block_for(plaintext_len: usize, sender_pub_len: usize) -> usize {
    plaintext_len + sender_pub_len + 4096
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn encrypt_decrypt_roundtrips(
        plaintext in prop::collection::vec(any::<u8>(), 0..16_384),
        sender_pub in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let (pk, sk) = kem::keygen().unwrap();
        let pad_block = pad_block_for(plaintext.len(), sender_pub.len());
        let blob = send::encrypt(&pk, &sender_pub, &plaintext, pad_block).unwrap();
        prop_assert_eq!(blob.len(), pad_block);
        prop_assert_eq!(send::decrypt(&sk, &blob).unwrap(), plaintext);
    }

    #[test]
    fn wrong_recipient_never_decrypts(
        plaintext in prop::collection::vec(any::<u8>(), 1..2_048),
        sender_pub in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let (pk, _sk) = kem::keygen().unwrap();
        let (_pk2, sk2) = kem::keygen().unwrap();
        let pad_block = pad_block_for(plaintext.len(), sender_pub.len());
        let blob = send::encrypt(&pk, &sender_pub, &plaintext, pad_block).unwrap();
        // ML-KEM implicit rejection yields a different shared secret, so the AEAD
        // tag fails rather than erroring in decaps.
        prop_assert!(send::decrypt(&sk2, &blob).is_err());
    }

    #[test]
    fn tampered_ciphertext_rejected(
        plaintext in prop::collection::vec(any::<u8>(), 0..2_048),
        sender_pub in prop::collection::vec(any::<u8>(), 0..64),
        flip in 1u8..=255,
    ) {
        let (pk, sk) = kem::keygen().unwrap();
        let pad_block = pad_block_for(plaintext.len(), sender_pub.len());
        let mut blob = send::encrypt(&pk, &sender_pub, &plaintext, pad_block).unwrap();
        // Last core byte is the final GCM tag byte; flipping it always fails.
        let (_, consumed) = Envelope::decode_prefix(&blob).unwrap();
        blob[consumed - 1] ^= flip;
        prop_assert!(send::decrypt(&sk, &blob).is_err());
    }
}

/// A multi-megabyte plaintext round-trips (too large for per-case proptest).
#[test]
fn large_plaintext_roundtrips() {
    let (pk, sk) = kem::keygen().unwrap();
    let plaintext: Vec<u8> = (0..2_000_000usize).map(|j| (j % 251) as u8).collect();
    let pad_block = pad_block_for(plaintext.len(), 1184);
    let blob = send::encrypt(&pk, &vec![0xAB; 1184], &plaintext, pad_block).unwrap();
    assert_eq!(send::decrypt(&sk, &blob).unwrap(), plaintext);
}
