//! Property tests for the signed ParaShare envelope: encrypt->decrypt
//! round-trips and returns the sender's verified ML-DSA-65 public key, the wrong
//! recipient key never decrypts, and tampering with the AEAD-protected
//! ciphertext (or the signature it covers) is always rejected.

use paramant_core::envelope::para_share;
use paramant_core::wire::Envelope;
use paramant_core::{kem, sig};
use proptest::prelude::*;

/// Generous block: ct_kem(1088) + sig_pub(1952) + signature(3309) + nonce(12) +
/// prefixes + header is well under 8 KiB of overhead.
fn pad_block_for(plaintext_len: usize) -> usize {
    plaintext_len + 8192
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn encrypt_decrypt_roundtrips(plaintext in prop::collection::vec(any::<u8>(), 0..4_096)) {
        let (kem_pk, kem_sk) = kem::keygen().unwrap();
        let (sig_pk, sig_sk) = sig::ml_dsa_65::keygen().unwrap();
        let pad_block = pad_block_for(plaintext.len());
        let blob = para_share::encrypt(&kem_pk, &sig_sk, &sig_pk, &plaintext, pad_block).unwrap();
        prop_assert_eq!(blob.len(), pad_block);
        let (recovered, sender_pub) = para_share::decrypt(&kem_sk, &blob).unwrap();
        prop_assert_eq!(recovered, plaintext);
        prop_assert_eq!(sender_pub, sig_pk.as_bytes().to_vec());
    }

    #[test]
    fn wrong_recipient_never_decrypts(plaintext in prop::collection::vec(any::<u8>(), 1..1_024)) {
        let (kem_pk, _kem_sk) = kem::keygen().unwrap();
        let (_kem_pk2, kem_sk2) = kem::keygen().unwrap();
        let (sig_pk, sig_sk) = sig::ml_dsa_65::keygen().unwrap();
        let pad_block = pad_block_for(plaintext.len());
        let blob = para_share::encrypt(&kem_pk, &sig_sk, &sig_pk, &plaintext, pad_block).unwrap();
        prop_assert!(para_share::decrypt(&kem_sk2, &blob).is_err());
    }

    #[test]
    fn tampered_ciphertext_rejected(
        plaintext in prop::collection::vec(any::<u8>(), 0..1_024),
        flip in 1u8..=255,
    ) {
        let (kem_pk, kem_sk) = kem::keygen().unwrap();
        let (sig_pk, sig_sk) = sig::ml_dsa_65::keygen().unwrap();
        let pad_block = pad_block_for(plaintext.len());
        let mut blob = para_share::encrypt(&kem_pk, &sig_sk, &sig_pk, &plaintext, pad_block).unwrap();
        // Last core byte is the final GCM tag byte; flipping it fails AEAD (and
        // would also break the signature that covers the ciphertext).
        let (_, consumed) = Envelope::decode_prefix(&blob).unwrap();
        blob[consumed - 1] ^= flip;
        prop_assert!(para_share::decrypt(&kem_sk, &blob).is_err());
    }
}

/// A multi-megabyte plaintext round-trips (too large for per-case proptest).
#[test]
fn large_plaintext_roundtrips() {
    let (kem_pk, kem_sk) = kem::keygen().unwrap();
    let (sig_pk, sig_sk) = sig::ml_dsa_65::keygen().unwrap();
    let plaintext: Vec<u8> = (0..2_000_000usize).map(|j| (j % 251) as u8).collect();
    let pad_block = pad_block_for(plaintext.len());
    let blob = para_share::encrypt(&kem_pk, &sig_sk, &sig_pk, &plaintext, pad_block).unwrap();
    let (recovered, sender_pub) = para_share::decrypt(&kem_sk, &blob).unwrap();
    assert_eq!(recovered, plaintext);
    assert_eq!(sender_pub, sig_pk.as_bytes().to_vec());
}
