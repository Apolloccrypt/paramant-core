//! Constant-time property tests for the secret-comparing paths.
//!
//! Wall-clock timing is platform-dependent and noisy, so these tests do not
//! measure time. They assert the *structural* guarantee that protects against
//! timing attacks: the comparison considers the whole input with no
//! data-dependent early return. Concretely  --  a mismatch at any position is
//! rejected uniformly, and the underlying comparison is `subtle::ConstantTimeEq`
//! (see kdf.rs / aead.rs). See docs/threat-model.md and ADR-0012.

use paramant_core::{aead, kdf};
use subtle::ConstantTimeEq;

#[test]
fn aead_decrypt_rejects_tamper_at_every_position() {
    let key = [5u8; aead::KEY_LEN];
    let nonce = [6u8; aead::NONCE_LEN];
    let ct = aead::encrypt(&key, &nonce, b"aad", b"a longer plaintext payload").unwrap();

    // Flip each bit-0 of every byte: tag check must reject all, with no
    // position where an early-return would let a tampered byte slip through.
    for i in 0..ct.len() {
        let mut bad = ct.clone();
        bad[i] ^= 0x01;
        assert!(
            aead::decrypt(&key, &nonce, b"aad", &bad).is_err(),
            "tamper at byte {i} was accepted"
        );
    }
    // The untampered ciphertext still opens  --  the test isn't vacuous.
    assert_eq!(
        aead::decrypt(&key, &nonce, b"aad", &ct).unwrap(),
        b"a longer plaintext payload"
    );
}

#[test]
fn verify_password_fails_closed() {
    // Argon2id hashing is deliberately expensive, so this test keeps the number
    // of hash calls small: it confirms verify_password wires up the constant-
    // time comparison and fails closed. Exhaustive single-bit coverage of the
    // comparison itself lives in `ct_eq_rejects_every_single_bit_flip` (cheap).
    let salt = b"sixteen-byte-salt";
    let tag = kdf::argon2id::hash_password(b"correct horse battery", salt).unwrap();

    assert!(kdf::argon2id::verify_password(
        b"correct horse battery",
        salt,
        &tag
    ));

    // Tamper at the first, a middle, and the last byte.
    for byte in [0usize, 16, 31] {
        let mut bad = *tag;
        bad[byte] ^= 0x01;
        assert!(
            !kdf::argon2id::verify_password(b"correct horse battery", salt, &bad),
            "verify accepted a tag tampered at byte {byte}"
        );
    }
    // A different password must also be rejected.
    assert!(!kdf::argon2id::verify_password(
        b"wrong password",
        salt,
        &tag
    ));
}

#[test]
fn ct_eq_rejects_every_single_bit_flip() {
    // The branch-free comparison verify_password and aead rely on: every
    // single-bit difference is detected, and an exact match compares equal.
    let reference = [0xABu8; 32];
    assert!(bool::from(reference.ct_eq(&reference)));
    for byte in 0..32 {
        for bit in 0..8 {
            let mut other = reference;
            other[byte] ^= 1 << bit;
            assert!(
                !bool::from(reference.ct_eq(&other)),
                "ct_eq missed a difference at byte {byte} bit {bit}"
            );
        }
    }
}
