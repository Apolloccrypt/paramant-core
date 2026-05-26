//! Property test: ML-DSA-65 sign-then-verify round-trips for arbitrary messages,
//! and a signature does not verify against a different message.

use paramant_core::sig::ml_dsa_65;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn sign_verify_roundtrip(msg in prop::collection::vec(any::<u8>(), 0..256)) {
        let (pk, sk) = ml_dsa_65::keygen().unwrap();
        let sig = ml_dsa_65::sign(&sk, &msg).unwrap();
        prop_assert!(ml_dsa_65::verify(&pk, &msg, &sig).unwrap());

        // Appending a byte changes the message, so the signature must not verify.
        let mut other = msg.clone();
        other.push(0xAB);
        prop_assert!(!ml_dsa_65::verify(&pk, &other, &sig).unwrap());
    }
}
