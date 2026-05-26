//! Property test: every ML-KEM-768 keypair round-trips — the secret a sender
//! encapsulates is exactly the secret the receiver decapsulates.

use paramant_core::kem;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn keygen_encaps_decaps_roundtrip(_iter in any::<u32>()) {
        // keygen/encaps draw fresh randomness from the system RNG; the proptest
        // input just drives the case count.
        let (pk, sk) = kem::keygen().unwrap();
        let (ct, ss_sender) = kem::encaps(&pk).unwrap();
        let ss_receiver = kem::decaps(&sk, &ct).unwrap();
        prop_assert_eq!(ss_sender.as_bytes(), ss_receiver.as_bytes());
        prop_assert_eq!(ss_sender.as_bytes().len(), kem::SHARED_SECRET_LEN);
    }
}
