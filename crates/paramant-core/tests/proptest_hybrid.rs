//! Property test: every hybrid (ML-KEM-768 + ECDH P-256) keypair round-trips.

use paramant_core::kem::hybrid;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn keygen_encaps_decaps_roundtrip(_iter in any::<u16>()) {
        // keygen/encaps draw fresh randomness; the input just drives the count.
        let (pk, sk) = hybrid::keygen().unwrap();
        let (ct, ss_sender) = hybrid::encaps(&pk).unwrap();
        let ss_receiver = hybrid::decaps(&sk, &ct).unwrap();
        prop_assert_eq!(ss_sender.as_bytes(), ss_receiver.as_bytes());
        prop_assert_eq!(ss_sender.as_bytes().len(), hybrid::SHARED_SECRET_LEN);
    }
}
