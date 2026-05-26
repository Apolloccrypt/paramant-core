//! Property test: AES-256-GCM encrypt→decrypt round-trips for arbitrary inputs,
//! and authentication rejects a changed AAD.

use paramant_core::aead;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn roundtrip_and_aad_binding(
        key in any::<[u8; 32]>(),
        nonce in any::<[u8; 12]>(),
        aad in prop::collection::vec(any::<u8>(), 0..64),
        pt in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        prop_assume!(nonce != [0u8; 12]); // encrypt debug-asserts a non-zero nonce

        let ct = aead::encrypt(&key, &nonce, &aad, &pt).unwrap();
        prop_assert_eq!(aead::decrypt(&key, &nonce, &aad, &ct).unwrap(), pt);

        // Changing the AAD must break authentication.
        let mut other_aad = aad.clone();
        other_aad.push(0xAB);
        prop_assert!(aead::decrypt(&key, &nonce, &other_aad, &ct).is_err());
    }
}
