//! Property tests for wire format v1: `encode`/`decode` round-trips for arbitrary
//! valid envelopes, the decoder never panics on a mutated blob, and tampering
//! with the magic or version is always rejected.

use paramant_core::wire::{Envelope, Header, KemId, SigId};
use proptest::prelude::*;

fn kem_strategy() -> impl Strategy<Value = KemId> {
    prop_oneof![
        Just(KemId::MlKem512),
        Just(KemId::MlKem768),
        Just(KemId::MlKem1024),
    ]
}

fn sig_strategy() -> impl Strategy<Value = SigId> {
    prop_oneof![
        Just(SigId::None),
        Just(SigId::MlDsa44),
        Just(SigId::MlDsa65),
        Just(SigId::MlDsa87),
        Just(SigId::Falcon512),
        Just(SigId::SlhDsaShake256f),
    ]
}

prop_compose! {
    fn envelope_strategy()(
        kem_id in kem_strategy(),
        sig_id in sig_strategy(),
        ct_kem in prop::collection::vec(any::<u8>(), 0..300),
        sender_pub in prop::collection::vec(any::<u8>(), 0..300),
        sig_bytes in prop::collection::vec(any::<u8>(), 0..300),
        nonce in any::<[u8; 12]>(),
        ciphertext in prop::collection::vec(any::<u8>(), 0..300),
    ) -> Envelope {
        let signature = if sig_id.is_none() { None } else { Some(sig_bytes) };
        Envelope {
            header: Header { kem_id, sig_id, flags: 0x00 },
            ct_kem,
            sender_pub,
            signature,
            nonce,
            ciphertext,
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    // encode then decode is the identity for every valid envelope.
    #[test]
    fn encode_decode_roundtrips(env in envelope_strategy()) {
        let blob = env.encode().expect("valid envelope encodes");
        prop_assert_eq!(Envelope::decode(&blob).expect("decode"), env);
    }

    // A single flipped byte at any position must yield Ok or a clean Err  --  never
    // a panic (proptest fails the test if decode panics).
    #[test]
    fn mutated_blob_never_panics(
        env in envelope_strategy(),
        idx in any::<prop::sample::Index>(),
        xor in 1u8..=255,
    ) {
        let mut blob = env.encode().unwrap();
        let i = idx.index(blob.len());
        blob[i] ^= xor;
        let _ = Envelope::decode(&blob);
    }

    // Corrupting the magic bytes or the version byte is always rejected.
    #[test]
    fn magic_and_version_tampering_rejected(env in envelope_strategy(), which in 0u8..2) {
        let mut blob = env.encode().unwrap();
        if which == 0 {
            blob[0] ^= 0xFF;
        } else {
            blob[4] = blob[4].wrapping_add(1);
        }
        prop_assert!(Envelope::decode(&blob).is_err());
    }
}
