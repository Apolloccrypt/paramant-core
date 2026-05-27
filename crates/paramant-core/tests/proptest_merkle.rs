//! Property tests for the RFC 6962 Merkle tree: every appended leaf has a valid
//! inclusion proof against the current root, and any tampered proof is rejected.

use paramant_core::merkle::MerkleTree;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn every_leaf_has_a_verifying_proof(
        leaves in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..32), 1..40)
    ) {
        let mut tree = MerkleTree::new();
        for leaf in &leaves {
            tree.append(leaf);
        }
        let root = tree.root();
        prop_assert_eq!(tree.size(), leaves.len());

        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.inclusion_proof(i).unwrap();
            // The proof verifies against the actual root.
            prop_assert!(MerkleTree::verify_inclusion(&root, leaf, i, leaves.len(), &proof));

            // A tampered proof element always fails.
            if let Some(first) = proof.first() {
                let mut bad = proof.clone();
                bad[0][0] ^= 0x01;
                prop_assert_ne!(&bad[0], first);
                prop_assert!(!MerkleTree::verify_inclusion(&root, leaf, i, leaves.len(), &bad));
            }
        }

        // An out-of-range index has no proof.
        prop_assert!(tree.inclusion_proof(leaves.len()).is_err());
    }
}
