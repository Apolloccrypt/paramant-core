//! Append-only Merkle tree with RFC 6962 hash construction.
//!
//! Hashing follows RFC 6962 (Certificate Transparency) so the tree interoperates
//! with existing CT-log tooling and is auditable against public-log
//! infrastructure (see `docs/adrs/0013-merkle-rfc6962-hash-construction.md`):
//!
//! - leaf hash:     `SHA-256(0x00 || leaf_data)`
//! - internal hash: `SHA-256(0x01 || left_hash || right_hash)`
//! - empty tree:    `SHA-256("")`
//!
//! A [`SignedTreeHead`] binds the tree size, a timestamp, and the root hash with
//! an ML-DSA-65 signature (`paramant-relay`'s default scheme).

use sha2::{Digest, Sha256};

use crate::error::{CoreError, CoreResult};
use crate::sig::ml_dsa_65;

/// Hash of a leaf's data: `SHA-256(0x00 || data)` (RFC 6962 §2.1).
fn hash_leaf(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(data);
    h.finalize().into()
}

/// Hash of two child subtrees: `SHA-256(0x01 || left || right)` (RFC 6962 §2.1).
fn hash_children(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Largest power of two strictly less than `n` (`n >= 2`); the RFC 6962 split point.
fn split_point(n: usize) -> usize {
    debug_assert!(n >= 2);
    1usize << (usize::BITS - 1 - (n as u64 - 1).leading_zeros())
}

/// Merkle Tree Hash of a list of already-computed leaf hashes (RFC 6962 §2.1).
fn mth(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        0 => Sha256::digest([]).into(),
        1 => leaves[0],
        n => {
            let k = split_point(n);
            hash_children(&mth(&leaves[..k]), &mth(&leaves[k..]))
        }
    }
}

/// The RFC 6962 audit path for leaf `m` within `leaves` (`m < leaves.len()`).
fn path(m: usize, leaves: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let n = leaves.len();
    if n == 1 {
        return Vec::new();
    }
    let k = split_point(n);
    if m < k {
        let mut p = path(m, &leaves[..k]);
        p.push(mth(&leaves[k..]));
        p
    } else {
        let mut p = path(m - k, &leaves[k..]);
        p.push(mth(&leaves[..k]));
        p
    }
}

/// An append-only Merkle tree over arbitrary byte leaves (RFC 6962).
#[derive(Debug, Clone, Default)]
pub struct MerkleTree {
    leaves: Vec<[u8; 32]>,
}

impl MerkleTree {
    /// Create an empty tree. Its root is `SHA-256("")`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a leaf, hashing it as `SHA-256(0x00 || leaf)`.
    pub fn append(&mut self, leaf: &[u8]) {
        self.leaves.push(hash_leaf(leaf));
    }

    /// The current Merkle Tree Hash (root). An empty tree hashes to `SHA-256("")`.
    pub fn root(&self) -> [u8; 32] {
        mth(&self.leaves)
    }

    /// The number of leaves in the tree.
    pub fn size(&self) -> usize {
        self.leaves.len()
    }

    /// The RFC 6962 inclusion (audit) proof for the leaf at `leaf_index`.
    ///
    /// # Errors
    /// [`CoreError::Merkle`] if `leaf_index` is not within the tree.
    pub fn inclusion_proof(&self, leaf_index: usize) -> CoreResult<Vec<[u8; 32]>> {
        if leaf_index >= self.leaves.len() {
            return Err(CoreError::Merkle("leaf index out of range"));
        }
        Ok(path(leaf_index, &self.leaves))
    }

    /// Verify an inclusion proof against a `root`, reconstructing it from the leaf
    /// (RFC 6962 / RFC 9162 §2.1.3.2). Returns `false` for any inconsistency.
    pub fn verify_inclusion(
        root: &[u8; 32],
        leaf: &[u8],
        leaf_index: usize,
        tree_size: usize,
        proof: &[[u8; 32]],
    ) -> bool {
        if leaf_index >= tree_size {
            return false;
        }
        let mut fnode = leaf_index;
        let mut snode = tree_size - 1;
        let mut r = hash_leaf(leaf);
        for p in proof {
            if snode == 0 {
                return false; // proof longer than the tree's depth
            }
            if fnode & 1 == 1 || fnode == snode {
                r = hash_children(p, &r);
                if fnode & 1 == 0 {
                    while fnode & 1 == 0 && fnode != 0 {
                        fnode >>= 1;
                        snode >>= 1;
                    }
                }
            } else {
                r = hash_children(&r, p);
            }
            fnode >>= 1;
            snode >>= 1;
        }
        snode == 0 && r == *root
    }
}

/// A signed commitment to the tree's state at a point in time (RFC 6962 STH).
///
/// The signature covers `tree_size ‖ timestamp ‖ root_hash`, with the two
/// integers serialized big-endian, signed with ML-DSA-65.
#[derive(Debug, Clone)]
pub struct SignedTreeHead {
    /// Number of leaves the head commits to.
    pub tree_size: u64,
    /// Issuance time, Unix milliseconds.
    pub timestamp: u64,
    /// The Merkle root at `tree_size`.
    pub root_hash: [u8; 32],
    /// ML-DSA-65 signature over the serialized head.
    pub signature: Vec<u8>,
}

impl SignedTreeHead {
    /// The canonical signed message: `tree_size_be ‖ timestamp_be ‖ root_hash`.
    fn message(tree_size: u64, timestamp: u64, root_hash: &[u8; 32]) -> [u8; 48] {
        let mut m = [0u8; 48];
        m[..8].copy_from_slice(&tree_size.to_be_bytes());
        m[8..16].copy_from_slice(&timestamp.to_be_bytes());
        m[16..].copy_from_slice(root_hash);
        m
    }

    /// Sign `tree`'s current root at `timestamp` with an ML-DSA-65 secret key.
    ///
    /// # Errors
    /// [`CoreError::Sig`] if signing fails.
    pub fn sign(tree: &MerkleTree, sk: &ml_dsa_65::SecretKey, timestamp: u64) -> CoreResult<Self> {
        let tree_size = tree.size() as u64;
        let root_hash = tree.root();
        let msg = Self::message(tree_size, timestamp, &root_hash);
        let sig = ml_dsa_65::sign(sk, &msg)?;
        Ok(Self {
            tree_size,
            timestamp,
            root_hash,
            signature: sig.as_bytes().to_vec(),
        })
    }

    /// Verify the head's signature against an ML-DSA-65 public key. Returns
    /// `false` for a malformed or invalid signature.
    pub fn verify(&self, pk: &ml_dsa_65::PublicKey) -> bool {
        let sig = match ml_dsa_65::Signature::from_bytes(&self.signature) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let msg = Self::message(self.tree_size, self.timestamp, &self.root_hash);
        ml_dsa_65::verify(pk, &msg, &sig).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tree_root_is_sha256_of_empty() {
        let t = MerkleTree::new();
        assert_eq!(t.size(), 0);
        let expected: [u8; 32] = Sha256::digest([]).into();
        assert_eq!(t.root(), expected);
    }

    #[test]
    fn single_leaf_root_is_leaf_hash() {
        let mut t = MerkleTree::new();
        t.append(b"");
        assert_eq!(t.root(), hash_leaf(b""));
    }

    #[test]
    fn proofs_verify_and_tamper_rejected() {
        let mut t = MerkleTree::new();
        for i in 0..17u8 {
            t.append(&[i]);
        }
        let root = t.root();
        for i in 0..t.size() {
            let proof = t.inclusion_proof(i).unwrap();
            assert!(MerkleTree::verify_inclusion(
                &root,
                &[i as u8],
                i,
                t.size(),
                &proof
            ));
            let mut bad = proof.clone();
            if let Some(first) = bad.first_mut() {
                first[0] ^= 0x01;
                assert!(!MerkleTree::verify_inclusion(
                    &root,
                    &[i as u8],
                    i,
                    t.size(),
                    &bad
                ));
            }
        }
        assert!(t.inclusion_proof(t.size()).is_err());
    }

    #[test]
    fn sth_sign_verify_roundtrip() {
        let mut t = MerkleTree::new();
        t.append(b"a");
        t.append(b"b");
        let (pk, sk) = ml_dsa_65::keygen().unwrap();
        let sth = SignedTreeHead::sign(&t, &sk, 1_700_000_000_000).unwrap();
        assert!(sth.verify(&pk));
        let mut tampered = sth.clone();
        tampered.root_hash[0] ^= 0x01;
        assert!(!tampered.verify(&pk));
    }
}
