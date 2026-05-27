# 0013. Merkle hash construction: RFC 6962

Date: 2026-05-27
Status: Accepted

## Context

Multiple Merkle tree hash constructions exist (raw concatenation, with
prefixes, with length-prefixing). Different choices are byte-incompatible with
existing CT-log infrastructure.

## Decision

Follow RFC 6962 Section 2:

- leaf:     `H(0x00 || leaf_data)`
- internal: `H(0x01 || left || right)`
- `H` = SHA-256

The empty tree hashes to `SHA-256("")`. Inclusion proofs and their verification
follow the same RFC (the verification walk is specified in RFC 9162 §2.1.3.2).
The Signed Tree Head signs `tree_size ‖ timestamp ‖ root_hash` (integers
big-endian) with ML-DSA-65, Paramant's default signature scheme (ADR-0008).

## Consequences

- Interoperable with existing Certificate Transparency tooling.
- Suitable for future public log inclusion (M11+).
- Slightly higher hash count vs. naive concat (acceptable cost).

## Alternatives

- Raw `H(left || right)`: rejected, the prefix prevents second-preimage attacks
  that confuse a leaf with an internal node.
- Length-prefixed: rejected, larger and unnecessary given the fixed output size
  of SHA-256.
