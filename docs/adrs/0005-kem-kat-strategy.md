# 0005. ML-KEM KAT strategy: decaps vectors + interop, not keygen replay

Datum: 2026-05-26
Status: Geaccepteerd

## Context

M1 calls for byte-equivalence between paramant-core's ML-KEM-768 and
paramant-relay's (`@noble/post-quantum`). Byte-for-byte *replay* of keygen and
encaps requires deterministic (seed / `derand`) entry points. The oqs stack
(`oqs` 0.10.1 → `oqs-sys` 0.10.1 → liboqs 0.12.0) binds only the randomized
`keypair` / `encaps` / `decaps`; there are **no `*_derand` symbols** in the
generated bindings. So a given seed's public key or ciphertext cannot be
reproduced through oqs.

## Beslissing

Prove parity on what is deterministic, and interop on the rest.

- **Decapsulation KAT (byte-equivalent).** `@noble` generates deterministic
  `(seed → pk, sk, ct, ss)` vectors; paramant-core asserts `decaps(sk, ct) == ss`
  byte-for-byte for each. Pins the receiver path exactly.
- **Cross-implementation interop.** `core.encaps(noble_pk)` decapsulated by
  `@noble` yields the same secret, and `@noble.encaps(core_pk)` decapsulated by
  the core yields the same secret. This proves wire-compatibility both
  directions — the property that actually lets the relay adopt the core with no
  client-visible change.
- **No `keygen_from_seed` / `encaps_from_seed`** in the public API; oqs cannot
  honour them.

## Consequenties

- **No `unsafe`** in the core: only the oqs safe API is used.
- The blueprint's "30 byte-equivalent KAT vectors" becomes 30 deterministic
  decaps vectors plus interop tests — same confidence in wire-compatibility.
- If a later oqs/liboqs exposes `derand`, or we move to a pure-Rust ML-KEM with
  deterministic keygen at M9 ([ADR-0002](0002-oqs-vs-pure-rust.md)), full keygen
  replay can be added without changing the public API.

## Alternatieven

- **oqs-sys FFI to liboqs `derand`**: rejected — the symbols are not bound by
  oqs-sys 0.10.1; would need a vendored fork plus `unsafe` FFI for no real gain
  over interop testing.
- **Swap ML-KEM to RustCrypto `ml-kem` (deterministic keygen)**: rejected for M1
  — violates ADR-0002 (oqs through M7); revisit at M9.
