# 0021. Cross-impl ML-DSA-65 validation (RustCrypto vs oqs/@noble)

Date: 2026-05-27
Status: Accepted

## Context

ParaSign (planned signing product, Sg0 ADRs in `paramant-sign-spec/`) signs in
the browser with ML-DSA-65 via the pure-Rust RustCrypto `ml-dsa` crate (the only
wasm-capable option; oqs is C and cannot target wasm32, ADR-0020). paramant-core
verifies with the mature liboqs ML-DSA-65 server-side. Before `crypto-wasm` is
extended with ML-DSA exports (ParaSign Sg1 step 2), the RustCrypto crate must be
proven equivalent to the implementation paramant-core already trusts.

`ml-dsa` is at `0.1.0` -- fresh and pre-audit (the RustCrypto/signatures team has
not published a completed review), well behind its sibling `ml-kem` (`0.3.2`).
ADR-0020 established the cross-impl-validator pattern for exactly this risk.

## Decision

Extend `crates/cross-impl-validator` with an ML-DSA-65 test that runs `ml-dsa
0.1.0` against the same 50 `@noble`-anchored vectors in `tests/kat/ml-dsa-65.json`
that paramant-core validates oqs against:

1. **Verify-KAT.** For all 50 vectors, `VerifyingKey::verify_with_context(msg,
   &[], &sig)` accepts the `@noble` signature, and a flipped message is rejected.
   Signing is randomised so sign-output bytes are not comparable; verification is
   the equivalence proof -- a divergent implementation would reject valid
   signatures. The matching variant is **external ML-DSA verify with an empty
   context** (the same `@noble`/oqs use); `verify_internal` is the raw variant
   and is not what these vectors use.
2. **Seeded-keygen-KAT.** For all 50 vectors, `SigningKey::<MlDsa65>::from_seed(
   xi).verifying_key().encode()` reproduces the `@noble` public key for the same
   32-byte seed. This confirms ml-dsa 0.1.0 exposes deterministic seeded keygen
   (`from_seed`, `Seed = B32`) **and** that it is byte-equivalent -- the property
   ParaSign Sg0 ADR-3's mnemonic-deterministic signing key relies on.

Both run under `cargo test -p cross-impl-validator` in the existing
`cross-impl-rustcrypto-kat` CI job.

## Consequences

- ParaSign Sg1 can proceed: a browser ML-DSA-65 signature produced by `ml-dsa`
  will verify identically on the server via paramant-core's oqs, and a
  mnemonic-derived seed yields the same public-key identity across
  implementations.
- Cross-impl divergence is now caught in CI on every push, before any browser
  deployment.
- `ml-dsa 0.1.0` remains pre-audit. Residual risk is mitigated, not eliminated:
  1. verify-KAT proves byte/verify equivalence with the FIPS-204 `@noble` vectors;
  2. server-side verification runs the mature oqs implementation;
  3. a faulty browser signer produces signatures that simply fail verification
     (loud failure, no silent forgery);
  4. ParaSign launches as beta until `ml-dsa` reaches an independent audit or a
     stabilised release.

## Alternatives

- **Server-side oqs signing (Sg0 ADR-1 Option A)**: rejected -- custodial, the
  relay could forge, breaking non-repudiation.
- **Wait for `ml-dsa` audit before any ParaSign work**: rejected -- the
  validation harness + mature-side verification + beta labelling let Sg1 proceed
  without trusting the immature signer blindly.
- **A different pure-Rust ML-DSA crate**: none more mature than RustCrypto
  `ml-dsa` as of 2026-05-27.
