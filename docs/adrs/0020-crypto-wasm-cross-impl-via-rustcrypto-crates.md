# 0020. crypto-wasm cross-impl validation via RustCrypto crate KAT

Date: 2026-05-27
Status: Accepted

## Context

The browser KEM flows (parashare, drop, ontvang) run on
`paramant-relay/crypto-wasm` (RustCrypto, compiled to WASM), a separate crypto
path from paramant-core (`oqs` + `aws-lc-rs`, native + Node) and from the SDK's
`@noble`. crypto-wasm shipped without KAT validation, ADR coverage, or CI.

Two facts shaped the decision:

1. **paramant-core cannot target wasm32.** `oqs` (liboqs, C via cmake) and
   `aws-lc-rs` (AWS-LC, C) have no wasm32 support, and paramant-core has no
   feature-gated pure-Rust backend. So a `paramant-core-wasm` mirroring the M5a
   NAPI binding is not buildable; the browser must use a pure-Rust crypto, which
   is exactly what crypto-wasm already is.
2. **crypto-wasm exposes only `encrypt_blob`/`decrypt_blob`** -- both randomised
   (ephemeral ECDH, randomised ML-KEM encapsulation, random nonce/padding) and
   with no deterministic primitive accessors. Byte-equivalence testing of the
   shipped wasm artifact would require adding exports, rebuilding it, and
   updating the production `WASM_SHA256` integrity pin in `crypto-bridge.js` --
   a production-visible change.

The wire formats also differ by design (0x03 hybrid ML-KEM+ECDH vs PQHB single
ML-KEM; `info = "paramant-v2"` vs `"paramant-v1-aes-key"`), and the relay
blind-stores non-PQHB blobs, so wire convergence buys no interoperability (see
`docs/wire-format-boundaries.md`).

## Decision

Validate the **RustCrypto crates crypto-wasm depends on** (`ml-kem`, `aes-gcm`,
`hkdf`, `sha2`) against the same `@noble`-anchored KAT vectors in `tests/kat/`
that paramant-core checks its `oqs`/`aws-lc-rs` backend against.

- A test-only crate, `crates/cross-impl-validator` (no lib consumers, dev-deps
  only), runs ml-kem decapsulation, AES-256-GCM and HKDF-SHA256 over the existing
  vectors. A `cross-impl-rustcrypto-kat` CI job gates it.
- Because both paramant-core's backend and these crates are validated against the
  same `@noble` anchors, primitive-level byte-equivalence holds transitively
  across all three crypto paths (oqs/aws-lc-rs, RustCrypto, @noble).
- crypto-wasm stays vendored in paramant-relay; governance is the paramant-core
  docs (`wire-format-boundaries.md`, `wire-format-0x03.md`) plus this KAT
  harness. No submodule.

## Consequences

- The browser crypto's primitive layer now has an audited, CI-gated KAT, closing
  the gap, with zero production-bundle risk (no crypto-wasm change, no
  `WASM_SHA256` pin change, no frontend redeploy).
- The crates are pinned to the same majors crypto-wasm uses (`ml-kem 0.3.x`,
  `aes-gcm 0.10`); a major bump in either repo is caught by re-running the KAT.
- The **shipped wasm artifact** itself is not byte-tested at this layer; the
  harness validates the crates it is built from. Full as-shipped testing (B2:
  deterministic exports + Node-wasm KAT) is deferred to whenever the browser
  bundle is rebuilt and re-pinned anyway.
- The cross-impl-validator pulls RustCrypto into the workspace dev-dependency
  graph; it is test-only and never enters a shipping artifact.

## Alternatives

- **B2 (add deterministic exports to crypto-wasm, KAT the shipped wasm)**:
  rejected for this milestone -- mutates the production browser bundle and its
  integrity pin. Reserved for the next frontend rebuild.
- **Submodule paramant-relay into paramant-core**: rejected -- too heavy for the
  governance need; docs + crate KAT suffice.
- **Build a paramant-core-wasm**: rejected -- paramant-core's C deps cannot
  target wasm32; it would require a third crypto backend (this is what
  crypto-wasm already is).
- **Force wire-format convergence (0x03 -> PQHB)**: rejected -- churn with no
  functional gain; the relay never reads browser blobs.
