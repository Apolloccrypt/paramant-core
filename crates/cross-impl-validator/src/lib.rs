//! Cross-implementation KAT validation (test-only).
//!
//! This crate has no runtime code. Its integration tests run the RustCrypto
//! crates that `paramant-relay/crypto-wasm` depends on (`ml-kem`, `aes-gcm`,
//! `hkdf`/`sha2`) against the same `@noble`-anchored KAT vectors in
//! `tests/kat/` that paramant-core validates its `oqs`/`aws-lc-rs` backend
//! against. Passing tests prove the browser crypto's primitive layer is
//! byte-equivalent to the relay/SDK and native paths. See
//! `docs/adrs/0020-crypto-wasm-cross-impl-via-rustcrypto-crates.md`.
