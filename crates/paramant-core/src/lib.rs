//! Paramant Core: post-quantum cryptographic substrate.
//!
//! See `BLUEPRINT.md` for the design and milestone plan. At **M0** this crate is
//! an intentionally empty shell — the cryptographic modules are added one
//! milestone at a time so every line lands with tests and review:
//!
//! - **M1** `kem` — ML-KEM-768 (+ hybrid ECDH P-256)
//! - **M2** `sig` — ML-DSA-65, SLH-DSA, Falcon
//! - **M3** `aead`, `kdf`, `mnemonic`
//! - **M4** `merkle`, `padding`, `envelope`, `wire`
//!
//! `paramant-relay` (build 2.5.0) is the reference: every primitive is checked
//! byte-for-byte against it via Known Answer Tests in `tests/kat/`.
