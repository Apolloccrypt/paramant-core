//! Envelope modes: complete encrypt/decrypt flows composed over the `wire`
//! codec and the M1–M3 primitives.
//!
//! Each mode is a distinct integration of KEM, AEAD, KDF and (optionally)
//! signatures behind the PQHB wire format, byte-equivalent with the matching
//! `paramant-relay` `sdk-js` flow (ADR-0003, ADR-0014).
//!
//! - [`send`] — anonymous KEM send (relay `sendAnonymous`, `SIG_ID = 0x0000`).
//!
//! ParaShare (signed, device-paired) and ParaDrop (BIP-39 mnemonic) arrive in
//! later phases; their modules are added when implemented (principle D — no
//! empty scaffolding).

pub mod send;
