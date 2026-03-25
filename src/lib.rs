// PARAMANT Core — Post-Quantum Crypto Library
// Mick Beer, 2026
//
// Architectuur identiek aan browser implementatie:
//   ML-KEM-768 + ECDH P-256  →  HKDF master  →  AES-256-GCM ratchet
//
// Modules:
//   crypto::kem     — ML-KEM-768 key encapsulation
//   crypto::ecdh    — ECDH P-256 key exchange
//   crypto::kdf     — HKDF sleutelafleiding
//   crypto::aead    — AES-256-GCM encryptie/decryptie
//   ratchet         — Dubbel ratchet protocol + KEM injectie
//   identity        — Sleutelpaar generatie + adres
//   session         — Volledige chat sessie
//   relay           — WebSocket relay client
//   error           — Error types

pub mod crypto;
pub mod ratchet;
pub mod identity;
pub mod session;
pub mod relay;
pub mod error;

pub use error::ParamantError;
pub type Result<T> = std::result::Result<T, ParamantError>;
