use thiserror::Error;

#[derive(Error, Debug)]
pub enum ParamantError {
    #[error("KEM error: {0}")]
    Kem(String),
    #[error("ECDH error: {0}")]
    Ecdh(String),
    #[error("Encryption error: {0}")]
    Encryption(String),
    #[error("Decryption failed — wrong key or tampered message")]
    DecryptionFailed,
    #[error("Replay attack detected — nonce already seen")]
    ReplayDetected,
    #[error("Invalid key: {0}")]
    InvalidKey(String),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Relay error: {0}")]
    Relay(String),
    #[error("Session not initialized")]
    SessionNotInitialized,
}
