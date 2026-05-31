//! Envelope modes: complete encrypt/decrypt flows composed over the `wire`
//! codec and the M1-M3 primitives.
//!
//! Each mode is a distinct integration of KEM, AEAD, KDF and (optionally)
//! signatures behind the PQHB wire format, byte-equivalent with the matching
//! `paramant-relay` `sdk-js` flow (ADR-0003, ADR-0014).
//!
//! - [`send`] -- anonymous KEM send (relay `sendAnonymous`, `SIG_ID = 0x0000`).
//! - [`para_share`] -- signed, device-paired send (relay `send`, ML-DSA-65).

use aws_lc_rs::rand::{SecureRandom, SystemRandom};

use crate::error::{CoreError, CoreResult};
use crate::wire::NONCE_SIZE;

pub mod para_share;
pub mod send;

/// 12 random bytes from the system CSPRNG for use as an AES-GCM nonce.
///
/// `SystemRandom::fill` only fails on catastrophic OS RNG failure; like
/// `padding.rs` we treat that as unrecoverable.
pub(crate) fn random_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    SystemRandom::new()
        .fill(&mut nonce)
        .expect("system RNG failure");
    nonce
}

/// Append random bytes to `core` so the result is exactly `pad_block` long
/// (the relay's outer padding). The core boundary is recovered on decode via
/// [`crate::wire::Envelope::decode_prefix`].
///
/// # Errors
/// [`CoreError::Wire`] if `core` is already larger than `pad_block`.
pub(crate) fn pad_to_block(mut core: Vec<u8>, pad_block: usize) -> CoreResult<Vec<u8>> {
    if core.len() > pad_block {
        return Err(CoreError::Wire("encoded core larger than pad_block"));
    }
    let from = core.len();
    core.resize(pad_block, 0);
    SystemRandom::new()
        .fill(&mut core[from..])
        .map_err(|_| CoreError::Wire("padding RNG failure"))?;
    Ok(core)
}
