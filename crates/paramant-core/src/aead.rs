//! AES-256-GCM authenticated encryption (FIPS 197 + NIST SP 800-38D) via AWS-LC.
//!
//! [`encrypt`] returns `ciphertext ‖ tag` (16-byte GCM tag appended); [`decrypt`]
//! consumes that same layout and verifies the tag before returning plaintext.
//!
//! **Nonce discipline:** the 96-bit nonce MUST be unique per key. Reusing a
//! `(key, nonce)` pair catastrophically breaks GCM confidentiality and
//! authenticity. The caller owns nonce generation; a debug assertion rejects the
//! all-zero nonce as a basic footgun guard. The key should come from zeroizing
//! storage (see `kem`/`sig` secret types); this module borrows it and never stores it.
//!
//! # Examples
//! ```
//! use paramant_core::aead;
//! let key = [7u8; aead::KEY_LEN];
//! let nonce = [1u8; aead::NONCE_LEN];
//! let ct = aead::encrypt(&key, &nonce, b"hdr", b"secret").unwrap();
//! assert_eq!(aead::decrypt(&key, &nonce, b"hdr", &ct).unwrap(), b"secret");
//! assert!(aead::decrypt(&key, &nonce, b"WRONG", &ct).is_err());
//! ```

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};

use crate::error::{CoreError, CoreResult};

/// AES-256 key length, in bytes.
pub const KEY_LEN: usize = 32;
/// GCM nonce length, in bytes (96 bits).
pub const NONCE_LEN: usize = 12;
/// GCM authentication tag length, in bytes.
pub const TAG_LEN: usize = 16;

fn load_key(key: &[u8; KEY_LEN]) -> CoreResult<LessSafeKey> {
    let unbound = UnboundKey::new(&AES_256_GCM, key).map_err(|_| CoreError::Aead("invalid key"))?;
    Ok(LessSafeKey::new(unbound))
}

/// Encrypt `plaintext`, returning `ciphertext ‖ tag`.
///
/// `aad` is authenticated but not encrypted. The `nonce` must be unique for this
/// `key`.
///
/// # Errors
/// [`CoreError::Aead`] if AWS-LC rejects the key or the operation fails.
pub fn encrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> CoreResult<Vec<u8>> {
    debug_assert_ne!(nonce, &[0u8; NONCE_LEN], "all-zero AES-GCM nonce");
    let key = load_key(key)?;
    let mut buf = plaintext.to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(*nonce),
        Aad::from(aad),
        &mut buf,
    )
    .map_err(|_| CoreError::Aead("encryption failed"))?;
    Ok(buf)
}

/// Decrypt `ciphertext ‖ tag`, verifying the tag, and return the plaintext.
///
/// # Errors
/// [`CoreError::Aead`] if the input is too short, the tag is invalid, or the
/// `aad`/`nonce`/`key` do not match those used to encrypt.
pub fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> CoreResult<Vec<u8>> {
    if ciphertext_and_tag.len() < TAG_LEN {
        return Err(CoreError::Aead("ciphertext shorter than the tag"));
    }
    let key = load_key(key)?;
    let mut buf = ciphertext_and_tag.to_vec();
    let plaintext = key
        .open_in_place(
            Nonce::assume_unique_for_key(*nonce),
            Aad::from(aad),
            &mut buf,
        )
        .map_err(|_| CoreError::Aead("decryption failed (bad tag, nonce, key, or aad)"))?;
    Ok(plaintext.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_with_aad() {
        let key = [3u8; KEY_LEN];
        let nonce = [9u8; NONCE_LEN];
        let ct = encrypt(&key, &nonce, b"header", b"the message").unwrap();
        assert_eq!(ct.len(), b"the message".len() + TAG_LEN);
        assert_eq!(
            decrypt(&key, &nonce, b"header", &ct).unwrap(),
            b"the message"
        );
    }

    #[test]
    fn tampering_and_wrong_aad_rejected() {
        let key = [3u8; KEY_LEN];
        let nonce = [9u8; NONCE_LEN];
        let mut ct = encrypt(&key, &nonce, b"header", b"msg").unwrap();
        assert!(decrypt(&key, &nonce, b"other", &ct).is_err()); // wrong aad
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(decrypt(&key, &nonce, b"header", &ct).is_err()); // tampered tag
        assert!(decrypt(&key, &nonce, b"header", &[0u8; 4]).is_err()); // too short
    }

    #[test]
    fn empty_plaintext_and_aad() {
        let key = [1u8; KEY_LEN];
        let nonce = [2u8; NONCE_LEN];
        let ct = encrypt(&key, &nonce, b"", b"").unwrap();
        assert_eq!(ct.len(), TAG_LEN);
        assert_eq!(decrypt(&key, &nonce, b"", &ct).unwrap(), b"");
    }
}
