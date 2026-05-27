//! BIP-0039 12-word English mnemonics.
//!
//! A [`Mnemonic`] is a human-transcribable encoding of 128 bits of entropy plus
//! a 4-bit checksum. [`Mnemonic::to_seed`] stretches it (PBKDF2-HMAC-SHA512,
//! 2048 rounds) into the 64-byte seed that higher layers feed to a KDF.
//!
//! English only, 12 words only  --  a deliberate single shape so wallets and the
//! relay agree without negotiating word counts or languages.
//!
//! # Examples
//! ```
//! use paramant_core::mnemonic::Mnemonic;
//! let entropy = [0u8; 16];
//! let m = Mnemonic::generate_from_entropy(entropy).unwrap();
//! assert_eq!(m.word_count(), 12);
//! // Round-trips through its phrase.
//! let again = Mnemonic::parse(&m.phrase()).unwrap();
//! assert_eq!(m.to_seed("")[..], again.to_seed("")[..]);
//! ```

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use bip39::{Language, Mnemonic as Bip39Mnemonic};
use zeroize::Zeroizing;

use crate::error::{CoreError, CoreResult};

/// 128 bits of entropy  ->  a 12-word mnemonic.
const ENTROPY_LEN: usize = 16;

/// A validated 12-word BIP-0039 English mnemonic.
pub struct Mnemonic(Bip39Mnemonic);

impl Mnemonic {
    /// Generate a fresh 12-word mnemonic from 128 bits of operating-system
    /// entropy (`aws-lc-rs` `SystemRandom`). The entropy is wiped after use.
    ///
    /// # Errors
    /// [`CoreError::Mnemonic`] if the system RNG fails.
    pub fn generate() -> CoreResult<Self> {
        let mut entropy = Zeroizing::new([0u8; ENTROPY_LEN]);
        SystemRandom::new()
            .fill(entropy.as_mut())
            .map_err(|_| CoreError::Mnemonic("RNG failure"))?;
        Self::generate_from_entropy(*entropy)
    }

    /// Build a 12-word mnemonic from exactly 16 bytes of entropy.
    ///
    /// # Errors
    /// [`CoreError::Mnemonic`] if the BIP-0039 encoding rejects the entropy.
    pub fn generate_from_entropy(entropy: [u8; ENTROPY_LEN]) -> CoreResult<Self> {
        Bip39Mnemonic::from_entropy_in(Language::English, &entropy)
            .map(Self)
            .map_err(|_| CoreError::Mnemonic("invalid entropy"))
    }

    /// Parse and validate an English mnemonic phrase (any valid word count).
    ///
    /// The input is Unicode-normalized and its checksum verified.
    ///
    /// # Errors
    /// [`CoreError::Mnemonic`] if a word is unknown or the checksum is wrong.
    pub fn parse(phrase: &str) -> CoreResult<Self> {
        Bip39Mnemonic::parse_in(Language::English, phrase)
            .map(Self)
            .map_err(|_| CoreError::Mnemonic("invalid mnemonic"))
    }

    /// Derive the 64-byte BIP-0039 seed for an optional `passphrase`.
    ///
    /// Uses PBKDF2-HMAC-SHA512 over 2048 rounds; both mnemonic and passphrase
    /// are Unicode-normalized (NFKD) per the spec. The seed is wiped on drop.
    pub fn to_seed(&self, passphrase: &str) -> Zeroizing<[u8; 64]> {
        Zeroizing::new(self.0.to_seed(passphrase))
    }

    /// The raw entropy this mnemonic encodes (16 bytes for a 12-word phrase).
    ///
    /// This is the secret material itself (not the BIP-0039 seed); it is the
    /// HKDF input for ParaDrop key derivation. Wiped on drop.
    pub fn to_entropy(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.to_entropy())
    }

    /// The mnemonic as a space-separated phrase.
    pub fn phrase(&self) -> String {
        self.0.to_string()
    }

    /// Number of words in the mnemonic.
    pub fn word_count(&self) -> usize {
        self.0.word_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_is_twelve_words_and_parses() {
        let m = Mnemonic::generate().unwrap();
        assert_eq!(m.word_count(), 12);
        assert!(Mnemonic::parse(&m.phrase()).is_ok());
    }

    #[test]
    fn rejects_bad_checksum_and_unknown_words() {
        // Valid words, wrong checksum (all "abandon").
        assert!(Mnemonic::parse("abandon ".repeat(12).trim_end()).is_err());
        // Unknown word.
        assert!(Mnemonic::parse("notaword ".repeat(12).trim_end()).is_err());
    }

    #[test]
    fn passphrase_changes_the_seed() {
        let m = Mnemonic::generate_from_entropy([7u8; ENTROPY_LEN]).unwrap();
        assert_ne!(m.to_seed("")[..], m.to_seed("pass")[..]);
    }
}
