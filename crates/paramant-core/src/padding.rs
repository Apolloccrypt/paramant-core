//! Length-hiding block padding.
//!
//! Plaintext is padded out to a fixed block boundary so that an observer learns
//! only the block tier, not the exact length. The layout is
//!
//! ```text
//! [ original_data || random_filler || original_length (u32, little-endian) ]
//! ```
//!
//! The trailing four bytes encode the original length; the filler between the
//! data and that suffix is random (`aws-lc-rs` `SystemRandom`) so two messages
//! of the same padded size are not bytewise distinguishable beyond their data.

use aws_lc_rs::rand::{SecureRandom, SystemRandom};

use crate::error::{CoreError, CoreResult};

/// Bytes reserved at the end of every padded blob for the length suffix.
const LEN_SUFFIX: usize = 4;

/// A fixed padding block size. Padded output is always a multiple of the chosen
/// block size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaddingScheme {
    /// 4 KiB blocks.
    Block4K,
    /// 64 KiB blocks.
    Block64K,
    /// 512 KiB blocks.
    Block512K,
    /// 5 MiB blocks.
    Block5M,
}

impl PaddingScheme {
    /// Block size in bytes.
    pub fn block_size(&self) -> usize {
        match self {
            PaddingScheme::Block4K => 4096,
            PaddingScheme::Block64K => 65536,
            PaddingScheme::Block512K => 524288,
            PaddingScheme::Block5M => 5242880,
        }
    }

    /// The smallest scheme whose single block holds `plaintext_len` plus the
    /// length suffix; the largest scheme if it exceeds every single block (the
    /// output then spans several blocks of that size).
    pub fn select_for(plaintext_len: usize) -> Self {
        let need = plaintext_len + LEN_SUFFIX;
        if need <= PaddingScheme::Block4K.block_size() {
            PaddingScheme::Block4K
        } else if need <= PaddingScheme::Block64K.block_size() {
            PaddingScheme::Block64K
        } else if need <= PaddingScheme::Block512K.block_size() {
            PaddingScheme::Block512K
        } else {
            PaddingScheme::Block5M
        }
    }
}

/// Largest plaintext the little-endian `u32` length suffix can record. Normally
/// [`u32::MAX`]; tests lower it via [`set_len_suffix_cap`] to exercise the
/// boundary without allocating 4 GiB.
#[cfg(not(test))]
const fn len_suffix_cap() -> usize {
    u32::MAX as usize
}

#[cfg(test)]
fn len_suffix_cap() -> usize {
    LEN_SUFFIX_CAP_OVERRIDE.with(|c| c.get())
}

#[cfg(test)]
thread_local! {
    /// Per-thread override of the `pad` length-suffix cap, defaulting to the
    /// real `u32::MAX` so untouched tests keep the production bound.
    static LEN_SUFFIX_CAP_OVERRIDE: std::cell::Cell<usize> = const { std::cell::Cell::new(u32::MAX as usize) };
}

/// Lower (or restore) the `pad` length-suffix cap for the current thread so a
/// test can hit the `usize -> u32` boundary without a 4 GiB allocation.
#[cfg(test)]
fn set_len_suffix_cap(cap: usize) {
    LEN_SUFFIX_CAP_OVERRIDE.with(|c| c.set(cap));
}

/// Pad `plaintext` to the next block boundary, returning the chosen scheme and
/// the padded bytes (always a multiple of the scheme's block size).
///
/// # Errors
/// [`CoreError::Padding`] if `plaintext` is longer than the little-endian
/// `u32` length suffix can record ([`u32::MAX`] bytes). Without this guard the
/// `usize -> u32` cast would wrap silently and write a suffix that under-counts
/// the data, so [`unpad`] would later recover a truncated plaintext.
pub fn pad(plaintext: &[u8]) -> CoreResult<(PaddingScheme, Vec<u8>)> {
    if plaintext.len() > len_suffix_cap() {
        return Err(CoreError::Padding(
            "plaintext length exceeds u32 suffix range",
        ));
    }
    let scheme = PaddingScheme::select_for(plaintext.len());
    let bs = scheme.block_size();
    let total = (plaintext.len() + LEN_SUFFIX).div_ceil(bs) * bs;

    let mut out = vec![0u8; total];
    out[..plaintext.len()].copy_from_slice(plaintext);
    // Random filler between the data and the length suffix.
    let filler_end = total - LEN_SUFFIX;
    SystemRandom::new()
        .fill(&mut out[plaintext.len()..filler_end])
        .expect("system RNG must not fail");
    out[filler_end..].copy_from_slice(&(plaintext.len() as u32).to_le_bytes());
    Ok((scheme, out))
}

/// Recover the original plaintext from a padded blob.
///
/// # Errors
/// [`CoreError::Padding`] if `padded` is empty, not a multiple of the scheme's
/// block size, or carries a length suffix that exceeds the available data.
pub fn unpad(padded: &[u8], scheme: PaddingScheme) -> CoreResult<Vec<u8>> {
    let bs = scheme.block_size();
    if padded.is_empty() || !padded.len().is_multiple_of(bs) {
        return Err(CoreError::Padding("padded length is not a whole block"));
    }
    let n = padded.len();
    let len = u32::from_le_bytes(padded[n - LEN_SUFFIX..].try_into().unwrap()) as usize;
    if len > n - LEN_SUFFIX {
        return Err(CoreError::Padding("length suffix exceeds padded data"));
    }
    Ok(padded[..len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_and_picks_smallest_block() {
        for len in [0usize, 1, 100, 4091, 4092, 4093, 65532, 600_000] {
            let pt: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let (scheme, padded) = pad(&pt).unwrap();
            assert!(padded.len().is_multiple_of(scheme.block_size()));
            assert_eq!(unpad(&padded, scheme).unwrap(), pt);
        }
        assert_eq!(PaddingScheme::select_for(0), PaddingScheme::Block4K);
        assert_eq!(PaddingScheme::select_for(4092), PaddingScheme::Block4K);
        assert_eq!(PaddingScheme::select_for(4093), PaddingScheme::Block64K);
    }

    #[test]
    fn rejects_corrupt_suffix_and_misaligned_input() {
        let (scheme, mut padded) = pad(b"paramant").unwrap();
        let n = padded.len();
        padded[n - 4..].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(unpad(&padded, scheme).is_err());
        assert!(unpad(&padded[..n - 1], scheme).is_err());
        assert!(unpad(&[], PaddingScheme::Block4K).is_err());
    }

    /// The `usize -> u32` length-suffix cast in `pad` rejects an over-long
    /// plaintext instead of wrapping. Exercised through an injected cap so the
    /// 4 GiB boundary needs no real allocation; a length one past the cap must
    /// fail, the cap itself must still succeed, and the production bound stays
    /// `u32::MAX` for every other test (override is thread-local, restored here).
    #[test]
    fn pad_rejects_plaintext_beyond_u32_suffix() {
        assert_eq!(
            len_suffix_cap(),
            u32::MAX as usize,
            "default cap is u32::MAX"
        );
        set_len_suffix_cap(16);
        // One byte past the cap wraps the suffix without the guard: must error.
        let err = pad(&[0u8; 17]).unwrap_err();
        assert!(matches!(err, CoreError::Padding(_)), "got {err:?}");
        // Exactly at the cap still pads and round-trips cleanly.
        let (scheme, padded) = pad(&[7u8; 16]).unwrap();
        assert_eq!(unpad(&padded, scheme).unwrap(), vec![7u8; 16]);
        set_len_suffix_cap(u32::MAX as usize);
    }
}
