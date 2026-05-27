//! Paramant wire format v1: the `PQHB` envelope codec.
//!
//! This is the byte-equivalent Rust implementation of `paramant-relay`'s wire
//! format v1 (`relay/crypto/wire-format.js`, approved 2026-04-24). The relay is
//! the source of truth (ADR-0003); any divergence here is a bug. See
//! `docs/wire-format-v1.md` for the full byte-level specification and
//! `docs/adrs/0014-wire-format-byte-equivalence-with-relay.md` for the policy.
//!
//! Layout (all integers big-endian, no inter-field padding):
//!
//! ```text
//! HEADER (10 bytes)  MAGIC "PQHB" | VERSION 0x01 | KEM_ID u16 | SIG_ID u16 | FLAGS u8
//! BODY               CT_KEM_LEN u32 | CT_KEM | SENDER_PUB_LEN u32 | SENDER_PUB
//!                    [if SIG_ID != 0]  SIG_LEN u32 | SIGNATURE
//!                    NONCE (12 bytes, no prefix) | CT_LEN u32 | CIPHERTEXT
//! ```
//!
//! The AEAD AAD for chunk `i` is `HEADER (10) || chunk_index_be32 (4)`, binding
//! the algorithm choice to ciphertext integrity.

use crate::error::{CoreError, CoreResult};

/// Magic bytes that prefix every v1 envelope: ASCII `PQHB`.
pub const WIRE_MAGIC: [u8; 4] = *b"PQHB";
/// Wire format version byte for v1.
pub const WIRE_VERSION_V1: u8 = 0x01;
/// Fixed header size in bytes (magic + version + kem_id + sig_id + flags).
pub const HEADER_FIXED_SIZE: usize = 10;
/// AES-256-GCM nonce size in bytes (carried with no length prefix).
pub const NONCE_SIZE: usize = 12;

/// KEM algorithm identifier (uint16). Values mirror the relay registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum KemId {
    /// ML-KEM-512 (FIPS 203, NIST level 1).
    MlKem512 = 0x0001,
    /// ML-KEM-768 (FIPS 203, NIST level 3, relay default).
    MlKem768 = 0x0002,
    /// ML-KEM-1024 (FIPS 203, NIST level 5).
    MlKem1024 = 0x0003,
}

impl KemId {
    /// The uint16 wire encoding of this identifier.
    pub fn as_u16(self) -> u16 {
        self as u16
    }
}

impl TryFrom<u16> for KemId {
    type Error = CoreError;
    fn try_from(id: u16) -> CoreResult<Self> {
        match id {
            0x0001 => Ok(KemId::MlKem512),
            0x0002 => Ok(KemId::MlKem768),
            0x0003 => Ok(KemId::MlKem1024),
            _ => Err(CoreError::UnknownAlgorithm { kind: "KEM", id }),
        }
    }
}

/// Signature algorithm identifier (uint16). `0x0000` means an anonymous
/// (unsigned) envelope and the signature section is omitted entirely. Values
/// mirror the relay registry (`relay/crypto/bootstrap.js`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SigId {
    /// No signature: anonymous envelope, signature section absent.
    None = 0x0000,
    /// ML-DSA-44 (FIPS 204, NIST level 2).
    MlDsa44 = 0x0001,
    /// ML-DSA-65 (FIPS 204, NIST level 3, relay default).
    MlDsa65 = 0x0002,
    /// ML-DSA-87 (FIPS 204, NIST level 5).
    MlDsa87 = 0x0003,
    /// Falcon-512 (FIPS 206, NIST level 1).
    Falcon512 = 0x0100,
    /// Falcon-1024 (FIPS 206, NIST level 5).
    Falcon1024 = 0x0101,
    /// SLH-DSA-SHA2-128s (FIPS 205).
    SlhDsaSha2_128s = 0x0200,
    /// SLH-DSA-SHA2-128f (FIPS 205).
    SlhDsaSha2_128f = 0x0201,
    /// SLH-DSA-SHA2-192s (FIPS 205).
    SlhDsaSha2_192s = 0x0202,
    /// SLH-DSA-SHA2-192f (FIPS 205).
    SlhDsaSha2_192f = 0x0203,
    /// SLH-DSA-SHA2-256s (FIPS 205).
    SlhDsaSha2_256s = 0x0204,
    /// SLH-DSA-SHA2-256f (FIPS 205).
    SlhDsaSha2_256f = 0x0205,
    /// SLH-DSA-SHAKE-128s (FIPS 205).
    SlhDsaShake128s = 0x0206,
    /// SLH-DSA-SHAKE-128f (FIPS 205).
    SlhDsaShake128f = 0x0207,
    /// SLH-DSA-SHAKE-192s (FIPS 205).
    SlhDsaShake192s = 0x0208,
    /// SLH-DSA-SHAKE-192f (FIPS 205).
    SlhDsaShake192f = 0x0209,
    /// SLH-DSA-SHAKE-256s (FIPS 205).
    SlhDsaShake256s = 0x020A,
    /// SLH-DSA-SHAKE-256f (FIPS 205).
    SlhDsaShake256f = 0x020B,
}

impl SigId {
    /// The uint16 wire encoding of this identifier.
    pub fn as_u16(self) -> u16 {
        self as u16
    }

    /// Whether this is the anonymous (no-signature) identifier.
    pub fn is_none(self) -> bool {
        self == SigId::None
    }
}

impl TryFrom<u16> for SigId {
    type Error = CoreError;
    fn try_from(id: u16) -> CoreResult<Self> {
        match id {
            0x0000 => Ok(SigId::None),
            0x0001 => Ok(SigId::MlDsa44),
            0x0002 => Ok(SigId::MlDsa65),
            0x0003 => Ok(SigId::MlDsa87),
            0x0100 => Ok(SigId::Falcon512),
            0x0101 => Ok(SigId::Falcon1024),
            0x0200 => Ok(SigId::SlhDsaSha2_128s),
            0x0201 => Ok(SigId::SlhDsaSha2_128f),
            0x0202 => Ok(SigId::SlhDsaSha2_192s),
            0x0203 => Ok(SigId::SlhDsaSha2_192f),
            0x0204 => Ok(SigId::SlhDsaSha2_256s),
            0x0205 => Ok(SigId::SlhDsaSha2_256f),
            0x0206 => Ok(SigId::SlhDsaShake128s),
            0x0207 => Ok(SigId::SlhDsaShake128f),
            0x0208 => Ok(SigId::SlhDsaShake192s),
            0x0209 => Ok(SigId::SlhDsaShake192f),
            0x020A => Ok(SigId::SlhDsaShake256s),
            0x020B => Ok(SigId::SlhDsaShake256f),
            _ => Err(CoreError::UnknownAlgorithm { kind: "SIG", id }),
        }
    }
}

/// The fixed 10-byte envelope header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// KEM algorithm used for key encapsulation.
    pub kem_id: KemId,
    /// Signature algorithm, or [`SigId::None`] for an anonymous envelope.
    pub sig_id: SigId,
    /// Reserved flags byte; MUST be `0x00` in v1.
    pub flags: u8,
}

/// A decoded (or to-be-encoded) v1 envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// Fixed header.
    pub header: Header,
    /// KEM ciphertext.
    pub ct_kem: Vec<u8>,
    /// Sender public key.
    pub sender_pub: Vec<u8>,
    /// Signature; `Some` iff `header.sig_id != SigId::None`.
    pub signature: Option<Vec<u8>>,
    /// AES-256-GCM nonce.
    pub nonce: [u8; NONCE_SIZE],
    /// AES-256-GCM ciphertext (already padded plaintext, see `padding`).
    pub ciphertext: Vec<u8>,
}

impl Envelope {
    /// Serialise to the v1 wire format.
    ///
    /// Returns [`CoreError::Wire`] if `flags != 0`, or if the signature presence
    /// disagrees with `sig_id` (present for `None`, or absent for a real algorithm).
    pub fn encode(&self) -> CoreResult<Vec<u8>> {
        if self.header.flags != 0x00 {
            return Err(CoreError::Wire("flags must be 0x00 in v1"));
        }
        let signed = !self.header.sig_id.is_none();
        match (&self.signature, signed) {
            (Some(_), false) => {
                return Err(CoreError::Wire("signature present with SIG_ID 0x0000"))
            }
            (None, true) => return Err(CoreError::Wire("signature absent with non-zero SIG_ID")),
            _ => {}
        }

        let sig_len = self.signature.as_ref().map_or(0, |s| 4 + s.len());
        let mut out = Vec::with_capacity(
            HEADER_FIXED_SIZE
                + 8
                + self.ct_kem.len()
                + self.sender_pub.len()
                + sig_len
                + NONCE_SIZE
                + 4
                + self.ciphertext.len(),
        );

        out.extend_from_slice(&WIRE_MAGIC);
        out.push(WIRE_VERSION_V1);
        out.extend_from_slice(&self.header.kem_id.as_u16().to_be_bytes());
        out.extend_from_slice(&self.header.sig_id.as_u16().to_be_bytes());
        out.push(self.header.flags);

        put_field(&mut out, &self.ct_kem);
        put_field(&mut out, &self.sender_pub);
        if let Some(sig) = &self.signature {
            put_field(&mut out, sig);
        }
        out.extend_from_slice(&self.nonce);
        put_field(&mut out, &self.ciphertext);
        Ok(out)
    }

    /// Parse a v1 wire-format envelope, consuming the whole buffer.
    ///
    /// Rejects (via [`CoreError::Wire`] / [`CoreError::UnknownAlgorithm`]): wrong
    /// magic, unsupported version, non-zero flags, unknown KEM/SIG IDs, a length
    /// prefix overrunning the buffer, and any trailing bytes after the ciphertext.
    pub fn decode(bytes: &[u8]) -> CoreResult<Self> {
        let (envelope, consumed) = Self::decode_prefix(bytes)?;
        if consumed != bytes.len() {
            return Err(CoreError::Wire("trailing bytes after ciphertext"));
        }
        Ok(envelope)
    }

    /// Decode one envelope from the start of `bytes`, returning it and the number
    /// of bytes it consumed. Unlike [`Envelope::decode`] this tolerates trailing
    /// bytes after the ciphertext — e.g. the random block padding that the
    /// envelope layer appends to the wire core (see `envelope`). Mirrors the
    /// relay decoder's `consumedBytes`.
    pub fn decode_prefix(bytes: &[u8]) -> CoreResult<(Self, usize)> {
        if bytes.len() < HEADER_FIXED_SIZE {
            return Err(CoreError::Wire("buffer shorter than header"));
        }
        if bytes[0..4] != WIRE_MAGIC {
            return Err(CoreError::Wire("bad magic (expected PQHB)"));
        }
        if bytes[4] != WIRE_VERSION_V1 {
            return Err(CoreError::Wire("unsupported version"));
        }
        let kem_id = KemId::try_from(read_u16_be(bytes, 5)?)?;
        let sig_id = SigId::try_from(read_u16_be(bytes, 7)?)?;
        let flags = bytes[9];
        if flags != 0x00 {
            return Err(CoreError::Wire("flags must be 0x00 in v1"));
        }

        let mut off = HEADER_FIXED_SIZE;
        let ct_kem = read_field(bytes, &mut off)?;
        let sender_pub = read_field(bytes, &mut off)?;
        let signature = if sig_id.is_none() {
            None
        } else {
            Some(read_field(bytes, &mut off)?)
        };
        let nonce_slice = read_bytes(bytes, off, NONCE_SIZE)?;
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(nonce_slice);
        off += NONCE_SIZE;
        let ciphertext = read_field(bytes, &mut off)?;

        Ok((
            Envelope {
                header: Header {
                    kem_id,
                    sig_id,
                    flags,
                },
                ct_kem,
                sender_pub,
                signature,
                nonce,
                ciphertext,
            },
            off,
        ))
    }

    /// The 14-byte AEAD additional authenticated data for chunk `chunk_index`:
    /// `HEADER (10) || chunk_index_be32 (4)`.
    pub fn aad_for_chunk(&self, chunk_index: u32) -> [u8; HEADER_FIXED_SIZE + 4] {
        let mut aad = [0u8; HEADER_FIXED_SIZE + 4];
        aad[0..4].copy_from_slice(&WIRE_MAGIC);
        aad[4] = WIRE_VERSION_V1;
        aad[5..7].copy_from_slice(&self.header.kem_id.as_u16().to_be_bytes());
        aad[7..9].copy_from_slice(&self.header.sig_id.as_u16().to_be_bytes());
        aad[9] = self.header.flags;
        aad[10..14].copy_from_slice(&chunk_index.to_be_bytes());
        aad
    }
}

/// Append a `u32` big-endian length prefix followed by the field bytes.
fn put_field(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
    out.extend_from_slice(field);
}

fn read_u16_be(buf: &[u8], at: usize) -> CoreResult<u16> {
    let b = read_bytes(buf, at, 2)?;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

fn read_u32_be(buf: &[u8], at: usize) -> CoreResult<u32> {
    let b = read_bytes(buf, at, 4)?;
    Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_bytes(buf: &[u8], at: usize, len: usize) -> CoreResult<&[u8]> {
    buf.get(
        at..at
            .checked_add(len)
            .ok_or(CoreError::Wire("length overflow"))?,
    )
    .ok_or(CoreError::Wire("field exceeds buffer"))
}

/// Read a `u32`-length-prefixed field at `*off`, advancing `*off` past it.
fn read_field(buf: &[u8], off: &mut usize) -> CoreResult<Vec<u8>> {
    let len = read_u32_be(buf, *off)? as usize;
    *off += 4;
    let field = read_bytes(buf, *off, len)?.to_vec();
    *off += len;
    Ok(field)
}
