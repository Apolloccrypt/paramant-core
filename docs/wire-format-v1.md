# Paramant Wire Format v1 (Rust port)

**Status**: paramant-core implementation tracking paramant-relay
`docs/wire-format-v1.md` (approved 2026-04-24).

This document is the Rust-implementation-oriented mirror of the canonical
paramant-relay wire-format specification. It is self-contained: an engineer can
implement a byte-compatible encoder and decoder in any language from this
document alone. Where it describes paramant-core internals it points at
[`crates/paramant-core/src/wire.rs`](../crates/paramant-core/src/wire.rs).

The format is named **PQHB** after its 4-byte magic ("Post-Quantum Hybrid
Blob").

---

## 1. Source of truth

`paramant-relay/docs/wire-format-v1.md` (approved 2026-04-24) is **canonical**.
The relay's encoder/decoder pair —
`paramant-relay/relay/crypto/wire-format.js` (Node, authoritative) and
`paramant-relay/sdk-js/src/wire-format.js` (browser SDK) — define the bytes on
the wire.

- This document is the Rust-implementation-oriented mirror.
- `paramant-core`'s `wire.rs` MUST produce byte-identical output to the relay
  for identical inputs. **Any divergence is a paramant-core bug**, never a
  design choice.
- ADR-0003 (source of truth) and
  [ADR-0014](adrs/0014-wire-format-byte-equivalence-with-relay.md)
  (byte-equivalence policy) govern the relationship. Changes flow
  relay → core, never the other direction.

Key words **MUST**, **MUST NOT**, **SHOULD**, **MAY** are to be interpreted as
in RFC 2119.

---

## 2. Byte layout

All multi-byte integers are **big-endian** (network byte order). There is no
padding or alignment between fields. The blob is the concatenation of a fixed
header and a variable body:

```
┌────────────────────────────────────────────────────────────────────┐
│ HEADER (10 bytes, fixed)                                             │
│   MAGIC        4B   'PQHB' = 0x50 0x51 0x48 0x42                      │
│   VERSION      1B   0x01 for v1                                       │
│   KEM_ID       2B   uint16 big-endian                                │
│   SIG_ID       2B   uint16 big-endian (0x0000 = unsigned/anonymous)  │
│   FLAGS        1B   reserved, MUST be 0x00 in v1                      │
├────────────────────────────────────────────────────────────────────┤
│ KEY ENCAPSULATION                                                    │
│   CT_KEM_LEN     4B   uint32 big-endian                              │
│   CT_KEM         N    KEM ciphertext                                 │
│   SENDER_PUB_LEN 4B   uint32 big-endian                             │
│   SENDER_PUB     N    sender public key                              │
├────────────────────────────────────────────────────────────────────┤
│ SIGNATURE  (present only if SIG_ID != 0x0000)                        │
│   SIG_LEN      4B   uint32 big-endian                                │
│   SIGNATURE    N                                                     │
├────────────────────────────────────────────────────────────────────┤
│ PAYLOAD                                                              │
│   NONCE        12B  AES-256-GCM nonce (NO length prefix, fixed)      │
│   CT_LEN       4B   uint32 big-endian                                │
│   CIPHERTEXT   N    AES-256-GCM ciphertext (encrypted padded data)   │
└────────────────────────────────────────────────────────────────────┘
```

Fixed overhead: 10-byte header + length prefixes. An anonymous envelope adds
`4 + 4 + 4 = 12` prefix bytes plus the 12-byte nonce; a signed envelope adds a
further 4-byte `SIG_LEN`.

```
unsigned total = 10 + (4+|ct_kem|) + (4+|sender_pub|) + 12 + (4+|ciphertext|)
signed total   = unsigned total + (4 + |signature|)
```

### AEAD additional authenticated data (AAD)

The AES-256-GCM AAD for AEAD chunk `chunk_index` is the 14 bytes

```
AAD = HEADER[0..10] || chunk_index_be32
```

i.e. `MAGIC || VERSION || KEM_ID || SIG_ID || FLAGS || uint32_be(chunk_index)`.
For a single-chunk envelope (the common case) `chunk_index = 0`. This binds the
algorithm selection to ciphertext integrity: flipping a bit in `KEM_ID` or
`SIG_ID` makes the GCM tag verification fail, so an attacker cannot silently
downgrade the algorithm. paramant-core exposes this as
`Envelope::aad_for_chunk(chunk_index)`.

---

## 3. Algorithm registry

`KEM_ID` and `SIG_ID` are uint16 values, assigned per family in 256-slot ranges.
IDs are stable: a later spec revision MAY add IDs but MUST NOT reassign or remove
one. A relay MAY refuse to load specific IDs for policy reasons (returning HTTP
415); refusal is a deployment decision, not a format change.

### KEM registry

| ID       | Algorithm    | Public key | Ciphertext | Status                |
|----------|--------------|-----------:|-----------:|-----------------------|
| `0x0000` | reserved     | —          | —          | invalid for encryption |
| `0x0001` | ML-KEM-512   | 800 B      | 768 B      | FIPS 203              |
| `0x0002` | ML-KEM-768   | 1184 B     | 1088 B     | FIPS 203, **default** |
| `0x0003` | ML-KEM-1024  | 1568 B     | 1568 B     | FIPS 203              |

### Signature registry

| ID       | Algorithm           | Public key | Signature | Status                |
|----------|---------------------|-----------:|----------:|-----------------------|
| `0x0000` | none (anonymous)    | —          | —         | valid, skips section  |
| `0x0001` | ML-DSA-44           | 1312 B     | 2420 B    | FIPS 204              |
| `0x0002` | ML-DSA-65           | 1952 B     | 3309 B    | FIPS 204, **default** |
| `0x0003` | ML-DSA-87           | 2592 B     | 4627 B    | FIPS 204              |
| `0x0100` | Falcon-512          | 897 B      | ~666 B    | FIPS 206              |
| `0x0101` | Falcon-1024         | 1793 B     | ~1280 B   | FIPS 206              |
| `0x0200`–`0x020B` | SLH-DSA / SPHINCS+ family | 32–64 B | large | FIPS 205     |

The canonical relay spec documents `0x0200` (SLH-DSA-SHA2-128s) and `0x0201`
(SLH-DSA-SHA2-128f); the relay's runtime registry (`relay/crypto/bootstrap.js`)
additionally registers the SHA2 and SHAKE `{128,192,256}×{s,f}` variants through
`0x020B`. paramant-core's [`SigId`](../crates/paramant-core/src/wire.rs) enum
covers the full `0x0200..=0x020B` range so it decodes anything the relay can
emit. IDs `>= 0x8000` are reserved for private/experimental use by self-hosters.

**Phase B** (initial deployment) loads only ML-KEM-768 (`0x0002`) and ML-DSA-65
(`0x0002`). Other IDs are reserved and documented but not yet wired to an impl.

---

## 4. Encoding rules

1. Every `*_LEN` prefix is a **uint32 big-endian** byte count of the field that
   immediately follows it.
2. All header integer fields (`KEM_ID`, `SIG_ID`) are **uint16 big-endian**.
3. There is **no padding or alignment** between fields.
4. `NONCE` is exactly 12 bytes and has **no length prefix**.
5. When `SIG_ID == 0x0000` the signature section is **omitted entirely** — not a
   zero-length prefix. When `SIG_ID != 0x0000` the section is present with its
   `SIG_LEN` prefix (which MAY itself be zero for a zero-length signature).
6. `FLAGS` MUST be `0x00`. Decoders MUST reject any other value.

A decoder MUST reject a blob that:

- is shorter than the 10-byte header;
- does not begin with the `PQHB` magic;
- carries a `VERSION` other than `0x01`;
- carries a `FLAGS` byte other than `0x00`;
- names an unregistered `KEM_ID` or `SIG_ID`;
- has any `*_LEN` prefix that overruns the remaining buffer;
- ends before the nonce or ciphertext is complete;
- has trailing bytes after the ciphertext (a v1 envelope consumes its buffer
  exactly).

---

## 5. Padding integration

Length-hiding padding is applied to the **plaintext**, before AEAD encryption —
not to the outer blob. The encoder:

1. Pads the plaintext to a fixed block tier via
   [`padding`](../crates/paramant-core/src/padding.rs) (M4 phase 1): one of
   4 KiB, 64 KiB, 512 KiB, 5 MiB, with a random filler and a little-endian
   `u32` length suffix.
2. Encrypts the padded plaintext with AES-256-GCM using
   `AAD = HEADER || chunk_index_be32`.
3. Places the resulting ciphertext (including the 16-byte GCM tag) in the
   `CIPHERTEXT` field.

Because padding is inside the ciphertext, the outer blob length is **not** block
aligned (the published test vectors are 5090 B and 1778 B). A decoder AEAD-
decrypts `CIPHERTEXT`, then unpads to recover the original plaintext. Multi-chunk
envelopes increment `chunk_index` per chunk; v1 deployments use a single chunk.

---

## 6. Versioning policy

- The `VERSION` byte is `0x01` for v1. `0x00` is invalid.
- Decoders MUST reject an unknown `VERSION` (no silent downgrade); a relay
  returns HTTP 415 listing the versions it supports.
- v1 evolves only through the reserved `FLAGS` byte (e.g. compression,
  multi-recipient, hybrid KEM as an extra length-prefixed field gated by a flag
  bit). New required structure that v1 cannot express requires a `VERSION` bump.
- See [ADR-0014](adrs/0014-wire-format-byte-equivalence-with-relay.md).

---

## 7. Test vectors

Two **anchor vectors** are transcribed from the relay spec; their SHA-256 is the
cross-implementation ground truth. The generator
([`scripts/extract-kat.mjs`](../scripts/extract-kat.mjs)) re-derives both and
refuses to emit if either SHA-256 diverges, then adds 28 generated vectors
covering every KEM and signature family, anonymous and signed forms, and
boundary cases (empty ciphertext, empty fields, large signatures). All 30 live
in [`tests/kat/wire-format-v1.json`](../tests/kat/wire-format-v1.json) and are
checked by `crates/paramant-core/tests/kat_wire.rs`.

Common inputs for both anchors: `ctKem = 00112233445566778899aabbccddeeff × 68`
(1088 B), `senderPub = cafe × 296` (592 B), `nonce = 000102030405060708090a0b`,
`ciphertext = deadbeef × 16` (64 B). (`× N` = the hex pattern repeated N times.)

| Anchor    | KEM_ID | SIG_ID | signature      | total | SHA-256 (full blob) |
|-----------|--------|--------|----------------|------:|---------------------|
| signed    | `0x0002` | `0x0002` | `babe × 1654` (3308 B) | 5090 B | `002b4f6aad4fa992804a3e94c46d514b4f842e9f5c283f7a31d7c76722d0476a` |
| anonymous | `0x0002` | `0x0000` | omitted        | 1778 B | `46bce75b12e90ed312420fafcbead4108d55aa25273aee3ce4f2b4f61b3d19ef` |

Their header bytes are `50514842010002000200` (signed) and
`50514842010002000000` (anonymous).

---

## 8. Security considerations

- **Magic + version** prevent confusion with other formats and allow controlled
  evolution; a decoder rejects anything not starting with `PQHB` `0x01`.
- **Algorithm-binding AAD**: the 10-byte header is in the GCM AAD, so tampering
  with `KEM_ID`/`SIG_ID`/`FLAGS` is an integrity failure, not a downgrade. This
  defeats algorithm-confusion attacks.
- **Bounds checking**: every length prefix MUST be validated against the
  remaining buffer before slicing, to prevent out-of-bounds reads. paramant-core
  uses checked arithmetic and `slice::get`.
- **Signature-absent signalling**: a missing signature section is meaningful
  only when `SIG_ID == 0x0000`. A recipient MUST NOT treat a missing section as
  a valid anonymous blob unless `SIG_ID` is explicitly `0x0000`.
- **Strict consumption**: rejecting trailing bytes prevents a class of
  ambiguous-framing attacks where attacker-controlled bytes ride along after a
  valid envelope.

---

## Appendix A: Reference implementations

| Implementation | File | Role |
|----------------|------|------|
| paramant-relay (Node) | `relay/crypto/wire-format.js` | **canonical** |
| paramant-relay SDK (browser) | `sdk-js/src/wire-format.js` | must match relay |
| paramant-core (Rust) | `crates/paramant-core/src/wire.rs` | this implementation |

All three MUST produce byte-identical output for identical inputs. The relay's
decoder is authoritative: any blob it rejects is incorrect regardless of the
producer's claim.

---

## References

- NIST FIPS 203 — Module-Lattice-Based KEM (ML-KEM)
- NIST FIPS 204 — Module-Lattice-Based Digital Signature (ML-DSA)
- NIST FIPS 205 — Stateless Hash-Based Digital Signature (SLH-DSA / SPHINCS+)
- NIST FIPS 206 — FN-DSA (Falcon)
- RFC 5116 — An Interface and Algorithms for Authenticated Encryption
- RFC 2119 — Key words for use in RFCs
