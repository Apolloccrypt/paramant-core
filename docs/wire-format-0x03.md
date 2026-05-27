# Browser wire format 0x03 (crypto-wasm hybrid)

**Status**: documentation of the as-shipped browser format. Canonical source is
`paramant-relay/crypto-wasm/src/lib.rs` (RustCrypto, compiled to WASM as
`frontend/pkg/paramant_crypto_bg.wasm`, consumed by `frontend/crypto-bridge.js`).
This doc mirrors it for audit/governance; it is NOT a paramant-core
implementation (paramant-core cannot target wasm32 -- see
[wire-format-boundaries.md](wire-format-boundaries.md)).

This is a different format from [PQHB / wire format v1](wire-format-v1.md). It is
used by the browser flows (parashare, drop, ontvang) and is never decoded by the
relay (which blind-stores it). See the boundaries doc for why both exist.

## 1. Crypto construction

A 0x03 blob is a **hybrid** KEM envelope:

- KEM: **ML-KEM-768** (RustCrypto `ml-kem 0.3.0-rc.2`), encapsulated to the
  recipient's ML-KEM public key.
- DH: **ECDH P-256** (RustCrypto `p256`), an ephemeral sender key against the
  recipient's P-256 public key.
- Key: `aes_key = HKDF-SHA256(ikm = ss_kem || ss_ecdh, salt = ct_kem[0..32],
  info = "paramant-v2", len = 32)`.
- AEAD: **AES-256-GCM**, 12-byte random nonce, 16-byte tag.

This differs from PQHB Send/ParaShare, which use a **single** ML-KEM-768 (no
ECDH mix) and `info = "paramant-v1-aes-key"`. The two formats are therefore not
interchangeable at the crypto layer, not only the framing.

There is **no signature** and **no algorithm-ID registry**: the algorithms are
fixed by the format. The magic byte doubles as the version.

## 2. Byte layout

All integers big-endian. `ct` is `AES-GCM ciphertext || 16-byte tag`.

```
MAGIC          1B    0x03   (0x02 = legacy v0, no AAD; decrypt accepts both)
CT_KEM_LEN     4B    uint32 (ML-KEM-768 ciphertext length, 1088)
CT_KEM         N     ML-KEM-768 ciphertext
SENDER_PUB_LEN 4B    uint32 (65)
SENDER_PUB     65B   ephemeral ECDH P-256 public key (uncompressed SEC1 point)
NONCE          12B   AES-256-GCM nonce (no length prefix)
CT_LEN         4B    uint32 (plaintext length + 16)
CIPHERTEXT     N     AES-256-GCM ct || tag
```

The encoded packet is then padded to a fixed **5 MiB** block with random bytes
(the `ct_len` field bounds the real payload, so trailing padding is ignored on
decode).

### AAD

For 0x03, the AES-256-GCM additional authenticated data is the **entire wire
prelude**: every byte from the magic through `CT_LEN` inclusive (i.e. everything
before `CIPHERTEXT`). Any in-flight mutation of a structural field fails the GCM
tag. (Legacy 0x02 used no AAD and relied on `salt = ct_kem[0..32]` for cascade
failure.)

## 3. Key encodings

- `kem_priv`: 2400-byte NIST FIPS 203 expanded decapsulation key
  (`dkPKE || ek || H(ek) || z`), as produced by `@noble/post-quantum`
  `ml_kem768.keygen()`.
- `ecdh_priv`: 32-byte big-endian P-256 scalar.
- `kem_pub`: 1184-byte ML-KEM-768 encapsulation key.
- `ecdh_pub`: 65-byte uncompressed SEC1 P-256 point.

## 4. API surface (crypto-wasm)

Only two wasm-bindgen exports, both operating on the whole blob (no primitive
accessors):

- `encrypt_blob(plaintext, kem_pub, ecdh_pub) -> blob` (randomised: ephemeral
  ECDH + randomised ML-KEM encapsulation + random nonce + random padding).
- `decrypt_blob(blob, kem_priv, ecdh_priv) -> plaintext` (accepts 0x02 and 0x03).

Because both entry points are randomised and there are no deterministic
primitive exports, a 0x03 blob has no fixed-vector KAT; equivalence is asserted
at the underlying-crate level instead (see boundaries doc, audit section).

## 5. Integrity pin

`frontend/crypto-bridge.js` hard-codes `WASM_SHA256` of the built
`paramant_crypto_bg.wasm` and verifies it on init. Any rebuild of crypto-wasm
changes that hash and must update the pin -- so adding exports to crypto-wasm is
a production-visible change, not a test-only one.
