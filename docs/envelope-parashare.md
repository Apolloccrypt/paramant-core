# ParaShare envelope (signed, device-paired)

**Status**: paramant-core implementation tracking paramant-relay `sdk-js`
(`index.js` `send` / `_encrypt` with `SIG_ID != 0x0000`, default ML-DSA-65).

ParaShare is [Send mode](envelope-send.md) plus an ML-DSA-65 signature. It reuses
Send's key encapsulation, key derivation, AEAD and padding unchanged; only the
signature and the `SIG_ID`/`SENDER_PUB` fields differ. Read `envelope-send.md`
first; this document states only the deltas. Source of truth: paramant-relay
(ADR-0003); design rationale in [ADR-0016](adrs/0016-parashare-signature.md).

## 1. Parameters (deltas from Send)

| Field | Value |
|-------|-------|
| `KEM_ID` | `0x0002` (ML-KEM-768, a **single** KEM -- not the hybrid) |
| `SIG_ID` | `0x0002` (ML-DSA-65) |
| `SENDER_PUB` | the sender's **ML-DSA-65 public key** (1952 bytes), not the KEM key |
| signature | ML-DSA-65, 3309 bytes, present in the `SIGNATURE` section |

Key derivation and AEAD are identical to Send:
`HKDF-SHA256(ikm = shared_secret, salt = ct_kem[0..32],
info = "paramant-v1-aes-key")`, AES-256-GCM, `AAD = HEADER(10) ||
chunk_index_be32`. The header in the AAD carries `SIG_ID = 0x0002`, so a
ParaShare AAD differs from a Send AAD.

## 2. Signed message

The signature covers, in order:

```text
msg = ct_kem || sender_pub || nonce || ciphertext || aad
```

`ciphertext` is the AES-256-GCM output (`ct || tag`); signing happens after
encryption. `sender_pub` is the ML-DSA-65 public key carried in `SENDER_PUB`.

## 3. Flow

**Encrypt** (`encrypt(recipient, signer_sk, signer_pub, plaintext, pad_block)`):
encapsulate (ML-KEM-768) -> derive key -> AES-256-GCM encrypt -> build `msg` ->
ML-DSA-65 sign -> assemble PQHB envelope -> pad core to `pad_block`.

**Decrypt** (`decrypt(recipient_sk, blob)` -> `(plaintext, sender_pub)`):
`decode_prefix` -> rebuild `msg` -> verify ML-DSA-65 signature against the carried
`SENDER_PUB` -> decapsulate -> AES-256-GCM decrypt. Returns the verified
`sender_pub` for caller-side pinning (TOFU); the core enforces only cryptographic
validity, matching the relay.

## 4. Test vectors

`tests/kat/envelope-parashare.json` (15 vectors), checked by
`crates/paramant-core/tests/kat_envelope_parashare.rs`:

- `ct_kem`/`shared_secret`/`signature` come from @noble (deterministic ML-KEM-768
  and ML-DSA-65) and are KAT inputs -- `oqs` derandomises neither encapsulation
  nor its hedged ML-DSA signing (ADR-0005). Each vector pins `aes_key`, the core
  length, header and core SHA-256 via `seal_core` (which takes the signature),
  links the KEM with `decaps == shared_secret`, and confirms the Rust ML-DSA-65
  verifier accepts the @noble signature (the `ml-dsa-65.json` cross-impl link).
- `proptest_envelope_parashare.rs` covers the randomised end-to-end
  `encrypt`/`decrypt` flow, wrong-recipient rejection, and tamper rejection.

De-risked by `scripts/derisk-parashare.mjs` before any Rust (WebCrypto ==
pure-Node AES/HKDF, the ML-DSA-65 signature verifies, relay `wireEncode`/`decode`
round-trips).

## 5. Security considerations (deltas from Send)

- **Sender authentication.** Unlike Send, the recipient learns a cryptographically
  verified sender ML-DSA-65 public key. It is only an identity if the caller pins
  it (TOFU / fingerprint); the core returns it but stores no trust state.
- **Signature binding.** The signature covers `ct_kem`, `sender_pub`, `nonce`,
  `ciphertext` and the header AAD, so none of these can be altered without
  detection. (The AEAD already protects the ciphertext and header; the signature
  additionally binds `sender_pub`, which the AAD does not cover.)
