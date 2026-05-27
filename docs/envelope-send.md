# Send mode envelope (anonymous)

**Status**: paramant-core implementation tracking paramant-relay `sdk-js`
(`index.js` `sendAnonymous` / `_encrypt` with `SIG_ID = 0x0000`).

This document specialises [`wire-format-v1.md`](wire-format-v1.md) (the generic
PQHB codec) for the anonymous Send mode. It is a Rust-implementation mirror of
the relay's behaviour.

---

## 1. Source of truth

- Relay implementation: `paramant-relay/sdk-js/index.js`, methods `_encrypt` /
  `_decrypt`, invoked anonymously by `sendAnonymous` (`SIG_ID = 0x0000`).
- Framing: `paramant-relay/sdk-js/src/wire-format.js` (the PQHB codec; mirrored
  in paramant-core `wire.rs`, phase 2a).
- This document mirrors that implementation for Rust. ADR-0003 (relay = source
  of truth) and [ADR-0015](adrs/0015-send-mode-key-derivation.md) govern it.
- The WebCrypto path the relay actually runs was proven byte-equal to the
  pure-Node HKDF + AES-256-GCM that paramant-core mirrors in Rust, by
  `scripts/derisk-send.mjs`, before any Rust was written.

> **Note — this is *not* a URL-fragment mode.** An earlier design described
> "Send" as a no-KEM, browser-fragment-derived key. No such mode exists in this
> relay (build 2.5.0 / sdk 3.0.0). The anonymous mode is KEM-based: the sender
> encapsulates to the recipient's ML-KEM-768 public key. See ADR-0015.

---

## 2. Use case

- Anonymous one-shot send: `SIG_ID = 0x0000`, no signature, no sender identity
  beyond the opaque `SENDER_PUB` field (the relay puts the sender's own KEM
  public key there as a stable identifier).
- The recipient is identified by their ML-KEM-768 public key; only the holder
  of the matching secret key can decrypt.
- Single-use / burn-on-read semantics are enforced by the relay, not by crypto.

---

## 3. Algorithm parameters

| Field | Value |
|-------|-------|
| `KEM_ID` | `0x0002` (ML-KEM-768) |
| `SIG_ID` | `0x0000` (anonymous, signature section omitted) |
| `FLAGS`  | `0x00` |
| KDF      | HKDF-SHA256, `salt = CT_KEM[0..32]`, `info = "paramant-v1-aes-key"`, 32-byte output |
| KDF IKM  | the ML-KEM-768 shared secret (32 bytes) |
| AEAD     | AES-256-GCM, 12-byte random nonce, 16-byte tag |
| AAD      | `HEADER (10 bytes) ‖ chunk_index_be32` (chunk 0 for single-chunk) |

The relay optionally mixes a pre-shared secret (`ikm = shared_secret ‖
sha256(pss)`); paramant-core's v1 anonymous Send uses `ikm = shared_secret`
(no PSS). PSS support is deferred (it is a relay-MITM hardening layer, not part
of the anonymous primitive).

---

## 4. Byte layout (Send mode)

A specific instance of the PQHB wire format:

```
HEADER (10B):  50 51 48 42 | 01 | 00 02 | 00 00 | 00      ("PQHB", v1, KEM 0x0002, SIG 0x0000, FLAGS 0)
CT_KEM:        u32_be(1088) ‖ ML-KEM-768 ciphertext
SENDER_PUB:    u32_be(len)  ‖ sender KEM public key (opaque identifier)
               (signature section omitted — SIG_ID is 0x0000)
NONCE:         12 random bytes (no length prefix)
CIPHERTEXT:    u32_be(len)  ‖ AES-256-GCM(ciphertext ‖ tag)
```

This **encoded core** is then padded for transport (§7). `AAD = HEADER ‖
chunk_index_be32`.

---

## 5. Key derivation

```text
salt    = CT_KEM[0..32]
ikm     = shared_secret                       (32 bytes, from ML-KEM-768)
aes_key = HKDF-SHA256(ikm, salt, "paramant-v1-aes-key", 32)
```

In paramant-core this is `envelope::send::derive_key(ct_kem, shared_secret)`,
implemented with `kdf::hkdf::extract` + `kdf::hkdf::expand`.

---

## 6. Encryption / decryption flow

**Encrypt** (`encrypt` → wire blob; non-deterministic):

1. `kem::encaps(recipient_pub)` → `(ct_kem, shared_secret)`.
2. `aes_key = derive_key(ct_kem, shared_secret)`.
3. Generate a 12-byte random nonce.
4. `ciphertext = AES-256-GCM(aes_key, nonce, aad = HEADER ‖ 0u32, plaintext)`
   (the **raw** plaintext — no plaintext-level padding).
5. `wire::Envelope::encode` → core bytes.
6. Append random bytes up to `pad_block` (§7).

**Decrypt** (`decrypt`):

1. `Envelope::decode_prefix(blob)` → `(envelope, consumed)` (tolerates the
   trailing padding).
2. `shared_secret = kem::decaps(recipient_sk, envelope.ct_kem)`.
3. `aes_key = derive_key(envelope.ct_kem, shared_secret)`.
4. `plaintext = AES-256-GCM-open(aes_key, envelope.nonce, aad, envelope.ciphertext)`.

The deterministic core is factored into `seal_core` / `open_core`, which take a
fixed `(ct_kem, shared_secret, nonce)` — these carry the KAT.

---

## 7. Padding

The transport blob is the encoded core followed by **random** bytes up to a
caller-chosen `pad_block` (the relay default is 5 MiB; tests use smaller tiers):

```text
blob = core ‖ random_fill(pad_block − core.len())          (error if core > pad_block)
```

There is **no length suffix**: the core boundary is recovered by
`Envelope::decode_prefix`'s `consumed` count. This differs from the
`padding` module (M4 phase 1), whose length-suffixed scheme is **not** used by
Send mode — the relay pads the outer blob, not the plaintext.

---

## 8. Test vectors

`tests/kat/envelope-send.json` (20 vectors), checked by
`crates/paramant-core/tests/kat_envelope_send.rs`:

- `ct_kem` / `shared_secret` / `secret_key` come from @noble ML-KEM-768
  (deterministic seeds) and are KAT **inputs** — `oqs` cannot derandomise
  encapsulation (ADR-0005), so the encrypt direction is pinned on a fixed KEM
  result, exactly like `ml-kem-768.json`.
- Each vector pins `aes_key`, the core length, header, and core SHA-256, and
  verifies `decaps(secret_key, ct_kem) == shared_secret` (linking the Rust
  `oqs` KEM to the vectors) and that `open_core` recovers the `j % 251`
  plaintext.
- Plaintext lengths cover 0, 1, AEAD-block boundaries, and up to 1 MiB.

Full envelopes are non-deterministic (random encapsulation, nonce, padding), so
there are no full-blob SHA-256 anchors; the deterministic `seal_core`/`open_core`
core carries byte-equivalence, and `proptest_envelope_send.rs` covers the
randomised end-to-end flow.

---

## 9. Security considerations

- **The recipient KEM key is the access control.** Anyone with the recipient
  secret key can decrypt; there is no forward secrecy (the KEM key is long-term).
- **`SENDER_PUB` is not authenticated.** It is carried in the clear and is *not*
  in the AEAD AAD (only the header is), so it is an unauthenticated hint, not a
  trustworthy identity — anonymous mode provides no sender authentication by
  design. Tampering with it is undetectable; tampering with the header, KEM
  ciphertext, nonce or ciphertext makes decryption fail.
- **Algorithm binding.** The 10-byte header (incl. `KEM_ID`/`SIG_ID`) is in the
  AAD, so an attacker cannot alter the declared algorithms without breaking the
  GCM tag.
- **Nonce uniqueness.** A fresh random 12-byte nonce is generated per envelope;
  the key is unique per envelope (derived from a fresh KEM shared secret), so
  GCM nonce reuse across messages does not arise.
