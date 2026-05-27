# 0016. ParaShare: single ML-KEM-768 + ML-DSA-65 signature over the envelope

Date: 2026-05-27
Status: Accepted

## Context

M4 phase 2c adds ParaShare, the signed device-paired send. In paramant-relay it
is the default `send`/`_encrypt` path with `SIG_ID != 0x0000` (default ML-DSA-65,
`0x0002`). It shares all of Send mode's key handling and adds a signature.

Reading the relay source pinned three details a fresh implementer would
otherwise guess wrong:

1. **One KEM, not the hybrid.** `_encrypt` calls `kemEngine(kemId)` -- a single
   ML-KEM-768. paramant-core has a `kem::hybrid` (ML-KEM-768 + ECDH P-256, M2),
   but the relay's wire path does not use it, so ParaShare must not either.
2. **`SENDER_PUB` holds the signing key.** When signed, `senderPub` is the
   sender's ML-DSA-65 public key (1952 bytes), not the KEM public key. The
   recipient verifies the embedded signature against it without an out-of-band
   lookup. (Anonymous Send puts the KEM public key there instead.)
3. **The signed message and its order.** The signature covers
   `ct_kem || sender_pub || nonce || ciphertext || aad`, where `aad = HEADER(10)
   || chunk_index_be32` and the header carries `SIG_ID = 0x0002`. Signing happens
   after AEAD encryption (it covers the ciphertext).

The AES key derivation is identical to Send
(`HKDF-SHA256(ikm = shared_secret, salt = ct_kem[0..32], info =
"paramant-v1-aes-key")`), so `para_share` reuses `send::derive_key`. The whole
path was de-risked in `scripts/derisk-parashare.mjs` before any Rust.

## Decision

`envelope::para_share` mirrors the relay exactly:

1. `encrypt(recipient, signer_sk, signer_pub, plaintext, pad_block)` does single
   ML-KEM-768 encapsulation, derives the key as in Send, AES-256-GCM-encrypts the
   raw plaintext with the header as AAD, signs the message above with ML-DSA-65,
   assembles the PQHB envelope (`SIG_ID = 0x0002`, `SENDER_PUB = signer_pub`),
   and pads the core to `pad_block`.
2. `decrypt(recipient_sk, blob)` decodes (tolerating trailing padding), verifies
   the signature against the carried `SENDER_PUB`, decapsulates, decrypts, and
   returns `(plaintext, sender_pub)`. Like the relay it enforces only
   cryptographic validity; pinning the sender key (TOFU) is the caller's job,
   which is why `decrypt` hands the verified key back.
3. **KAT verifies, does not reproduce, the signature.** `oqs` ML-DSA signing is
   hedged (randomised) and exposes no derandomisation (ADR-0005), so a full
   envelope is not byte-reproducible. The KAT takes a deterministic @noble
   ML-DSA-65 signature as an input, pins the deterministic framing through
   `seal_core(.., signature)`, links the KEM via `decaps == shared_secret`, and
   checks `sig::ml_dsa_65::verify` accepts the @noble signature -- the same
   cross-implementation strategy as `ml-dsa-65.json`. The randomised end-to-end
   `encrypt`/`decrypt` flow is covered by property tests.

## Consequences

- `para_share` depends on `send::derive_key` and the shared
  `envelope::{random_nonce, pad_to_block}` helpers (promoted from `send` in this
  phase); the HKDF/AEAD path is defined once.
- A future hybrid-KEM or alternative-signature send would be a new `SIG_ID`/
  `KEM_ID` combination, not a change to this mode.
- `decrypt` returning the verified `sender_pub` is the seam where a future TOFU /
  fingerprint layer (relay `_tofuCheck`) plugs in.

## Alternatives

- **Use `kem::hybrid` for ParaShare**: rejected -- the relay's signed path uses a
  single ML-KEM-768; using the hybrid would produce blobs it cannot decode.
- **Reproduce the signature bytes in the KAT**: impossible -- hedged ML-DSA
  signing is randomised and `oqs` has no derandomised entry point.
- **Verify against a caller-pinned key inside `decrypt`**: rejected -- matches the
  relay by verifying against the carried key and returning it for the caller to
  pin, keeping the core free of trust-store policy.
