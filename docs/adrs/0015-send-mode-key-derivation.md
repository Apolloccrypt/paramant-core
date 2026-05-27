# 0015. Send mode: anonymous KEM, HKDF key derivation, outer padding

Date: 2026-05-27
Status: Accepted

## Context

M4 phase 2b implements the first envelope mode. An earlier design described
"Send mode" as an anonymous, no-KEM transfer whose AES-256-GCM key is derived
from a key encoded in a URL fragment via HKDF, with the plaintext padded by the
`padding` module (M4 phase 1) before encryption.

Reading the relay source first (the standing rule from phase 2a) showed none of
that matches reality. `paramant-relay` (build 2.5.0 / `sdk-js` 3.0.0) has no
URL-fragment mode anywhere — not in `sdk-js`, not in the browser frontend. Its
anonymous transfer is `sendAnonymous`, which calls the same `_encrypt` as a
signed send but with `SIG_ID = 0x0000`. Concretely:

- It encapsulates to the recipient's **ML-KEM-768** public key; the AES key is
  derived from the **KEM shared secret**, not a fragment.
- Key derivation is `HKDF-SHA256(ikm = shared_secret, salt = ct_kem[0..32],
  info = "paramant-v1-aes-key")`, 32-byte output.
- The **raw** plaintext is AES-256-GCM-encrypted with `AAD = HEADER ‖
  chunk_index_be32`. There is no plaintext-level padding.
- The wire core is then padded with **random** bytes up to a caller-chosen
  block size; the boundary is recovered from the decoder's consumed-byte count,
  not a length suffix.

The relay's `_encrypt` runs WebCrypto HKDF + AES-GCM. Before writing Rust,
`scripts/derisk-send.mjs` proved that path byte-identical to the pure-Node
HMAC-HKDF + AES-256-GCM that paramant-core mirrors (and to the relay's own
`wireEncode` framing), across five fixed inputs.

## Decision

`envelope::send` implements the relay's anonymous mode exactly:

1. **KEM-based, not fragment-based.** `encrypt(recipient_pub, sender_pub,
   plaintext, pad_block)` encapsulates with ML-KEM-768, derives the key per the
   formula above, and seals with `SIG_ID = 0x0000`. `sender_pub` is an opaque,
   unauthenticated identifier (the relay uses the sender's own KEM public key).
2. **Outer random padding.** The encoded core is padded with random bytes to
   `pad_block`; `decode` is unchanged (strict) and a new additive
   `Envelope::decode_prefix` returns the consumed length so the envelope layer
   can ignore trailing padding (mirrors the relay's `consumedBytes`). The
   `padding` module is not used here.
3. **KAT on a deterministic core.** Full envelopes are non-deterministic
   (random encapsulation, nonce and padding), and `oqs` exposes no
   derandomised encapsulation (ADR-0005). So the byte-equivalence KAT pins the
   deterministic `seal_core` / `open_core`, taking `ct_kem` + `shared_secret`
   from @noble ML-KEM-768 as inputs, and links them to the Rust `oqs` KEM via
   `decaps(secret_key, ct_kem) == shared_secret` (the `ml-kem-768.json`
   pattern). The randomised end-to-end flow is covered by property tests.
4. **No PSS in v1.** The relay can mix a pre-shared secret into the HKDF IKM
   (`shared_secret ‖ sha256(pss)`); that is a relay-MITM hardening layer, not
   part of the anonymous primitive, and is deferred.

## Consequences

- The "Send" name is kept for continuity with the relay, but it is an anonymous
  KEM send; the URL-fragment concept is dropped as fictional.
- `decode_prefix` is the supported way to parse an envelope out of a padded or
  concatenated buffer; strict `decode` remains for exact-core checks.
- Signed (ParaShare) and mnemonic (ParaDrop) modes reuse `wire`, `aead`, `kdf`
  and `kem`; ParaDrop in particular does not use the PQHB format at all (it is a
  bare `nonce ‖ ct_len ‖ ct` packet keyed from a BIP-39 mnemonic) and will get
  its own analysis in a later phase.

## Alternatives

- **Implement the URL-fragment / no-KEM Send mode as described in the phase-2b
  brief**: rejected -- it does not exist in the relay; building it would violate
  ADR-0003 and produce blobs no relay or SDK accepts.
- **Pad the plaintext with the `padding` module before AEAD**: rejected -- the
  relay pads the outer blob with random fill and no length suffix; pre-padding
  the plaintext would change the bytes and the recovered length.
- **Pin a full-envelope SHA-256 anchor**: impossible -- encapsulation, nonce and
  padding are randomised and encapsulation cannot be derandomised in `oqs`.
