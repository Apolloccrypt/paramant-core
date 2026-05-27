# 0017. ParaDrop: BIP-39 entropy-derived keys, no PQHB framing

Date: 2026-05-27
Status: Accepted

## Context

M4 phase 2c's final mode is ParaDrop, the anonymous BIP-39 "drop" (relay
`drop`/`pickup`). Reading the relay source pinned several things that differ
from Send/ParaShare:

1. **It is not PQHB-framed.** The packet is `nonce(12) || ct_len_be32 ||
   ciphertext`; the boundary is the explicit `ct_len`, so trailing block padding
   is ignored on open. There is no magic, version, KEM or signature.
2. **Keys come from the raw 16-byte entropy, not the BIP-39 seed.**
   `_deriveDropKeys(entropy)` runs HKDF-SHA256 directly on the entropy:
   `aes_key = HKDF(ikm=entropy, salt="paramant-drop-v1", info="aes-key", 32)` and
   `lookup_id = SHA-256(HKDF(ikm=entropy, salt="paramant-drop-v1",
   info="lookup-id", 32))`. The mnemonic is only a human-transcribable encoding
   of that entropy; `to_seed()` (PBKDF2) is **not** used here.
3. **AEAD uses no AAD.** `crypto.subtle.encrypt({name:'AES-GCM', iv:nonce}, ...)`
   passes no `additionalData`; there is no header to bind.
4. **`lookup_id` is a relay storage key**, not payload crypto -- the relay stores
   and retrieves the blob under its hex form.

The whole path was de-risked in `scripts/derisk-paradrop.mjs` (WebCrypto ==
pure-Node) before any Rust.

## Decision

`envelope::para_drop` mirrors the relay exactly:

1. `drop(plaintext, pad_block) -> (Mnemonic, blob)` generates 16 bytes of entropy,
   builds the 12-word mnemonic, seals the packet, and pads with random bytes to
   `pad_block`. `pickup(mnemonic, blob) -> plaintext` derives the entropy from
   the mnemonic and opens.
2. `derive`, `seal` and `open` are the deterministic core. `derive(entropy)`
   returns `(aes_key, lookup_id)`; `seal(entropy, nonce, plaintext)` builds the
   `nonce || ct_len_be32 || ct` packet with AES-256-GCM and no AAD.
3. **`Mnemonic::to_entropy` is added** (M3's `mnemonic` only exposed
   entropy -> mnemonic and seed derivation). It returns the raw entropy in a
   `Zeroizing<Vec<u8>>`, since that entropy is the symmetric secret.
4. **KAT pins full-packet SHA-256 anchors.** Unlike Send/ParaShare there is no
   randomised KEM or hedged signature, so given `(entropy, nonce, plaintext)` the
   packet is fully deterministic and reproducible in Rust. The entropy<->mnemonic
   mapping itself stays covered by `bip39.json`; the ParaDrop KAT self-checks the
   round-trip and `pickup`.

## Consequences

- ParaDrop shares only `envelope::{random_nonce, pad_to_block}` and `aead`/`kdf`
  with the other modes; it deliberately does not touch `wire` (no PQHB).
- `lookup_id` is exposed for the relay-routing layer (M5) but is not needed to
  decrypt; it is derived but otherwise inert in the core.
- Wrong mnemonic -> wrong key -> AEAD tag failure on `open` (no separate error
  path), matching the relay's "drop not found / wrong mnemonic" behaviour at the
  crypto layer.

## Alternatives

- **Use the BIP-39 seed (`to_seed`) as the HKDF input**: rejected -- the relay
  feeds the raw entropy to HKDF; using the PBKDF2 seed would derive different
  keys and never interoperate.
- **Reuse the PQHB `wire` codec for the packet**: rejected -- the relay's drop
  packet is a bare `nonce || ct_len || ct`, not a PQHB envelope; forcing it
  through `wire` would not match the bytes.
- **Bind a header as AAD**: rejected -- there is no header to bind, and the relay
  passes no AAD.
