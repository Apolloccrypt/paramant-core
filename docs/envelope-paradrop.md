# ParaDrop packet (anonymous BIP-39 drop)

**Status**: paramant-core implementation tracking paramant-relay `sdk-js`
(`index.js` `drop` / `pickup`).

ParaDrop is the odd one out: it does **not** use the PQHB
[wire format](wire-format-v1.md). There is no KEM and no signature -- both sides
share a 12-word BIP-39 mnemonic out of band, and all key material comes from its
16 bytes of entropy. Source of truth: paramant-relay (ADR-0003); rationale in
[ADR-0017](adrs/0017-paradrop-mnemonic-derivation.md). De-risked in
`scripts/derisk-paradrop.mjs` (WebCrypto == pure-Node) before any Rust.

## 1. Key derivation

```text
prk        = HKDF-Extract(salt = "paramant-drop-v1", ikm = entropy)   # 16-byte entropy
aes_key    = HKDF-Expand(prk, "aes-key",   32)
lookup_id  = SHA-256(HKDF-Expand(prk, "lookup-id", 32))               # relay storage key
```

The **raw entropy** is the HKDF input -- not the BIP-39 seed (`to_seed`/PBKDF2 is
not used). The mnemonic only encodes that entropy for the human.

## 2. Packet

AES-256-GCM with **no AAD**, framed (not PQHB):

```text
packet = nonce(12) || ct_len_be32 || ciphertext        (ciphertext = ct || tag)
```

The on-wire blob appends random padding to a caller block size; `open` reads the
explicit `ct_len` and ignores trailing padding.

## 3. Flow

- `drop(plaintext, pad_block) -> (Mnemonic, blob)`: random 16-byte entropy -> 12-word
  mnemonic; `seal`; pad to `pad_block`.
- `pickup(mnemonic, blob) -> plaintext`: `mnemonic.to_entropy()`; `open`.
- Deterministic core: `derive(entropy) -> (aes_key, lookup_id)`,
  `seal(entropy, nonce, plaintext) -> packet`, `open(entropy, packet) -> plaintext`.
- `lookup_id(entropy)` exposes the relay storage key (hex-encode for the API);
  it is not needed to decrypt.

## 4. Test vectors

`tests/kat/envelope-paradrop.json` (15 vectors), checked by
`crates/paramant-core/tests/kat_envelope_paradrop.rs`. Because nothing is
randomised in the core, each vector pins a **full-packet SHA-256 anchor** plus
`aes_key` and `lookup_id`, and self-checks the entropy<->mnemonic round-trip and
`pickup`. The mnemonic<->entropy mapping itself is covered by `bip39.json`.
`proptest_envelope_paradrop.rs` covers the randomised `drop`/`pickup` flow,
wrong-mnemonic rejection, and tamper rejection.

## 5. Security considerations

- **The mnemonic is the whole secret.** Anyone with the 12 words decrypts; there
  is no forward secrecy and no sender authentication. A leaked mnemonic is a
  full compromise.
- **Wrong mnemonic -> AEAD failure.** A different mnemonic derives a different key
  and `open` fails the GCM tag; there is no distinct "wrong key" signal at the
  crypto layer (the relay reports "not found / wrong mnemonic" at the API layer).
- **`lookup_id` is unlinkable to the key.** It is a separate HKDF branch hashed
  with SHA-256, so the storage key reveals nothing about `aes_key`.
