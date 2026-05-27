# Changelog

All notable changes to paramant-core are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **ParaSign Sg1 step 1**: cross-impl ML-DSA-65 validation added to
  `cross-impl-validator`. Proves the RustCrypto `ml-dsa 0.1.0` crate (the
  browser/wasm signer ParaSign will use) is equivalent to the implementation
  paramant-core trusts: verify-KAT accepts all 50 `@noble`-anchored signatures
  (external verify, empty context) and rejects tampered messages, and a
  seeded-keygen-KAT shows `SigningKey::from_seed(xi)` reproduces the `@noble`
  public key for every seed -- validating Sg0 ADR-3's mnemonic-deterministic
  key. Runs in the existing `cross-impl-rustcrypto-kat` CI job.
  [ADR-0021](docs/adrs/0021-ml-dsa-65-cross-impl-validation.md).
- **M6 (Browser convergence + cross-impl validation)**: documents that paramant
  runs three wire formats by design (PQHB native/SDK, `0x03` browser hybrid via
  `paramant-relay/crypto-wasm`, `/send` WebCrypto URL-fragment) and that the
  relay blind-stores non-PQHB blobs, so convergence is not a correctness concern
  ([wire-format-boundaries.md](docs/wire-format-boundaries.md),
  [wire-format-0x03.md](docs/wire-format-0x03.md)). Adds `cross-impl-validator`
  (test-only crate): the RustCrypto crates crypto-wasm depends on (`ml-kem`,
  `aes-gcm`, `hkdf`, `sha2`) are KAT-validated against the same `@noble`-anchored
  `tests/kat` vectors as paramant-core's `oqs`/`aws-lc-rs` backend, proving
  primitive byte-equivalence across all three crypto paths. New
  `cross-impl-rustcrypto-kat` CI job. paramant-core cannot target wasm32 (C
  deps), so no `paramant-core-wasm` crate; governance is docs + this KAT, not a
  submodule. [ADR-0020](docs/adrs/0020-crypto-wasm-cross-impl-via-rustcrypto-crates.md).
- **M5a (Bridge)**: `crates/paramant-core-node` -- a napi-rs binding published as
  `@paramant/core`, exposing paramant-core's KEM, ML-DSA-65, AES-256-GCM and the
  three envelope modes to paramant-relay as thin `#[napi]` wrappers (Buffers in/
  out, `CoreError` -> JS `Error`). Interop test (`test/interop.mjs`) runs the
  binding over the relay-anchored `tests/kat/` vectors plus envelope round-trips
  (149 checks); a `napi-interop` CI job builds the cdylib and runs it. Benchmark
  (`scripts/bench-napi.mjs`, `docs/benchmarks.md`) and the endpoint-swap runbook
  (`docs/deploy-bridge.md`) included. The binding manifest is permitted by
  [ADR-0018](docs/adrs/0018-allow-binding-manifests.md); design in
  [ADR-0019](docs/adrs/0019-napi-binding.md). The live endpoint swap + bench vs
  the legacy relay path is M5b (in the paramant-relay repo).
- **M4 (in progress)** (Transparency & Framing): `merkle` + `padding` + `wire` +
  `envelope::{send, para_share, para_drop}`. 135 new KAT vectors (**325 total**).
- M4 phase 2c: `envelope::para_drop` module -- anonymous BIP-39 mnemonic drop,
  byte-equivalent with paramant-relay `sdk-js` `drop`/`pickup`. Not PQHB-framed:
  keys are `HKDF-SHA256(ikm = entropy, salt = "paramant-drop-v1")` for an
  `"aes-key"` and a `SHA-256("lookup-id")` storage id; AES-256-GCM with no AAD;
  packet `nonce || ct_len_be32 || ciphertext`. `drop` returns the 12-word
  mnemonic + padded blob, `pickup` reverses it. Adds `Mnemonic::to_entropy`.
  Mirrored in [ADR-0017](docs/adrs/0017-paradrop-mnemonic-derivation.md). 15 KAT
  vectors with full-packet SHA-256 anchors (deterministic -- no KEM/signature);
  128-case roundtrip + wrong-mnemonic + tamper proptest. De-risked by
  `scripts/derisk-paradrop.mjs`.
- M4 phase 2c: `envelope::para_share` module -- signed, device-paired send,
  byte-equivalent with paramant-relay `sdk-js` `send`/`_encrypt` (`SIG_ID =
  0x0002` ML-DSA-65): single ML-KEM-768 (not the hybrid KEM), Send-mode key
  derivation and AEAD, plus an ML-DSA-65 signature over
  `ct_kem || sender_pub || nonce || ciphertext || aad` (`sender_pub` = the
  ML-DSA-65 public key). `decrypt` verifies the signature against the carried
  key and returns it for caller-side pinning. Shared `random_nonce`/`pad_to_block`
  promoted to `envelope`. Mirrored in [ADR-0016](docs/adrs/0016-parashare-signature.md).
  15 KAT vectors (deterministic `seal_core` framing on @noble inputs; the Rust
  ML-DSA-65 verifier checks the @noble signature, decaps links the KEM); 48-case
  roundtrip + wrong-recipient + tamper proptest. De-risked by
  `scripts/derisk-parashare.mjs` (WebCrypto == pure-Node, signature verifies,
  relay framing round-trips).
- M4 phase 2b: `envelope::send` module  --  anonymous Send-mode envelope,
  byte-equivalent with paramant-relay `sdk-js` `sendAnonymous` (`SIG_ID =
  0x0000`): ML-KEM-768 to the recipient, `HKDF-SHA256(ikm = shared_secret,
  salt = ct_kem[0..32], info = "paramant-v1-aes-key")`, AES-256-GCM with the
  PQHB header bound as AAD, and outer random padding to a caller block size.
  Adds `Envelope::decode_prefix` (trailing-tolerant, returns consumed length).
  Mirrored in [`docs/envelope-send.md`](docs/envelope-send.md);
  [ADR-0015](docs/adrs/0015-send-mode-key-derivation.md) records the
  KEM-not-fragment design. 20 KAT vectors (deterministic `seal_core`/`open_core`
  on @noble ML-KEM-768 inputs, linked via `decaps`); 128-case roundtrip +
  wrong-recipient + tamper proptest. De-risked by `scripts/derisk-send.mjs`
  (WebCrypto == pure-Node == relay framing).
- M4 phase 2a: `wire` module  --  the `PQHB` envelope codec, byte-equivalent with
  paramant-relay's wire format v1 (`relay/crypto/wire-format.js`, approved
  2026-04-24): 10-byte magic header (`KEM_ID`/`SIG_ID` registry, reserved
  `FLAGS`), big-endian length-prefixed body, and `aad_for_chunk` binding the
  header to AEAD integrity. Mirrored in
  [`docs/wire-format-v1.md`](docs/wire-format-v1.md);
  [ADR-0014](docs/adrs/0014-wire-format-byte-equivalence-with-relay.md) records
  the byte-equivalence policy. 30 KAT vectors including two SHA-256-anchored
  vectors from the relay spec (signed 5090 B, anonymous 1778 B); 256-case
  round-trip + mutation/tamper-reject proptest.
- M4: `merkle` module  --  append-only Merkle tree with RFC 6962 hash construction
  (`0x00` leaf-prefix, `0x01` internal-prefix; empty tree = `SHA-256("")`;
  [ADR-0013](docs/adrs/0013-merkle-rfc6962-hash-construction.md)) plus inclusion
  proofs and a `SignedTreeHead` signed with ML-DSA-65. 30 KAT vectors: 20 Merkle
  (RFC 6962 self-checked roots + generated) and 10 STH cross-impl with
  `@noble/post-quantum` ML-DSA-65; 256-case proptest.
- M4: `padding` module  --  length-hiding block padding (4K/64K/512K/5M) with random
  filler and a little-endian `u32` length suffix. 25 KAT vectors over all four
  block sizes and boundary cases; 256-case round-trip + selection-monotonicity
  proptest.
- **M3 complete** (Symmetric Layer): `aead` + `kdf` + `mnemonic` +
  constant-time tests. KAT corpus now **190 vectors**.
- M3: `kdf` module  --  Argon2id password hashing at OWASP-2024 params
  (`m=19456` KiB, `t=2`, `p=1`; [ADR-0011](docs/adrs/0011-argon2id-parameters.md))
  with constant-time `verify_password` (`subtle`), and HKDF-SHA256
  (`extract`/`expand`). 35 KAT vectors: 20 HKDF (RFC 5869 Appendix A + generated,
  pure HMAC) and 15 Argon2id (`@noble/hashes` validated against the RFC 9106
  Appendix A vector before emitting at our params).
- M3: `mnemonic` module  --  BIP-0039 12-word English mnemonics via the `bip39`
  crate (`generate`/`generate_from_entropy`/`parse`/`to_seed`). 15 KAT vectors
  from trezor/python-mnemonic canonical vectors (phrase + seed cross-checked).
- M3: constant-time policy ([ADR-0012](docs/adrs/0012-constant-time-policy.md))  -- 
  `tests/constant_time.rs` asserts the structural property (whole-input
  comparison via `subtle::ConstantTimeEq`, no early return) for `aead::decrypt`
  and `kdf::argon2id::verify_password`; threat model lists the must-be-CT
  functions.
- M3: `aead` module  --  AES-256-GCM (FIPS 197 + SP 800-38D) via
  `aws-lc-rs`. 40 KAT vectors byte-equivalent with `@noble/ciphers` (encrypt =
  `ct||tag`) + decrypt + tamper rejection + a 256-case round-trip/AAD-binding
  property.
- M2 (in progress): `sig` module  --  ML-DSA-65 (FIPS 204) `keygen`/`sign`/`verify`
  via liboqs, per-algorithm types ([ADR-0007](docs/adrs/0007-signature-type-pattern.md)),
  default scheme ([ADR-0008](docs/adrs/0008-default-signature.md)). 30 KAT vectors
  verifying @noble signatures + tamper rejection + interop + sign/verify proptest.
- M2 (in progress): `sig::slh_dsa` (liboqs SPHINCS+-SHA2-128f-simple) and
  `sig::falcon_512`, round-trip tested. Neither is cross-impl KAT'd: liboqs 0.12's
  SPHINCS+ is not FIPS-205 SLH-DSA ([ADR-0009](docs/adrs/0009-sphincs-vs-slh-dsa.md)),
  and Falcon's encoding varies between implementations. `paramant-relay` uses neither.
- M2: hybrid KEM `kem::hybrid`  --  ML-KEM-768  XOR  ECDH P-256 (`aws-lc-rs`), combined via
  HKDF-Extract per draft-ietf-tls-hybrid-design
  ([ADR-0010](docs/adrs/0010-hybrid-kem-construction.md)); round-trip + property
  tested. `kem.rs` split into `kem/{mod,hybrid}.rs` (>300 lines). KAT corpus raised
  to 100 cross-impl vectors (50 ML-KEM + 50 ML-DSA). **M2 complete.**
- M1 (First Light): `kem` module  --  ML-KEM-768 (FIPS 203) `keygen`/`encaps`/`decaps`
  via liboqs (`oqs`), with zeroizing secret types and no `unsafe`; `error` module
  (`CoreError`/`CoreResult`).
- ML-KEM-768 KAT: 30 deterministic vectors from `@noble/post-quantum`
  (`scripts/extract-kat.mjs`  ->  `tests/kat/ml-kem-768.json`); tests prove `decaps`
  byte-equivalence with paramant-relay, interop on @noble keypairs, and a
  512-case round-trip property. KAT strategy in
  [ADR-0005](docs/adrs/0005-kem-kat-strategy.md).
- M0 bootstrap: Cargo workspace with the `paramant-core` crate (empty shell),
  pinned dependency catalogue, and `rust-toolchain.toml` (Rust 1.80).
- Documentation set: `README`, `SECURITY`, `CONTRIBUTING`, `LICENSE` (BUSL-1.1),
  `docs/architecture.md`, `docs/threat-model.md`, `docs/doc-conventions.md`.
- Architecture Decision Records 0001-0004 (edition/MSRV, oqs-vs-pure-rust,
  source-of-truth, code-minimization).
- CI (`cargo check/test/clippy -D warnings/fmt --check`, `cargo audit`,
  `cargo deny`) and weekly Dependabot for Cargo.

### Changed
- Repository restructured from the March 2026 single-crate prototype to the
  blueprint v3.1 workspace layout. The prototype is preserved at the
  `archive/march-2026-prototype` tag.
- MSRV bumped 1.80  ->  **1.95** (pinned `1.95.0`). `oqs` 0.10, needed at M1 for
  seed-based keygen, pulls an edition-2024 dependency requiring rustc >= 1.85; we
  pinned latest stable. See [ADR-0001](docs/adrs/0001-rust-edition-msrv.md).
- Dependabot ignores cargo major bumps (deliberate, manual review per ADR-0004).

## [0.1.0] - TBD

- Initial milestone series (M1-M4) lands the cryptographic core.
