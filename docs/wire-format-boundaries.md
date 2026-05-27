# Wire format boundaries in paramant

Paramant operates **three** wire formats, produced by three crypto
implementations, for three client populations. This is intentional, not a
migration backlog. This document is the M6 "A3" deliverable: it records the
boundary so the coexistence is understood rather than mistaken for drift.

## 1. The three formats

| Flow                    | Client                | Format                                | Relay handling      |
|-------------------------|-----------------------|---------------------------------------|---------------------|
| `/send`                 | browser WebCrypto     | raw AES-256-GCM, key in URL fragment  | blind pass-through  |
| parashare / drop / ontvang | crypto-wasm (RustCrypto) | `0x03` hybrid ML-KEM-768 + ECDH-P256 | blind pass-through  |
| SDK (js/py) + native    | paramant-core (oqs/aws-lc-rs) | PQHB ([v1](wire-format-v1.md))  | decoded / validated |

- `/send`: `send.html` generates an AES-256-GCM key in the browser, encrypts with
  WebCrypto, and puts `base64url(key[32] || iv[12])` in the URL fragment ("the
  key lives in the link"). No KEM, no envelope. Uploaded to `/v2/anon-inbound`.
- parashare/drop/ontvang: `crypto-bridge.js` -> `crypto-wasm`, the `0x03` hybrid
  envelope ([wire-format-0x03.md](wire-format-0x03.md)).
- SDK + native: PQHB, the format paramant-core and the paramant-relay reference
  encoder implement.

## 2. The relay is a blind store for non-PQHB

`paramant-relay`'s `peekInboundBlob()` does `if (!wireFormat.isV1(blob)) return
null;` -- non-PQHB blobs **pass through** and are stored opaquely in RAM, served
back to the recipient unmodified. PQHB validation (`/v2/inbound`,
`/v2/anon-inbound`, drop-create) only **rejects malformed PQHB** (HTTP 415/400);
it never rejects a well-formed non-PQHB blob.

Consequence: **format convergence is not a relay-correctness concern.** Each
client population reads what its peer wrote; the relay never interprets the
browser formats. A browser `0x03` blob is written and read by crypto-wasm; a
`/send` fragment blob is written and read by WebCrypto; only SDK/native traffic
exercises the PQHB decoder.

## 3. Why the formats are not converged

`0x03` and PQHB differ in more than framing:

- **KEM construction.** `0x03` is hybrid ML-KEM-768 + ECDH-P256 (two shared
  secrets HKDF-combined). PQHB Send/ParaShare use a single ML-KEM-768. Different
  keys for the same plaintext.
- **KDF.** `0x03` uses `info = "paramant-v2"`; PQHB uses
  `info = "paramant-v1-aes-key"`.
- **Backend.** crypto-wasm runs on RustCrypto (`ml-kem`, `p256`, `aes-gcm`) so it
  can target wasm32; paramant-core runs on `oqs` + `aws-lc-rs` (C), which cannot
  compile to wasm32. A single codebase across browser and native is therefore
  structurally impossible without a third crypto backend.
- **No functional gain.** The relay never reads either browser format, so
  aligning them buys no interoperability, while a migration would risk
  in-flight/at-rest `0x03` data.

Decision: keep three formats. Unify the *audit story* (section 4), not the bytes.

## 4. Audit scope

All three crypto paths are in scope:

- **paramant-core** (Rust, oqs + aws-lc-rs): native + Node, KAT-validated against
  `@noble`-anchored vectors in `tests/kat/`, exercised in CI.
- **crypto-wasm** (Rust, RustCrypto): the browser KEM path. Its underlying
  primitives (`ml-kem`, `aes-gcm`, `hkdf`, `sha2`) are well-known RustCrypto
  crates; equivalence with the FIPS/`@noble` vectors is asserted at the crate
  level (crypto-wasm itself exposes only the randomised hybrid blob API, so it
  has no fixed-vector KAT of its own -- see wire-format-0x03.md section 4).
- **`/send` WebCrypto**: browser-native AES-256-GCM; audited by spec compliance
  (it is the platform's FIPS-validated AES-GCM).

The cross-implementation validation strategy and where crypto-wasm lives for
governance are recorded in the M6 ADR.
