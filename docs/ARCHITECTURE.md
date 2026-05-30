# Paramant architecture (cross-repo)

This is the authoritative overview of how paramant-core and paramant-relay fit
together. Both repositories link here.

## The three layers

```
+-------------------------------------------------------------+
|  paramant.app frontend (browser)                            |
|  - /send: WebCrypto + URL fragment (raw AES-GCM)            |
|  - /parashare /ontvang: crypto-wasm 0x03 hybrid             |
|  - /sign /verify (planned): crypto-wasm ML-DSA              |
+----------------------+--------------------------------------+
                       |
                       | HTTPS
                       v
+-------------------------------------------------------------+
|  paramant-relay (Node.js, Apolloccrypt/paramant-relay)      |
|  - /v2/* HTTP API for SDK clients                           |
|  - admin dashboard, Stripe billing                          |
|  - 5 sector relays + admin (docker compose)                 |
|  - crypto-wasm vendored (RustCrypto wasm, browser)          |
|  - @paramant/core NAPI binding (server-side, since M5b)     |
+----------------------+--------------------------------------+
                       |
                       | npm @paramant/core (NAPI .node)
                       v
+-------------------------------------------------------------+
|  paramant-core (Rust, Apolloccrypt/paramant-core)           |
|  - primitives: KEM, signatures, AEAD, KDF, mnemonic         |
|  - protocol: Merkle, padding, wire, envelopes               |
|  - paramant-core-node (NAPI binding)                        |
|  - cross-impl-validator (ADR-0020, ADR-0021)                |
+-------------------------------------------------------------+
```

## Three crypto codepaths

| Path | Implementation | Wire format | Audience |
|---|---|---|---|
| Server, native, SDKs | paramant-core (oqs + aws-lc-rs, C) | PQHB | non-browser |
| Browser parashare/ontvang | crypto-wasm (RustCrypto, wasm32) | 0x03 hybrid | browser interactive |
| Browser /send (anonymous) | WebCrypto + URL fragment | raw AES-GCM | browser anonymous |

All three are under paramant-core's audit governance via cross-impl KAT validation
(ADR-0020). The browser RustCrypto crates are validated byte-for-byte against the
same `@noble`-anchored vectors the server stack uses.

## Source-of-truth flow

paramant-relay defines the wire formats canonically. paramant-core's
`wire-format-v1.md` mirrors PQHB byte-for-byte (ADR-0003, ADR-0014). The browser
0x03 format is documented in `wire-format-0x03.md`. Spec updates flow from relay to
core, never the other way.

Crypto correctness flows from the FIPS reference (the `@noble/post-quantum` library)
through three implementations:

- **oqs:** paramant-core decapsulation validated against `@noble` vectors (ADR-0005).
- **RustCrypto:** the cross-impl-validator crate validates ML-KEM, AES-GCM, HKDF,
  and ML-DSA-65 against the same vectors (ADR-0020, ADR-0021).
- **Browser WebCrypto:** spec compliance audited via the browser vendors.

## Deploy and release coordination

- **paramant-core:** pre-1.0 (`0.5.0-alpha.1`). Consumed by the relay via a git
  commit pin, not an npm publish, for now.
- **paramant-relay:** production deploy via SSH plus `docker compose build`. The
  multi-stage Dockerfile clones paramant-core at `PARAMANT_CORE_COMMIT` and builds
  the NAPI binding for musl in-image.

Compatibility matrix:

| paramant-relay | @paramant/core | paramant-core commit |
|---|---|---|
| 2.5.0 (pre-M5b) | none (used `@noble` directly) | n/a |
| 3.0.0 (M5b) | 0.5.0-alpha.1 | `dc454d4` |
| 3.1.0+ (planned, M8) | TBD | TBD |

## How to contribute changes

- **Crypto primitives, wire format, envelopes:** PR to paramant-core. After merge,
  a relay maintainer bumps `PARAMANT_CORE_COMMIT` in the relay Dockerfile.
- **HTTP API, admin UI, billing:** PR to paramant-relay.
- **Cross-repo changes:** open an issue in paramant-core first to agree the
  approach, then land coordinated PRs.
