# Architecture

*v0.1  --  mirrors blueprint Sec.2-4. Updated as milestones land.*

## Two repositories

| Repo | Role | Language |
|---|---|---|
| `Apolloccrypt/paramant-relay` | HTTP, admin, routing, billing | Node.js |
| `Apolloccrypt/paramant-core` | Crypto primitives, wire format, envelopes | Rust |

`paramant-relay` (build 2.5.0) stays in production and shrinks as `paramant-core`
grows under it. After M7, all relay crypto is imported from `@paramant/core`
(via NAPI-RS); the relay keeps HTTP, admin, routing, and billing.

## Workspace layout

```
paramant-core/
+-- Cargo.toml                # workspace root + pinned dependency catalogue
+-- rust-toolchain.toml       # Rust 1.95
+-- crates/
|   +-- paramant-core/        # core lib (this is the whole product at M0)
|   +-- paramant-core-node/   # NAPI binding  --  added at M5
|   +-- cross-impl-validator/ # browser RustCrypto KAT gate  --  added at M6
+-- tests/                    # kat/ (Known Answer Tests)
+-- scripts/extract-kat.mjs   # generates KAT vectors from paramant-relay
+-- docs/                     # this file, threat model, conventions, ADRs
+-- .github/workflows/ci.yml  # check, test, clippy, fmt, audit, deny
```

Crates are added one per milestone that justifies them: `paramant-core-node` (M5)
and the test-only `cross-impl-validator` (M6); `-py` / `-c` / `-cli` come at M11+
only when needed. Never all upfront. A `paramant-core-wasm` crate was considered at
M6 but rejected ([ADR-0020](adrs/0020-crypto-wasm-cross-impl-via-rustcrypto-crates.md)):
paramant-core's C dependencies cannot target wasm32, so browser crypto stays in
`paramant-relay/crypto-wasm` (RustCrypto) and is kept byte-equivalent by the
cross-impl KAT here.

## Modules

The core is a flat `src/`  --  one file per concept, split only past 300 lines.
See the [README](../README.md#modules-target-layout) for the file/milestone table.
Per `pub` item: rustdoc with an example. No traits without two implementations,
no generics without a reason, no abstraction that does not pay for itself
([ADR-0004](adrs/0004-code-minimization.md)).

## Dependencies

Twelve, pinned, no wildcards (blueprint Sec.4). Each does something existing deps
cannot:

- **Post-quantum:** `oqs` (liboqs  --  NIST FIPS 203/204/205/206). See
  [ADR-0002](adrs/0002-oqs-vs-pure-rust.md).
- **Classical:** `aws-lc-rs` (FIPS-validated AES-GCM, ECDH P-256, SHA-2).
- **KDF/hash:** `argon2`, `hkdf`, `sha2`.
- **Mnemonic:** `bip39`.
- **Memory safety:** `zeroize`, `subtle`.
- **Serialization:** `serde`, `serde_json`, `hex`.
- **Errors:** `thiserror`.
- **Testing only:** `proptest`, `criterion`.

Deliberately absent: `tokio` (no async in core), `anyhow` (library code uses
`thiserror`), `tracing` (logging is the consumer's job), `clap` (CLI only),
`rayon` (parallelism is the consumer's choice).

## Compile targets

One codebase, several ABIs: native lib (M0), Node via NAPI-RS (M5), Python wheel /
C ABI (M11+). The crypto and wire format are written once. There is no browser-WASM
build of paramant-core itself  --  its C dependencies cannot target wasm32  --  so the
browser uses the RustCrypto-based `paramant-relay/crypto-wasm`, kept byte-equivalent
via `cross-impl-validator` ([ADR-0020](adrs/0020-crypto-wasm-cross-impl-via-rustcrypto-crates.md)).

## Source of truth

GitHub is the source of truth; the server pulls released artifacts via CI, never
the reverse. Crypto code carries no secrets, so the repository can be
source-available from commit 1. See [ADR-0003](adrs/0003-source-of-truth.md).
