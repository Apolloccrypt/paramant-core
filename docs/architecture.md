# Architecture

*v0.1 — mirrors blueprint §2–4. Updated as milestones land.*

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
├── Cargo.toml                # workspace root + pinned dependency catalogue
├── rust-toolchain.toml       # Rust 1.80
├── crates/
│   ├── paramant-core/        # core lib (this is the whole product at M0)
│   └── paramant-core-node/   # NAPI binding — added at M5
├── tests/                    # kat/ (Known Answer Tests), fuzz/
├── scripts/extract-kat.js    # generates KAT vectors from paramant-relay
├── docs/                     # this file, threat model, conventions, ADRs
└── .github/workflows/ci.yml  # check, test, clippy, fmt, audit, deny
```

Crates are added one per milestone that justifies them: `paramant-core-node` (M5),
`paramant-core-wasm` (M6), then `-py` / `-c` / `-cli` at M11+ only when needed.
Never all upfront.

## Modules

The core is a flat `src/` — one file per concept, split only past 300 lines.
See the [README](../README.md#modules-target-layout) for the file/milestone table.
Per `pub` item: rustdoc with an example. No traits without two implementations,
no generics without a reason, no abstraction that does not pay for itself
([ADR-0004](adrs/0004-code-minimization.md)).

## Dependencies

Twelve, pinned, no wildcards (blueprint §4). Each does something existing deps
cannot:

- **Post-quantum:** `oqs` (liboqs — NIST FIPS 203/204/205/206). See
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

One codebase, several ABIs: native lib (M0), Node via NAPI-RS (M5), browser WASM
(M6), Python wheel / C ABI (M11+). The crypto and wire format are written once.

## Source of truth

GitHub is the source of truth; the server pulls released artifacts via CI, never
the reverse. Crypto code carries no secrets, so the repository can be
source-available from commit 1. See [ADR-0003](adrs/0003-source-of-truth.md).
