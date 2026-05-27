# paramant-core

Post-quantum cryptographic core for [Paramant](https://paramant.app). It holds
the cryptographic primitives, wire format, and envelope logic  --  KEM, signatures,
AEAD, KDF, mnemonic, Merkle log, padding  --  as one small, auditable Rust library.
Every primitive is checked byte-for-byte against the production `paramant-relay`
(build 2.5.0), so the relay can adopt this core without any client-visible change.

> **Status: M0 (bootstrap).** The crate is an intentionally empty shell. The
> cryptographic modules land one milestone at a time (M1-M4). See
> [`BLUEPRINT.md`](BLUEPRINT.md) for the full plan.

## Modules (target layout)

Flat `crates/paramant-core/src/`, one file per concept, split only past 300 lines:

| File | Contents | Milestone |
|---|---|---|
| `error.rs` | `CoreError`, `CoreResult` | M1 |
| `kem.rs` | ML-KEM-768 + hybrid ECDH P-256 | M1-M2 |
| `sig.rs` | ML-DSA-65, SLH-DSA, Falcon | M2 |
| `aead.rs` | AES-256-GCM | M3 |
| `kdf.rs` | Argon2id + HKDF | M3 |
| `mnemonic.rs` | BIP-0039 (12-word) | M3 |
| `merkle.rs` | Merkle tree + Signed Tree Head | M4 |
| `padding.rs` | 4/64/512 KB + 5 MB blocks | M4 |
| `envelope.rs` | Send / ParaShare / ParaDrop | M4 |
| `wire.rs` | wire format v1 + TLV | M4 |

## Quick start

```sh
cargo build      # build the workspace
cargo test       # run unit + KAT + property tests
cargo doc --open # read the API docs
```

Requires the toolchain pinned in [`rust-toolchain.toml`](rust-toolchain.toml)
(Rust 1.95, installed automatically by rustup).

## Compile targets

One core, many consumers. Bindings are added at the milestone that needs them
(code-minimization, [ADR-0004](docs/adrs/0004-code-minimization.md)):

| Target | Command | Consumer | Added |
|---|---|---|---|
| Native lib | `cargo build --release` | Rust projects, CLI | M0 |
| Node native | `napi build --release` | paramant-relay | M5 |
| Browser WASM | `wasm-pack build --target web` | paramant.app/send | M6 |
| Python wheel | `maturin build --release` | Python SDK | M11+ |
| C ABI | `cargo build -p paramant-core-c` | Go SDK, mobile, OT | M11+ |

## Documentation

- [BLUEPRINT.md](BLUEPRINT.md)  --  full design and milestone plan
- [docs/architecture.md](docs/architecture.md)  --  workspace, modules, dependencies
- [docs/threat-model.md](docs/threat-model.md)  --  assets, adversaries, boundaries
- [docs/doc-conventions.md](docs/doc-conventions.md)  --  rustdoc, ADR, CHANGELOG rules
- [docs/adrs/](docs/adrs/)  --  Architecture Decision Records
- [SECURITY.md](SECURITY.md)  --  responsible disclosure
- [CONTRIBUTING.md](CONTRIBUTING.md)  --  how to contribute

Why Paramant is relevant lives at [paramant.app/vs](https://paramant.app/vs),
not in this README.

## License

[BUSL-1.1](LICENSE), converting to Apache-2.0 on 2029-01-01. Contact:
[mick@paramant.app](mailto:mick@paramant.app).
