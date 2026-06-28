# paramant-core

Post-quantum cryptographic core for [Paramant](https://paramant.app). It holds
the cryptographic primitives, wire format, and envelope logic  --  KEM, signatures,
AEAD, KDF, mnemonic, Merkle log, padding  --  as one small, auditable Rust library.
Every primitive is checked byte-for-byte against the production `paramant-relay`,
so the relay can adopt this core without any client-visible change.

> **Status: M0 through M6 complete, plus ParaSign Sg1 step 1.** The NAPI binding
> (`@paramant/core`) is in production: paramant-relay's ML-KEM-768 keygen runs on
> this core since 2026-05-27 (M5b). Cross-implementation byte-equivalence with the
> browser RustCrypto stack is proven (ADR-0020, ADR-0021). See
> [`BLUEPRINT.md`](BLUEPRINT.md) for the milestone history and forward plan, and
> [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for how this fits paramant-relay.

## What is here

| Layer | Module(s) | Milestone |
|---|---|---|
| Errors | `error.rs` | M1 |
| KEMs | `kem/` (ML-KEM-768, hybrid ML-KEM + ECDH P-256) | M1-M2 |
| Signatures | `sig.rs` (ML-DSA-65, SLH-DSA, Falcon) | M2 |
| AEAD | `aead.rs` (AES-256-GCM via aws-lc-rs) | M3 |
| KDFs | `kdf.rs` (Argon2id, HKDF) | M3 |
| Mnemonics | `mnemonic.rs` (BIP-0039) | M3 |
| Merkle log | `merkle.rs` (RFC 6962 + Signed Tree Head) | M4 |
| Padding | `padding.rs` (block padding) | M4 |
| Wire format | `wire.rs` (PQHB, byte-equivalent with relay) | M4 |
| Envelopes | `envelope/` (anonymous, signed) | M4 |

Plus two bindings:

| Binding | Crate | Consumer | Milestone |
|---|---|---|---|
| NAPI | `paramant-core-node` (npm `@paramant/core`) | paramant-relay (server) | M5a/M5b (in production) |
| Cross-impl validator | `cross-impl-validator` | CI gate for the browser RustCrypto stack | M6, ParaSign Sg1 |

Validated by 325 known-answer-test vectors (`tests/kat/`) and 21 Architecture
Decision Records (`docs/adrs/`).

## Audience

- **Crypto reviewers and audit firms:** ADRs, KAT vectors, and source are built
  for offline audit. Start with [`docs/architecture.md`](docs/architecture.md),
  then [`BLUEPRINT.md`](BLUEPRINT.md), then [`docs/adrs/`](docs/adrs/) and
  [`docs/threat-model.md`](docs/threat-model.md).
- **paramant-relay maintainers:** changes here may need relay coordination. See
  [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the core-relay relationship.
- **Paramant users:** see [paramant.app](https://paramant.app); this repo is below
  your concern level.
- **Self-hosters:** see
  [paramant-relay](https://github.com/Apolloccrypt/paramant-relay) instead; this is
  the crypto core that the relay uses.

## Relationship to paramant-relay

[Apolloccrypt/paramant-relay](https://github.com/Apolloccrypt/paramant-relay) is the
production HTTP server (Node.js): the `/v2/` API for SDK clients, the paramant.app
frontend, the vendored browser `crypto-wasm` binding, and the docker container
fleet (5 sector relays plus admin).

Per [ADR-0003](docs/adrs/0003-source-of-truth.md), the relay's wire format is the
source of truth and paramant-core mirrors it byte-for-byte (ADR-0014). Three wire
formats coexist by design; see
[`docs/wire-format-boundaries.md`](docs/wire-format-boundaries.md).

The migration is a strangler pattern: M5b shipped one ML-KEM-768 call site from the
JavaScript `@noble/post-quantum` library to `@paramant/core`. Later milestones move
more call sites; the end state is a relay that does HTTP, admin, and billing only,
with all crypto via paramant-core.

## Quick start

```sh
cargo build         # build the workspace
cargo test --all    # unit + KAT + property tests (325 KAT vectors)
cargo doc --open    # read the API docs
```

Requires Rust 1.95 (pinned in [`rust-toolchain.toml`](rust-toolchain.toml),
installed automatically by rustup). Benchmarks live in
[`docs/benchmarks.md`](docs/benchmarks.md).

## Documentation

- [`BLUEPRINT.md`](BLUEPRINT.md)  --  milestone history and forward plan
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)  --  cross-repo overview (core + relay)
- [`docs/architecture.md`](docs/architecture.md)  --  paramant-core internal layout
- [`docs/threat-model.md`](docs/threat-model.md)  --  assets, adversaries, boundaries
- [`docs/wire-format-v1.md`](docs/wire-format-v1.md)  --  PQHB byte-level spec (relay mirror)
- [`docs/wire-format-0x03.md`](docs/wire-format-0x03.md)  --  browser hybrid byte-level spec
- [`docs/wire-format-boundaries.md`](docs/wire-format-boundaries.md)  --  three-format coexistence
- [`docs/envelope-send.md`](docs/envelope-send.md)  --  anonymous envelope spec
- [`docs/envelope-parashare.md`](docs/envelope-parashare.md)  --  signed envelope spec
- [`docs/https-next-level-relay.md`](docs/https-next-level-relay.md)  --  relay HTTPS hardening playbook
- [`docs/benchmarks.md`](docs/benchmarks.md)  --  NAPI throughput numbers
- [`docs/doc-conventions.md`](docs/doc-conventions.md)  --  rustdoc, ADR, CHANGELOG rules
- [`docs/adrs/`](docs/adrs/)  --  21 Architecture Decision Records
- [`SECURITY.md`](SECURITY.md)  --  responsible disclosure
- [`CONTRIBUTING.md`](CONTRIBUTING.md)  --  how to contribute

Marketing and product positioning live at [paramant.app](https://paramant.app), not
in this README.

## License

[BUSL-1.1](LICENSE), converting to Apache-2.0 on 2029-01-01. Contact:
[mick@paramant.app](mailto:mick@paramant.app).
