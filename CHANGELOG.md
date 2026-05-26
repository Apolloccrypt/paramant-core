# Changelog

All notable changes to paramant-core are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- M1 (First Light): `kem` module — ML-KEM-768 (FIPS 203) `keygen`/`encaps`/`decaps`
  via liboqs (`oqs`), with zeroizing secret types and no `unsafe`; `error` module
  (`CoreError`/`CoreResult`).
- ML-KEM-768 KAT: 30 deterministic vectors from `@noble/post-quantum`
  (`scripts/extract-kat.mjs` → `tests/kat/ml-kem-768.json`); tests prove `decaps`
  byte-equivalence with paramant-relay, interop on @noble keypairs, and a
  512-case round-trip property. KAT strategy in
  [ADR-0005](docs/adrs/0005-kem-kat-strategy.md).
- M0 bootstrap: Cargo workspace with the `paramant-core` crate (empty shell),
  pinned dependency catalogue, and `rust-toolchain.toml` (Rust 1.80).
- Documentation set: `README`, `SECURITY`, `CONTRIBUTING`, `LICENSE` (BUSL-1.1),
  `docs/architecture.md`, `docs/threat-model.md`, `docs/doc-conventions.md`.
- Architecture Decision Records 0001–0004 (edition/MSRV, oqs-vs-pure-rust,
  source-of-truth, code-minimization).
- CI (`cargo check/test/clippy -D warnings/fmt --check`, `cargo audit`,
  `cargo deny`) and weekly Dependabot for Cargo.

### Changed
- Repository restructured from the March 2026 single-crate prototype to the
  blueprint v3.1 workspace layout. The prototype is preserved at the
  `archive/march-2026-prototype` tag.
- MSRV bumped 1.80 → **1.95** (pinned `1.95.0`). `oqs` 0.10, needed at M1 for
  seed-based keygen, pulls an edition-2024 dependency requiring rustc ≥ 1.85; we
  pinned latest stable. See [ADR-0001](docs/adrs/0001-rust-edition-msrv.md).
- Dependabot ignores cargo major bumps (deliberate, manual review per ADR-0004).

## [0.1.0] - TBD

- Initial milestone series (M1–M4) lands the cryptographic core.
