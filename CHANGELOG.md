# Changelog

All notable changes to paramant-core are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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

## [0.1.0] - TBD

- Initial milestone series (M1–M4) lands the cryptographic core.
