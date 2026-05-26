# 0001. Rust edition and MSRV

Datum: 2026-05-26
Status: Geaccepteerd

## Context

paramant-core needs a stable, reproducible toolchain. The crypto dependencies
(`oqs`, `aws-lc-rs`, `argon2`) build on recent-but-not-bleeding-edge Rust. We
want one pinned toolchain so local builds, CI, and audit reproductions match.

## Beslissing

- **Edition 2021.**
- **MSRV 1.80**, pinned in `rust-toolchain.toml` (`channel = "1.80"`, components
  `rustfmt` + `clippy`).
- Review the MSRV roughly monthly; bump only with a reason (a dependency requires
  it, or a needed language feature), recorded in `CHANGELOG.md`.

## Consequenties

- CI and local builds use the same compiler; "works on my machine" gaps close.
- Edition 2024 and post-1.80 features are off the table until a deliberate bump.
- Consumers must build with 1.80+.

## Alternatieven

- **`channel = "stable"`** (floating): rejected — non-reproducible, silent
  breakage when a new stable changes lint behaviour under `-D warnings`.
- **Edition 2024**: rejected for now — newer than the conservative-toolchain
  principle (blueprint §1.C) wants for security code.
