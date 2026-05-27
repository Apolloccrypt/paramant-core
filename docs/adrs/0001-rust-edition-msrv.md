# 0001. Rust edition and MSRV

Datum: 2026-05-26
Status: Geaccepteerd (MSRV herzien 1.80  ->  1.95 op dezelfde dag, zie Consequenties)

## Context

paramant-core needs a stable, reproducible toolchain. The crypto dependencies
(`oqs`, `aws-lc-rs`, `argon2`) build on recent Rust. We want one pinned
toolchain so local builds, CI, and audit reproductions match exactly.

## Beslissing

- **Edition 2021.**
- **MSRV 1.95**, pinned exactly in `rust-toolchain.toml` (`channel = "1.95.0"`,
  components `rustfmt` + `clippy`). Exact patch pin for audit reproducibility.
- Review the MSRV roughly monthly; bump only with a reason (a dependency requires
  it, or a needed language feature), recorded in `CHANGELOG.md`.

## Consequenties

- CI and local builds use the same compiler; "works on my machine" gaps close.
- Consumers must build with 1.95+.
- **MSRV history:** M0 initially pinned **1.80** (conservative). At M1 this was
  bumped to **1.95** (latest stable, 2026-04-14): `oqs` 0.10  --  mandated for the
  post-quantum primitives by [ADR-0002](0002-oqs-vs-pure-rust.md) and required at
  M1 for seed-based (`derand`) keygen so KAT vectors are byte-equivalent with
  paramant-relay  --  pulls a transitive dependency that needs **edition 2024**
  (rustc >= 1.85). 1.80 and oqs are therefore mutually exclusive. We chose latest
  stable over the bare 1.85 floor to absorb ecosystem MSRV-creep once, not
  repeatedly.

## Alternatieven

- **`channel = "stable"`** (floating): rejected  --  non-reproducible; a new stable
  could change lint behaviour under `-D warnings` silently.
- **Stay on 1.80, pin transitive deps down**: rejected  --  fragile, fights the
  ecosystem, recurring maintenance, and risks losing oqs 0.10's `derand` API.
- **Bump only to 1.85** (the edition-2024 floor): rejected  --  would likely force
  another bump soon; latest-stable is less churn for a multi-year project.
