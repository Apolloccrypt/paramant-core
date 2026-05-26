# 0012. Constant-time policy

Datum: 2026-05-27
Status: Geaccepteerd

## Context

Timing side channels leak secrets when the time a function takes depends on
secret data — a tag comparison that returns early on the first mismatched byte
is a forgery oracle; a password check whose duration tracks how many bytes
matched is a hash-recovery oracle. Several paramant-core functions handle
secrets on paths where timing leakage is exploitable.

## Beslissing

The following functions MUST run in time independent of secret values:

- `aead::decrypt` — GCM tag verification
- `kdf::argon2id::verify_password` — hash comparison
- `kem::decaps` — any internal comparison (ML-KEM implicit rejection)
- `sig::*::verify` — signature verification

**Implementation.** Our own comparisons use `subtle::ConstantTimeEq`. The
underlying crates provide the constant-time guarantee for their internal
operations: `aws-lc-rs` (AEAD tag, ECDH), `argon2`, and `oqs`/liboqs (FIPS
KEM/signature primitives).

**Testing.** `tests/constant_time.rs` asserts the *structural* property, not
wall-clock timing (which is platform-dependent and flaky in CI): the comparison
examines the whole input with no data-dependent early return. Exhaustive
single-bit coverage runs through the cheap `ct_eq` primitive; `aead::decrypt`
is checked to reject a tamper at every byte position; `verify_password` is
checked to fail closed. This is documented in `docs/threat-model.md`.

## Consequenties

- Comparisons are marginally slower than `==`, in exchange for closing
  timing-based key/forgery oracles.
- We do not (and cannot portably) prove wall-clock constant-time in CI; we trust
  audited primitives for that and test the structural property ourselves. True
  wall-clock verification (e.g. `dudect`) is a possible future, out-of-CI check.

## Alternatieven

- **`PartialEq` / `==` on secrets**: rejected — short-circuits on the first
  differing byte, leaking a match prefix via timing.
- **Hand-rolled XOR-accumulate comparison**: rejected — `subtle` is audited,
  idiomatic, and resists compiler optimization back into a branch.
- **Wall-clock timing assertions in CI**: rejected — noisy and
  platform-dependent; they would flake without proving the property.
