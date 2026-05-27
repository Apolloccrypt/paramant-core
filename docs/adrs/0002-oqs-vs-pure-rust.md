# 0002. Post-quantum crypto via oqs, not pure-Rust crates

Datum: 2026-05-26
Status: Geaccepteerd

## Context

The post-quantum primitives (ML-KEM-768, ML-DSA-65, SLH-DSA, Falcon) can come
from the `oqs` crate (Rust bindings to liboqs, the Open Quantum Safe C library)
or from pure-Rust crates (`pqcrypto-mlkem`, `pqcrypto-mldsa`, RustCrypto's
emerging implementations). This is security-critical code headed for external
audit.

## Beslissing

Use **`oqs` (liboqs C bindings) for M1-M7.** Re-evaluate migrating to pure-Rust
crates at **M9** (audit-prep), when those crates have NIST-final implementations
and their own validation story.

## Consequenties

- We track the upstream reference implementation; NIST's validation effort
  targets the underlying C code.
- A C dependency enters the build (liboqs); the build needs a C toolchain +
  CMake. The FFI boundary is a fuzzing target (blueprint Sec.10).
- An `oqs` breaking change is a known risk; this ADR is the migration anchor.

## Alternatieven

- **pure-Rust now**: rejected for M1-M7  --  the crates are not yet NIST-final and
  carry less validation weight for an audit. Revisited at M9.
- **Hand-rolled primitives**: rejected outright  --  never roll your own crypto;
  principle D says use vetted crates, not reimplement.
