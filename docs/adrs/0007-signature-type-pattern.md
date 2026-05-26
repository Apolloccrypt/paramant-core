# 0007. Per-algorithm signature types

Datum: 2026-05-27
Status: Geaccepteerd

## Context

paramant-core offers three signature schemes (ML-DSA-65, SLH-DSA, Falcon) with
different key and signature sizes and different security properties. Mixing keys
across schemes — passing an ML-DSA key to Falcon verify — must be impossible.

## Beslissing

Each algorithm is its own module (`sig::ml_dsa_65`, later `sig::slh_dsa`,
`sig::falcon_512`) with its own `PublicKey` / `SecretKey` / `Signature`
newtypes. No generic `SigAlgorithm` enum and no trait across schemes. A small
private helper (`raw_keygen` / `raw_sign` / `raw_verify` over an oqs
`Algorithm`) removes duplication without exposing a generic surface.

## Consequenties

- The type system prevents cross-scheme key confusion at compile time.
- Bounded per-module repetition (three small newtypes each); the shared helper
  carries the actual liboqs logic once.
- Adding a scheme is one new module; existing modules are untouched.

## Alternatieven

- **Generic over a `SigAlgorithm` enum or trait**: rejected — permits runtime
  algorithm confusion, adds abstraction for its own sake (ADR-0004), and buys
  nothing the modules don't already give.
