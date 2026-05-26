# 0008. ML-DSA-65 is the default signature scheme

Datum: 2026-05-27
Status: Geaccepteerd

## Context

Paramant needs one default signature scheme for envelopes and Signed Tree Heads.
Candidates: ML-DSA-65 (FIPS 204, lattice), SLH-DSA (FIPS 205, hash-based but
large and slow), Falcon (FN-DSA, small signatures but floating-point and
constant-time hazards, not yet FIPS-final).

## Beslissing

The default is **ML-DSA-65**: FIPS 204 final, already used by `paramant-relay`,
a balanced size/speed profile, and straightforward constant-time
implementations. SLH-DSA and Falcon remain available for callers who want
hash-based conservatism or the smallest signatures, respectively.

## Consequenties

- Byte-equivalence and interop with `paramant-relay` are anchored on ML-DSA-65.
- Envelope and STH signing (M4) default to ML-DSA-65.
- The other schemes are opt-in, not removed.

## Alternatieven

- **SLH-DSA default**: rejected — kilobyte-plus signatures and slower signing;
  kept as the conservative hash-based option.
- **Falcon default**: rejected — floating-point and constant-time hazards, and
  not FIPS-final; kept for callers who specifically need small signatures.
