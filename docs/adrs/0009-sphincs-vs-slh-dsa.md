# 0009. SPHINCS+ (liboqs) vs FIPS 205 SLH-DSA

Datum: 2026-05-27
Status: Geaccepteerd

## Context

M2 intended to ship SLH-DSA (FIPS 205) alongside ML-DSA-65 and Falcon, with
cross-implementation Known-Answer Tests against `@noble/post-quantum` (which
implements FIPS 205 SLH-DSA). The KAT immediately failed: liboqs 0.12 exposes
the **round-3 SPHINCS+ "simple"** instantiations (`SphincsSha2128fSimple`, …),
not FIPS 205 SLH-DSA. The two differ in message processing (FIPS 205 adds a
domain-separation prefix), so signatures do not cross-verify.

## Beslissing

Ship the liboqs primitive as `sig::slh_dsa` (SPHINCS+-SHA2-128f-simple),
**round-trip tested within liboqs only**. Make no cross-implementation or
FIPS 205 byte-equivalence claim, and document the caveat on the module. The
KEM/ML-DSA strategy (verify @noble vectors) does not apply here.

`paramant-relay` does not use SLH-DSA, so there is no relay-parity requirement.

## Consequenties

- `sig::slh_dsa` is available and self-consistent (sign↔verify), but is round-3
  SPHINCS+, not FIPS 205, until liboqs exposes SLH-DSA.
- No SLH-DSA KAT vectors in `tests/kat/`; coverage is the round-trip unit test.
- When liboqs ships FIPS 205 SLH-DSA, switch the backing `Algorithm`, add the
  @noble cross-impl KAT, and update this ADR.

## Alternatieven

- **Implement FIPS 205 message-prefix on top of SPHINCS+**: rejected — hand-rolling
  the FIPS wrapper around a round-3 primitive is exactly the "don't reinvent
  crypto" trap (ADR-0004); wait for liboqs.
- **Drop SPHINCS+ entirely until FIPS 205 lands**: viable, but a working,
  round-trip-tested hash-based option has value; kept with a clear caveat.
