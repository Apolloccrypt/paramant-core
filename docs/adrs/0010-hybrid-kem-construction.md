# 0010. Hybrid KEM combiner construction

Datum: 2026-05-27
Status: Geaccepteerd

## Context

A single post-quantum KEM (ML-KEM-768) is young; a single classical KEM (ECDH
P-256) falls to a cryptographically relevant quantum computer. A hybrid combines
both so the shared secret stays secure as long as **either** primitive holds  -- 
the conservative choice while PQ confidence matures.

## Beslissing

Hybrid = **ML-KEM-768  XOR  ECDH P-256**, combined per
`draft-ietf-tls-hybrid-design`:

```text
ss = HKDF-Extract( salt = ml_kem_ct || ecdh_ephemeral_pub,
                   ikm  = ml_kem_ss || ecdh_ss )        // HMAC-SHA-256, 32 bytes
```

Wire format: public key `ml_kem_pk || ecdh_pub` (SEC1 uncompressed point, 65 B);
ciphertext `ml_kem_ct || ecdh_ephemeral_pub`. ECDH comes from AWS-LC
(`aws-lc-rs`, FIPS-validated), ML-KEM from liboqs, the combiner from `hkdf` +
`sha2`. No `unsafe`. Binding both ciphertexts into the salt and both shared
secrets into the IKM gives the standard both-ciphertexts/dual-input robustness.

## Consequenties

- The shared secret is secure if ML-KEM **or** ECDH holds.
- Larger artifacts: public key 1249 B, ciphertext 1153 B, shared secret 32 B.
- ECDH ephemeral keygen is randomized (aws-lc-rs exposes no deterministic
  variant), so no deterministic hybrid KAT is generated in M2. Confidence rests
  on the round-trip + property tests and on the ML-KEM half already being KAT
  byte-equivalent with `paramant-relay`. Full cross-implementation hybrid KAT
  and live `@noble` interop arrive with the NAPI bridge at M5.

## Alternatieven

- **Concatenation only** (`ss = ml_kem_ss || ecdh_ss`): rejected  --  not a uniform
  32-byte secret, weaker binding to the transcript.
- **X-Wing** (`draft-connolly-cfrg-xwing`, ML-KEM-768 + X25519): strong, but
  Paramant standardized on ECDH P-256 (FIPS, AWS-LC). Revisit at M9.
- **Single KEM**: rejected  --  defeats the purpose of hybrid resilience.
