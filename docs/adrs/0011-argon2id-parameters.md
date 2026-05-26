# 0011. Argon2id parameters

Datum: 2026-05-27
Status: Geaccepteerd

## Context

Argon2id takes three tuning parameters — memory cost `m`, time cost `t`, and
parallelism `p`. Set too low they weaken resistance to offline cracking; set too
high they make interactive password verification sluggish. The values must be
fixed in one place so every caller inherits a vetted cost rather than guessing.

## Beslissing

Use the **OWASP 2024 Password Storage Cheat Sheet** recommendation for Argon2id:

- `m = 19456` KiB (19 MiB)
- `t = 2` iterations
- `p = 1` lane
- 32-byte output, Argon2 version `0x13` (19)

These are baked into `kdf::argon2id` as constants (`M_COST_KIB`, `T_COST`,
`P_COST`, `TAG_LEN`); `hash_password` exposes no parameter knobs.

Reference:
<https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>

## KAT-bron (volgt ADR-0005)

RFC 9106 Appendix A defines exactly **one** Argon2id test vector, and at
parameters unlike ours (`m=32` KiB, `t=3`, `p=4`, with a secret and associated
data). One vector is too few to form a corpus, and it does not exercise our
`hash_password` parameters. So instead of inlining RFC vectors we deliberately
reuse the cross-implementation strategy already chosen for the KEM in
[ADR-0005](0005-kem-kat-strategy.md): a trusted independent implementation
produces the vectors and paramant-core must reproduce them byte-for-byte.

Concretely, `@noble/hashes` generates 15 Argon2id vectors at our OWASP params —
but only **after** the generator has reproduced the single RFC 9106 Appendix A
vector on that same run, so the reference is itself anchored to the RFC ground
truth before we trust it. The Rust `argon2` crate must then match those 15 tags
exactly; that byte-equality is what rules out parameter-conversion bugs (KiB vs
bytes, lanes vs parallelism). HKDF and BIP-0039 need no such workaround: HKDF is
anchored directly to RFC 5869 Appendix A (pure HMAC, no third-party library) and
BIP-0039 uses the trezor/python-mnemonic canonical vectors.

## Consequenties

- ~19 MiB and two passes per hash: sub-second on 2024-era CPUs, acceptable for
  interactive verification, costly to parallelize at attack scale.
- Higher memory than the RFC 9106 minimum, below maximum-security profiles.
- Test cost: each KAT / constant-time hash allocates 19 MiB, so password tests
  are kept to a small number of calls.

## Alternatieven

- **RFC 9106 minimum (`m = 8` MiB)**: rejected — too low for 2024 attack budgets.
- **Argon2d / Argon2i**: rejected — Argon2id is the recommended hybrid for
  password hashing (Argon2d alone is side-channel-prone, Argon2i weaker against
  GPUs).
- **Higher `t` at lower `m`**: rejected — memory hardness, not iteration count,
  is what frustrates parallel cracking hardware.
- **Configurable parameters**: rejected — one vetted cost beats per-caller
  guesses; revisit by bumping the constants (a versioned change) as hardware
  moves.
- **Inline-only RFC 9106 vectors (no `@noble`)**: rejected — Appendix A supplies
  a single Argon2id vector, at non-OWASP parameters; too few for a corpus. We
  keep it as the ground-truth anchor and follow the ADR-0005 cross-impl pattern
  for volume (see "KAT-bron" above).
