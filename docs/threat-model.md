# Threat Model

*v0.1  --  STRIDE-lite. One page. Revisited every tagged release.*

## Assets

1. **Secret keys**  --  KEM/signature secret keys and derived symmetric keys. Must
   never leave the process in plaintext, never hit logs, zeroized on drop.
2. **Plaintext**  --  the user data inside an envelope, before encryption / after
   decryption.
3. **Merkle log**  --  the append-only transparency log and its Signed Tree Heads;
   integrity and non-equivocation matter even though it is public.

## Adversaries

| Adversary | Capability | What we defend |
|---|---|---|
| **Passive network** | Reads all ciphertext in transit | Confidentiality via ML-KEM-768 hybrid + AES-256-GCM; no plaintext or key on the wire |
| **Active network** | Modifies, replays, reorders | Integrity/authenticity via AEAD tag + ML-DSA-65 signatures; wire format rejects tampering |
| **Malicious operator** | Controls the relay host and storage | Relay sees only ciphertext + opaque metadata; envelope keys are out-of-band (URL fragment / pairing), never at the relay |
| **Compromised endpoint** | Owns one peer's device | Bounded blast radius: per-message keys, forward secrecy goals, Merkle log exposes equivocation |

## Out of scope

- A compromised **build host** or a malicious dependency injected before
  compilation (mitigated operationally: pinned deps, `cargo audit` / `cargo deny`,
  reproducible builds goal, SBOM  --  not a property of the source).
- Side channels below the cryptographic layer (CPU, power, EM).
- Endpoint malware that reads plaintext before encryption.

## Security properties the code must hold

- **Constant-time** where a timing leak would matter (AEAD tag check, password
  verification, secret comparisons)  --  via `subtle`. Marked per function and
  tested in `tests/constant_time.rs` (from M3).
- **Secret hygiene**  --  all key material wrapped in `zeroize::Zeroizing<T>`
  (zeroized on drop, never `Debug`-printed). Secret handling lives inline in
  each primitive's module (`kem`, `sig`, `kdf`, `mnemonic`); there is no
  separate `secret.rs`  --  we wrap only where it earns its keep (principle D,
  [ADR-0004](adrs/0004-code-minimization.md)).
- **No `unsafe`** without a `// SAFETY:` comment and an ADR.
- **Byte-equivalence** with `paramant-relay` (build 2.5.0) for every primitive,
  proven by Known Answer Tests, so migration introduces no behavioural change.

## Constant-time requirements

Timing side channels leak secrets when comparison or branching depends on
secret data. These functions MUST run in time independent of secret values:

| Function | Why | Mechanism |
|---|---|---|
| `aead::decrypt` (tag check) | A forgery oracle leaks how many tag bytes matched | AWS-LC verifies the GCM tag in constant time |
| `kdf::argon2id::verify_password` | A timing oracle recovers the stored hash | `subtle::ConstantTimeEq` over the 32-byte tag |
| `kem::decaps` / its internal checks | ML-KEM implicit rejection must not branch on the secret | liboqs (FIPS 203) constant-time decaps |
| `sig::*::verify` | Timing on signature checks can aid forgery | liboqs verify; no early-out on secret data |

**How we test it.** Wall-clock measurement is platform-dependent and flaky, so
`tests/constant_time.rs` asserts the *structural* property instead: the
comparison examines the whole input with no data-dependent early return  --  every
single-bit tamper of an AEAD ciphertext and of an Argon2id tag is rejected, and
the comparison primitive is `subtle::ConstantTimeEq`. We rely on the underlying
crates (`aws-lc-rs`, `argon2`, `oqs`) for the constant-time guarantee inside
their own primitives. See [ADR-0012](adrs/0012-constant-time-policy.md).
