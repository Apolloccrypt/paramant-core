# Threat Model

*v0.1 — STRIDE-lite. One page. Revisited every tagged release.*

## Assets

1. **Secret keys** — KEM/signature secret keys and derived symmetric keys. Must
   never leave the process in plaintext, never hit logs, zeroized on drop.
2. **Plaintext** — the user data inside an envelope, before encryption / after
   decryption.
3. **Merkle log** — the append-only transparency log and its Signed Tree Heads;
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
  reproducible builds goal, SBOM — not a property of the source).
- Side channels below the cryptographic layer (CPU, power, EM).
- Endpoint malware that reads plaintext before encryption.

## Security properties the code must hold

- **Constant-time** where a timing leak would matter (AEAD tag check, password
  verification, secret comparisons) — via `subtle`. Marked per function and
  tested in `tests/constant_time.rs` (from M3).
- **Secret hygiene** — all key material wrapped in `secrecy::Secret<T>`,
  `Zeroize` on drop, never `Debug`-printed.
- **No `unsafe`** without a `// SAFETY:` comment and an ADR.
- **Byte-equivalence** with `paramant-relay` (build 2.5.0) for every primitive,
  proven by Known Answer Tests, so migration introduces no behavioural change.
