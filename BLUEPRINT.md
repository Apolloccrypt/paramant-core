# PARAMANT-CORE BLUEPRINT
## Milestone history and forward plan

*v3.3  .  2026-05-27  .  Mick Beer  .  paramant.app*

This blueprint captures what has shipped (M0 through M6 plus ParaSign Sg1 step 1)
and what comes next (M5b production-soak, ParaSign Sg1 step 2+, M7 production-soak,
M8+ audit preparation). It replaces blueprint v3.1 (Dutch, pre-implementation
placeholders).

---

## 0. Status today (2026-05-27)

Code: paramant-core M0-M6 complete plus ParaSign Sg1 step 1 (cross-impl ML-DSA-65).
The `paramant-core-node` NAPI binding is live in production (M5b deployed
2026-05-27 to Hetzner Frankfurt). 21 ADRs, 310 KAT vectors, CI green.

Production: paramant-relay live at 116.203.86.81, 5 sector relays plus admin,
ML-KEM-768 keygen via `@paramant/core`, 7-day soak-acceptance window started.

---

## 1. Design principles

- **A. GitHub is source of truth.** CI builds, no secrets in code.
- **B. Apple-simple.** README under 200 lines, single build command.
- **C. Cutting-edge in WHAT (PQ crypto), conservative in HOW** (Cargo, oqs,
  aws-lc-rs, RustCrypto).
- **D. Code minimization** (ADR-0004). One file per module unless it grows past a
  few hundred lines; a small, deliberate dependency set.
- **E. Working-tree discipline.** Explicit paths in `git add`, never `-A`.

---

## 2. Repository roles

| Repo | Role | Stack | License |
|---|---|---|---|
| Apolloccrypt/paramant-core | Crypto primitives, wire format, envelopes, bindings | Rust | BUSL-1.1 |
| Apolloccrypt/paramant-relay | HTTP server, admin, billing, frontend, browser crypto-wasm | Node.js | BUSL-1.1 |

Strangler pattern: the relay migrates crypto call sites to `@paramant/core`
milestone by milestone. End state: the relay is HTTP, admin, routing, and billing
only, with all crypto via paramant-core.

---

## 3. Milestones shipped (M0-M6)

### M0  Bootstrap
Workspace, docs scaffolding, ADRs 0001-0004, CI.

### M1  First Light
ML-KEM-768 via oqs (liboqs). 50 KAT vectors validated by decapsulation parity
against the `@noble/post-quantum` reference (ADR-0005, forced by oqs lacking
seeded keygen).

### M2  PQ Complete
ML-DSA-65, SLH-DSA, Falcon signatures; hybrid ML-KEM-768 + ECDH P-256 per
draft-ietf-tls-hybrid-design. 50 more KAT vectors. ADRs 0007-0010.

### M3  Symmetric Layer
AES-256-GCM (aws-lc-rs), Argon2id (OWASP 2024 parameters), HKDF (RFC 5869),
BIP-0039 mnemonics. Constant-time discipline (ADR-0012), Argon2id KAT source policy
(ADR-0011).

### M4  Protocol Layer
RFC 6962 Merkle log plus Signed Tree Head, block padding, PQHB wire format
(byte-equivalent with the relay, ADR-0014), two envelope modes (anonymous = send,
signed = parashare). Direct relay-source analysis corrected earlier
wire-format assumptions. ADRs 0013-0017.

### M5a  NAPI Bridge
`paramant-core-node` crate, `#[napi]` wrappers, Linux x64-glibc and x64-musl
builds, interop checks against relay-anchored KAT vectors. NAPI throughput is
documented in `docs/benchmarks.md` (ML-KEM-768 keygen ~78.5k ops/sec, decaps
~94.4k ops/sec, AES-256-GCM 1 KiB encrypt ~425k ops/sec). ADRs 0018-0019.

### M5b  Relay Integration
PR #33 swapped the relay's ML-KEM-768 keygen from `@noble` to `@paramant/core`. A
multi-stage Dockerfile builds the binding in-image for musl, pinned by
`PARAMANT_CORE_COMMIT`. Deployed to production 2026-05-27; all 5 sector relays plus
admin healthy; soak monitoring active. (PR #34, ParaSign Sg1 step 2, extends the
browser crypto-wasm with ML-DSA exports and is open, awaiting the M5b soak signal.)

### M6  Browser-Relay Consolidation
Documented the three-format coexistence (`docs/wire-format-boundaries.md`). The
`cross-impl-validator` crate proves byte-equivalence of ML-KEM, AES-GCM, HKDF, and
ML-DSA-65 between the browser RustCrypto crates and the oqs/aws-lc-rs server stack,
against the same `@noble`-anchored KAT vectors. No fresh wasm binding is built:
paramant-core's C dependencies cannot target wasm32 (ADR-0020). ADR-0021 records the
ML-DSA cross-impl validation.

---

## 4. ParaSign product line (parallel track)

Started 2026-05-27. Reuses paramant-core's ML-DSA-65 primitives via the browser
crypto-wasm binding. Specs in `~/paramant-sign-spec` (ADRs Sg0-1 through Sg0-4):

- **ADR-1:** ML-DSA maturity and browser-side signing (Option B).
- **ADR-2:** `.psign` container format (PSIG magic, PQHB-style framing).
- **ADR-3:** Mnemonic-only key management for the MVP.
- **ADR-4:** Anonymous-first signing with an optional account-binding badge.

Milestones:

- **Sg0:** ADRs (done).
- **Sg1 step 1:** cross-impl ML-DSA-65 KAT proven (done, ADR-0021).
- **Sg1 step 2:** ML-DSA exports in crypto-wasm + wasm rebuild + SHA pin update
  (PR #34, open).
- **Sg1 step 3:** `/sign` and `/verify` frontend routes plus `.psign` encoder.
- **Sg2:** multi-signer, PAdES-PQ, key-at-rest.
- **Sg3:** eIDAS qualified-signature track.

---

## 5. Forward plan (M5b soak through M14)

### M5b production-soak (active, 2026-05-27 to ~2026-06-03)
7-day clean signal required. Monitoring via a systemd timer on 116.203.86.81:
10-minute samples of `/health`, `/v2/capabilities` (ML-KEM-768 loaded), per-container
health, and error-level docker logs. Acceptance: zero DOWN events, zero
ml-kem-768=false events, empty errors log.

### M7  Sector full traffic (target ~2026-06 to ~2026-08)
60-day production soak expanding `@paramant/core` from keygen to encaps, decaps,
AES-GCM, and signing on one sector's full traffic. Goal: confidence for general
availability.

### M8  Migration completion
Migrate the remaining relay crypto call sites. After M8 the relay's crypto layer is
a thin shim over `@paramant/core`.

### M9  External audit
Independent crypto review plus penetration test. Findings documented under
`docs/`.

### M10  Audit remediation
Address findings; critical and high severity fixed before M11.

### M11  General Availability
Paramant 3.0 launch, ParaSign GA, production pricing tiers.

### M12  IETF drafts
Submit Internet-Drafts for the PQHB wire format and the hybrid construction.

### M13  Standardization
European standardization bodies for PQ envelope formats; eIDAS qualified-signature
track for ParaSign.

### M14  Production-grade SLA
Enterprise contracts, dedicated relay options.

(Dates beyond M7 are directional, not commitments.)

---

## 6. Out of scope (deliberate omissions)

- **A fresh `paramant-core-wasm` binding:** not viable; paramant-core has C
  dependencies and cannot target wasm32 (ADR-0020). Browser crypto lives in
  `paramant-relay/crypto-wasm` (RustCrypto), governed by cross-impl KAT here.
- **Rewriting paramant-relay in Rust:** not planned. The Node.js HTTP layer is fit
  for purpose; only the crypto layer migrates.
- **Hardware security modules** (YubiKey, smartcard PQ): tracked as ParaSign Sg3+
  future work.

---

## 7. Open questions

- Timing of an independent audit of the `ml-dsa` RustCrypto crate (ParaSign ships
  as beta until then).
- eIDAS qualified-signature path depends on the QTSP-accreditation process.
- Paramant BV incorporation (gates the US enterprise track).
- LICENSE additional-use-grant review.

---

## License

See [LICENSE](LICENSE). BUSL-1.1, converts to Apache-2.0 on 2029-01-01.
