# PARAMANT-CORE BLUEPRINT
## Volledige koers van project naar GOEDE eerste beta. CLI-executable. Minimal.

*v3.1 . 26 mei 2026 . Mick Beer . paramant.app*

---

## 0. STATUS NU

Repo bestaat: `github.com/Apolloccrypt/paramant-core`. Out of date. Claude CLI brengt het naar deze blueprint, niet andersom.

paramant-relay blijft de bestaande Node.js productie-codebase (build 2.5.0). Bij elke mijlpaal krimpt paramant-relay een stukje en groeit paramant-core. Eindstaat na M7: paramant-relay is HTTP + admin + routing + Stripe, alle crypto komt via `@paramant/core`.

| Repo | Rol | Taal |
|---|---|---|
| `Apolloccrypt/paramant-relay` | HTTP, admin, routing, billing | Node.js |
| `Apolloccrypt/paramant-core` | Crypto-primitieven, wire format, envelopes | Rust |

Geen rewrite. Geen tijdsdruk. Mijlpalen knallen wanneer in flow.

---

## 1. VIER ONTWERP-PRINCIPES

**A. GitHub is source of truth.** Server pulled vanuit GitHub via CI. Geen secrets in code, ooit. Alle env-waarden in GitHub Actions secrets, Hetzner secrets, of `.env` files in `.gitignore`. Cryptocode heeft van nature geen secrets, dus dit kan vanaf commit 1.

**B. Apple-simpel.** Een repo. README <= 200 regels. Een build-command (`cargo build`). Een test-command (`cargo test`). Wie de repo opent moet binnen 60 seconden begrijpen wat het is.

**C. Vooruitstrevend in WAT, conservatief in WAARMEE.** Bleeding-edge crypto (NIST PQ suite). Gevestigde toolchain (Cargo, GitHub Actions, oqs, aws-lc-rs). Geen experimentele build-systems, geen pre-1.0 deps voor security-paden.

**D. Code-minimalisatie. Maximaal effect met minimaal oppervlak.**

Less code is less audit surface, less bugs, less cognitive load. Concreet:
- Een bestand per module tenzij > 300 regels rechtvaardigen splitsen
- Geen traits zonder 2+ implementaties
- Geen generics zonder duidelijke reden
- Geen abstraction layers die zichzelf niet terugverdienen
- Crates voor crypto-primitieven, niet zelf implementeren
- Re-export waar wrappen niets toevoegt
- Functies boven builders waar dat past
- 2 crates bij M0, geen 6. Crates erbij wanneer ze NODIG zijn

**Anti-patterns die we niet doen:**
- Geen `<T: Trait + Send + Sync + 'static>` als concrete types voldoen
- Geen macros die magie verbergen
- Geen helper-helper-helper modules
- Geen "future-proofing" voor scenarios die we niet kunnen benoemen
- Geen wrapper-types voor types die al goed zijn (alleen voor security: Secret<T>)

---

## 2. ARCHITECTUUR

```
paramant-core/
+-- Cargo.toml                       # workspace root
+-- README.md                        # <= 200 regels
+-- SECURITY.md
+-- CONTRIBUTING.md
+-- LICENSE                          # BUSL-1.1  ->  Apache 2.0 op 2029-01-01
+-- CHANGELOG.md
+-- rust-toolchain.toml              # pin Rust 1.80+
+-- crates/
|   +-- paramant-core/               # core lib
|   +-- paramant-core-node/          # NAPI-RS binding (toegevoegd bij M5)
+-- tests/
|   +-- kat/                         # Known Answer Tests, JSON
|   +-- fuzz/                        # cargo-fuzz targets
+-- scripts/
|   +-- extract-kat.js               # genereert KAT-vectors uit paramant-relay
+-- docs/
|   +-- architecture.md
|   +-- threat-model.md
|   +-- wire-format-v1.md
|   +-- doc-conventions.md
|   +-- adrs/
+-- .github/workflows/
|   +-- ci.yml
|   +-- dependabot.yml
+-- .gitignore
+-- BLUEPRINT.md                     # dit document
```

Crates die later toegevoegd worden, een per relevante mijlpaal:

| Mijlpaal | Crate toegevoegd | Reden |
|---|---|---|
| M0 | `paramant-core` | core lib |
| M5 | `paramant-core-node` | NAPI binding voor paramant-relay |
| M6 | `paramant-core-wasm` | browser-WASM voor paramant.app/send |
| M11+ | `paramant-core-py` | Python SDK (alleen wanneer nodig) |
| M11+ | `paramant-core-c` | C ABI (alleen wanneer nodig voor Go/mobile/OT) |
| M11+ | `paramant-cli` | standalone binary (alleen wanneer nodig) |

Niet allemaal vanaf M0 aanmaken. Wachten tot de mijlpaal die het rechtvaardigt.

---

## 3. MODULES IN paramant-core

Plat. Een bestand per concept. Splitsen alleen bij > 300 regels.

```
crates/paramant-core/src/
+-- lib.rs                           # prelude + re-exports (<= 50 regels)
+-- error.rs                         # CoreError, CoreResult (thiserror)
+-- secret.rs                        # Secret<T> wrapper helpers
+-- kem.rs                           # ML-KEM-768 + hybrid (ECDH P-256)
+-- sig.rs                           # ML-DSA-65 + SLH-DSA + Falcon
+-- aead.rs                          # AES-256-GCM
+-- kdf.rs                           # Argon2id + HKDF
+-- mnemonic.rs                      # BIP-0039 12-word
+-- merkle.rs                        # tree + Signed Tree Head
+-- padding.rs                       # 4/64/512 KB + 5 MB blokken
+-- envelope.rs                      # Send + ParaShare + ParaDrop modes
+-- wire.rs                          # wire format v1 + TLV
```

12 bestanden. Geschatte totaal: <= 2000 regels Rust voor de volledige core. Als een module groeit boven 300 regels, dan splitsen (kem.rs  ->  kem/mod.rs + kem/hybrid.rs), niet eerder.

Per pub item: rustdoc met voorbeeld. Geen exceptions.

---

## 4. DEPENDENCIES

Strikt minimaal. Gepind. Geen wildcards. Iedere dep verantwoord in een korte ADR.

```toml
[workspace.dependencies]
# PQ crypto via liboqs (NIST FIPS 203/204/205/206)
oqs            = "0.10"

# Classical crypto (FIPS-validated AWS-LC)
aws-lc-rs      = "1.13"

# KDF + hashing
argon2         = "0.5"
hkdf           = "0.12"
sha2           = "0.10"

# Mnemonic
bip39          = "2.0"

# Memory safety
zeroize        = { version = "1.8", features = ["derive"] }
secrecy        = { version = "0.10", features = ["serde"] }
subtle         = "2.6"

# Serialization (compact, no derive macros where not needed)
serde          = { version = "1.0", features = ["derive"] }
serde_json     = "1.0"
hex            = "0.4"

# Errors
thiserror      = "1.0"

# Testing only
proptest       = "1.5"
criterion      = "0.5"
```

12 dependencies, plus their transitive trees. Iedere dep heeft een doel dat niet door bestaande deps kan worden gedaan.

Niet toegevoegd vanaf M0:
- Geen `tokio` (geen async in core, sync is sneller en eenvoudiger)
- Geen `anyhow` (thiserror is genoeg voor library code)
- Geen `tracing` (logging is consumer's verantwoordelijkheid)
- Geen `clap` (alleen in paramant-cli later)
- Geen `rayon` (parallellisme is consumer's keuze)

ADR-002 documenteert: `oqs` voor M1-M7. Migratie naar `pqcrypto-*` evalueren bij M9.

---

## 5. DOCUMENTATIE-DISCIPLINE

**Per commit:**
- Rustdoc op elke `pub` item, met voorbeeld
- `cargo doc --no-deps` rendert zonder warnings
- CHANGELOG.md bijgewerkt onder `## [Unreleased]`

**Per architecturele beslissing:**
- ADR in `docs/adrs/NNNN-titel.md`

**Per tagged release:**
- Threat model herzien
- CHANGELOG-entries verplaatst naar release-sectie
- Signed Git tag via GPG

**ADR-template (kort):**

```markdown
# NNNN. Titel

Datum: YYYY-MM-DD
Status: Voorgesteld | Geaccepteerd | Vervangen door NNNN

## Context
Wat vereiste de beslissing?

## Beslissing
Wat hebben we gekozen?

## Consequenties
Welke opties zijn afgesloten? Welke openen?

## Alternatieven
Wat hebben we niet gekozen, en waarom niet?
```

**README-structuur (<= 200 regels):**
1. Wat is paramant-core (3 zinnen)
2. Modules (lijst)
3. Quick start (3 commands)
4. Compile-targets (tabel)
5. Documentatie (links)
6. Licentie + contact

Geen marketing-paragrafen. Geen feature-walls. Wie wil weten waarom Paramant relevant is leest paramant.app/vs.

---

## 6. MIJLPALEN

| Mijlpaal | Wat | Status na voltooiing |
|---|---|---|
| **M0** | Bootstrap | Repo gesynchroniseerd met blueprint, CI groen, 2 crates compileren, docs in place |
| **M1** | First Light | ML-KEM-768 werkt, 30 KAT-vectors byte-equivalent met paramant-relay |
| **M2** | PQ Complete | KEM + alle SIG primitieven, 100+ KAT-vectors |
| **M3** | Symmetric Layer | AEAD + KDF + mnemonic, constant-time verified |
| **M4** | Protocol Layer | Merkle + padding + envelope + wire v1, end-to-end werkt |
| **M5** | Bridge | paramant-core-node toegevoegd, een paramant-relay endpoint draait erop |
| **M6** | Surface | paramant-core-wasm toegevoegd, paramant.app/send draait op WASM |
| **M7** | **GOEDE EERSTE BETA** | Een sector-relay (IoT) draait 60+ dagen op paramant-core, 0 regressies |
| M8 | External Review | 3 reviewers, 0 kritieke findings, blog post live |
| M9 | Audit Prepared | Audit-pakket compleet, firma begonnen |
| M10 | Audited | Rapport publiek, findings geremedieerd |
| M11 | GA Release | v1.0.0 op crates.io + npm, persrelease |
| M12 | Specification | Wire format v1 spec + CTS publiek |
| M13 | Second Implementation | Go-implementatie passes CTS |
| M14 | Standardized | IETF/ETSI draft geaccepteerd |

Focus deze blueprint: M0 tot M7. Vanaf M8 lichter.

---

## 7. PER-MIJLPAAL CLAUDE CODE PROMPTS

### M0  --  SYNC REPO MET BLUEPRINT

```
Read BLUEPRINT.md in full.

State: paramant-core repo on GitHub already exists at 
github.com/Apolloccrypt/paramant-core but is out of date.

Task: bring the repo into conformance with BLUEPRINT.md. Code-minimization is
principle D: minimize lines, files, crates, deps. Less is more.

Steps:

1. Reconcile workspace structure:
   - Cargo workspace with ONLY crates/paramant-core (lib) for now
   - Empty stubs for paramant-core-node will be added at M5, not now
   - rust-toolchain.toml pinning 1.80+
   - .gitignore covering target/, *.swp, .DS_Store, .env, .env.*

2. Write or update docs (each <= stated length):
   - README.md: <= 200 lines, follows blueprint Sec.5 structure
   - SECURITY.md: responsible disclosure, contact privacy@paramant.app
   - CONTRIBUTING.md: conventional commits, signed commits, rustdoc requirement, 
     no unsafe without ADR
   - LICENSE: BUSL-1.1 full text, Change Date 2029-01-01, Change License Apache 2.0
   - CHANGELOG.md: Keep a Changelog format
   - docs/architecture.md: mirrors blueprint Sec.2-4, <= 2 pages
   - docs/threat-model.md: v0.1, STRIDE-lite, <= 1 page. Assets: secret keys, 
     plaintext, merkle log. Adversaries: passive net, active net, malicious 
     operator, compromised endpoint
   - docs/doc-conventions.md: rustdoc style + ADR template + CHANGELOG rules
   - docs/adrs/0001-rust-edition-msrv.md: Rust 2021, MSRV 1.80
   - docs/adrs/0002-oqs-vs-pure-rust.md: oqs M1-M7, evaluate pqcrypto-* at M9
   - docs/adrs/0003-source-of-truth.md: GitHub is source of truth, no secrets 
     in repo, server pulls via CI
   - docs/adrs/0004-code-minimization.md: principle D from blueprint, with 
     concrete anti-patterns

3. CI workflow .github/workflows/ci.yml:
   - cargo check
   - cargo test
   - cargo clippy -- -D warnings
   - cargo fmt -- --check
   - cargo audit
   - cargo deny check (if cargo-deny.toml exists)
   - Run on stable, push and PR triggers

4. dependabot config .github/workflows/dependabot.yml:
   - Weekly cargo updates

5. Cargo.toml workspace + crates/paramant-core/Cargo.toml with minimum deps 
   needed (thiserror, secrecy, zeroize). NO crypto deps yet, M1 adds those.

6. Empty src/lib.rs in paramant-core crate with just:
   //! Paramant Core: post-quantum cryptographic substrate.
   //! See BLUEPRINT.md for the design and milestone plan.

Conventional commits, one per logical unit (docs:, ci:, chore:). All signed
with --signoff.

When done, verify:
- cargo build passes
- cargo test passes
- cargo clippy -- -D warnings passes
- cargo fmt -- --check passes
- CI is green on main

Push to origin/main and report.

Do NOT over-engineer. No extra modules, no extra crates, no premature 
abstractions. Less is more.
```

### M1  --  FIRST LIGHT

```
M1 from BLUEPRINT.md. Code-minimization is principle D.

Goal: ML-KEM-768 in paramant-core, byte-equivalent with paramant-relay,
30 KAT-vectors passing.

Tasks:

1. crates/paramant-core/Cargo.toml: add oqs, aws-lc-rs (not used yet but 
   matches blueprint Sec.4), serde, serde_json (dev), hex (dev), proptest (dev).
   Pin via workspace.dependencies.

2. crates/paramant-core/src/error.rs (ONE FILE):
   thiserror-based CoreError enum. CoreResult<T>. Keep it small.

3. crates/paramant-core/src/secret.rs (ONE FILE):
   Re-export secrecy::Secret. Helper for hex deserialization in test code.

4. crates/paramant-core/src/kem.rs (ONE FILE, target <= 250 lines):
   - PublicKey, SecretKey (wraps Secret), Ciphertext, SharedSecret structs
   - Functions: keygen(), keygen_from_seed(seed), encaps(pk), 
     encaps_from_seed(pk, seed), decaps(sk, ct)
   - Implementation: oqs::kem::Kem with Algorithm::MlKem768
   - Derive Zeroize on SecretKey internal storage
   - Rustdoc on every pub item, with example in at least one
   - No traits, no generics, no builders. Functions on opaque types.
   - No unsafe

5. crates/paramant-core/src/lib.rs:
   //! Paramant Core.
   pub mod error;
   pub mod secret;
   pub mod kem;
   pub mod prelude;  // re-exports common types

6. crates/paramant-core/src/prelude.rs:
   pub use crate::error::{CoreError, CoreResult};
   pub use crate::secret::Secret;

7. scripts/extract-kat.js (Node.js):
   - require ../paramant-relay/relay/crypto (or wherever ML-KEM-768 lives)
   - Generate 30 vectors with seeds 0..29 padded to 64 bytes
   - Write tests/kat/ml-kem-768.json with:
     {
       "primitive": "ml-kem-768",
       "source": "paramant-relay build 2.5.0",
       "vectors": [
         { "test_id": "kem-000", "input": { "seed_hex": "..." }, 
           "expected": { "public_key_hex": "...", "secret_key_hex": "...", 
                         "ciphertext_hex": "...", "shared_secret_hex": "..." } },
         ...
       ]
     }

8. crates/paramant-core/tests/kat_ml_kem_768.rs:
   - Read tests/kat/ml-kem-768.json
   - For each vector: assert byte-equal output from paramant-core
   - Verify decaps(sk, ct) produces same shared_secret

9. crates/paramant-core/tests/proptest_kem.rs:
   - proptest target: keygen produces valid keys (decaps after encaps == shared)
   - 1000 iterations

Acceptance:
- cargo test passes all 30 KAT vectors
- cargo fuzz works without crashes (5 min run)
- cargo clippy -- -D warnings passes
- cargo doc --no-deps renders without warnings
- Coverage on kem.rs > 85% (cargo-tarpaulin)

Commits: feat(kem): ML-KEM-768 with KAT, test(kem): 30 vectors, docs(kem): 
rustdoc. All signed.

DO NOT add extra modules. DO NOT split kem.rs into submodules unless > 300 
lines. DO NOT add traits. Minimize.
```

### M2  --  POST-QUANTUM COMPLETE

```
M2 from BLUEPRINT.md. Code-minimization is principle D.

Goal: KEM hybrid + all SIG primitives, 100+ KAT-vectors.

Tasks:

1. In crates/paramant-core/src/kem.rs (still ONE file if under 300 lines):
   - Add HybridPublicKey, HybridSecretKey, HybridCiphertext, HybridSharedSecret
   - Functions: hybrid_keygen, hybrid_encaps, hybrid_decaps
   - ECDH P-256 via aws-lc-rs::agreement
   - Combined shared secret via HKDF-Extract(salt = PQ_ss, ikm = ECDH_ss)
   - ADR-005 documents the hybrid construction

   If kem.rs exceeds 300 lines, split into kem/mod.rs + kem/hybrid.rs at this 
   point. Not before.

2. crates/paramant-core/src/sig.rs (ONE file):
   - PublicKey, SecretKey, Signature types (for each algorithm or generic
     via enum SigAlgorithm)
   - Decision: separate types per algorithm (ADR-006). Pattern: 
     MlDsa65PublicKey, SlhDsaPublicKey, FalconPublicKey
   - Functions: ml_dsa_65::{keygen, sign, verify}, slh_dsa::{...}, falcon::{...}
   - All via oqs::sig::Sig
   - Default for Paramant: ML-DSA-65 (ADR-007)

3. scripts/extract-kat.js: extend to generate vectors for hybrid_kem, 
   ml_dsa_65, slh_dsa, falcon. Add to existing JSON or split per primitive.

4. tests/kat_*.rs for each new primitive. Pattern identical to M1.

5. tests/proptest_sig.rs: sign-then-verify round trip, 1000 iters per algo.

6. ADRs:
   - 0005-hybrid-kem-construction.md
   - 0006-signature-type-pattern.md (per-algo types, not generic)
   - 0007-default-signature-algorithm.md (ML-DSA-65 default)

Acceptance:
- 130+ total KAT vectors
- All tests pass
- cargo doc renders
- 3 new ADRs written
- CHANGELOG updated

Commits: feat(kem): hybrid construction, feat(sig): ML-DSA-65, feat(sig): 
SLH-DSA, feat(sig): Falcon, test: KATs for all, docs(adr): 5/6/7. Signed.

Reminder: no unnecessary traits, no generics where concrete enums work.
```

### M3  --  SYMMETRIC LAYER

```
M3 from BLUEPRINT.md. Code-minimization.

Goal: AEAD + KDF + mnemonic complete, constant-time verified where relevant.

Tasks:

1. crates/paramant-core/src/aead.rs (ONE file, <= 200 lines):
   - encrypt(key: &Secret<[u8;32]>, nonce: &[u8;12], aad: &[u8], pt: &[u8]) -> Vec<u8>
   - decrypt(key, nonce, aad, ct) -> CoreResult<Vec<u8>>
   - aws-lc-rs::aead with AES-256-GCM
   - Debug build: assert nonce != all-zero
   - KAT: tests/kat/aes-256-gcm.json (40 vectors)

2. crates/paramant-core/src/kdf.rs (ONE file, <= 250 lines):
   - argon2id::hash_password(password: &[u8], salt: &[u8]) -> Secret<[u8;32]>
   - argon2id::verify_password(password, salt, expected) -> bool (constant-time)
   - Params: m=19456, t=2, p=1 (OWASP 2024). ADR-008 documents.
   - hkdf::extract, hkdf::expand
   - KAT: tests/kat/argon2id.json (15 vectors), tests/kat/hkdf.json (20)

3. crates/paramant-core/src/mnemonic.rs (ONE file, <= 150 lines):
   - Mnemonic struct wrapping 12 words
   - generate(), generate_from_entropy([u8; 16]) (for KAT), parse(&str), 
     to_seed(passphrase) -> Secret<[u8; 64]>
   - Uses bip39 crate, English wordlist only
   - KAT: tests/kat/bip39.json (15 vectors)

4. scripts/extract-kat.js: extend.

5. Constant-time check in tests/constant_time.rs:
   - Test that aead::decrypt rejects tampered ciphertext in constant time
   - Test that argon2id::verify_password is constant-time
   - Use subtle::ConstantTimeEq

6. Document in docs/threat-model.md: which functions MUST be constant-time.

7. ADR-008: Argon2id parameter choice.

Acceptance:
- 90+ new KAT vectors (total 220+)
- cargo test passes
- Constant-time properties tested
- ADR-008 written
- cargo clippy passes

Commits: feat(aead), feat(kdf): argon2id, feat(kdf): hkdf, feat(mnemonic), 
test: constant-time, docs(adr): 8. Signed.
```

### M4  --  PROTOCOL LAYER

```
M4 from BLUEPRINT.md. Code-minimization.

Goal: merkle + padding + envelope + wire format v1 complete, end-to-end 
round-trip byte-equivalent with paramant-relay.

Tasks:

1. crates/paramant-core/src/merkle.rs (ONE file, <= 300 lines, split if exceeds):
   - MerkleTree struct (append, root, inclusion_proof, verify_inclusion)
   - SHA-256 hashing
   - SignedTreeHead { tree_size, root_hash, timestamp, signature }
   - sign_sth(sk: &Ml DSA65SecretKey, ...) and verify_sth(pk, sth)

2. crates/paramant-core/src/padding.rs (ONE file, <= 150 lines):
   - enum PaddingScheme { Block4K, Block64K, Block512K, Block5M }
   - pad(plaintext) -> (PaddingScheme, Vec<u8>)
   - unpad(padded, scheme) -> CoreResult<Vec<u8>>
   - Last 4 bytes encode original length

3. crates/paramant-core/src/wire.rs (ONE file, <= 250 lines):
   - Version byte at start (0x01 for v1)
   - TLV (Type-Length-Value) encoding
   - encode_v1(envelope) -> Vec<u8>
   - decode_v1(bytes) -> CoreResult<Envelope>
   - Forward-compat: unknown TLV tags skipped, not errored
   - docs/wire-format-v1.md spec (5-10 pages, RFC-style)

4. crates/paramant-core/src/envelope.rs (ONE file, <= 300 lines, split if exceeds):
   - enum Envelope { Send {..}, ParaShare {..}, ParaDrop {..} }
   - Send: AES-256-GCM with browser-generated key (out-of-band, URL fragment)
   - ParaShare: Hybrid KEM + ML-DSA-65 signature + device fingerprint
   - ParaDrop: BIP-0039 mnemonic + ML-KEM-768 session
   - encrypt/decrypt functions per variant

5. tests/envelope_roundtrip.rs:
   - For each mode: full round-trip
   - Then load paramant-relay output via tests/kat/envelope-*.json
   - Assert byte-equivalence

6. docs/wire-format-v1.md: complete spec.

7. ADR-009: wire format versioning strategy.

Acceptance:
- All envelope modes round-trip
- Byte-equivalent with paramant-relay output
- 50+ new KAT vectors
- docs/wire-format-v1.md exists, >= 5 pages

Commits: feat(merkle), feat(padding), feat(wire), feat(envelope), test: 
roundtrip, docs(adr): 9, docs(wire): v1 spec. Signed.
```

### M5  --  BRIDGE

```
M5 from BLUEPRINT.md. Code-minimization.

Goal: paramant-core-node NAPI binding created, one paramant-relay endpoint 
runs entirely on it.

Tasks:

1. Create crates/paramant-core-node (cargo new --lib --vcs none):
   - napi 2.16 + napi-derive 2.16
   - paramant-core = { path = "../paramant-core" }
   - [lib] crate-type = ["cdylib"]
   - package.json: name @paramant/core, version 0.5.0-alpha.1

2. crates/paramant-core-node/src/lib.rs (ONE file, <= 400 lines):
   - #[napi] thin wrappers around paramant-core public API
   - Inputs/outputs as Buffer
   - Errors as JS Error
   - One function per paramant-core function. No clever batching.

3. crates/paramant-core-node/build.rs: napi-build setup.

4. crates/paramant-core-node/scripts/build.sh:
   - napi build --release --platform --target x86_64-unknown-linux-gnu
   - napi build --release --platform --target aarch64-unknown-linux-gnu

5. In paramant-relay (NOT in this repo, document the procedure):
   - npm install @paramant/core (initially file:// link)
   - Pick ONE endpoint that does ML-KEM-768 keygen, e.g. /api/keygen
   - Replace existing crypto call with require('@paramant/core').kemKeygen()
   - Run existing test suite

6. tests/interop_napi.rs:
   - Crypto via paramant-core direct: encrypt
   - Crypto via @paramant/core NAPI: decrypt
   - Assert plaintext matches
   - And vice versa

7. scripts/bench-vs-relay.sh:
   - 10,000 keygen ops in paramant-core (native), paramant-core via NAPI, 
     paramant-relay (legacy)
   - Report ratio. Target: NAPI > 80% of native.
   - Save to docs/benchmarks.md

8. docs/deploy-bridge.md (<= 2 pages):
   - Step-by-step for swapping one endpoint
   - Rollback (git revert + npm install old version)
   - Monitoring metrics

Acceptance:
- @paramant/core builds for Linux x64 + arm64
- Interop tests pass
- NAPI performance > 80% native
- One paramant-relay endpoint uses paramant-core in dev environment
- Runbook is followable

Commits: feat(node): NAPI binding, test(node): interop, docs(bridge): runbook. 
Signed.
```

### M6  --  SURFACE

```
M6 from BLUEPRINT.md. Code-minimization.

Goal: paramant-core-wasm created, paramant.app/send runs on it in browser.

Tasks:

1. Create crates/paramant-core-wasm (cargo new --lib --vcs none):
   - wasm-bindgen 0.2 + js-sys 0.3
   - paramant-core = { path = "../paramant-core" }
   - [lib] crate-type = ["cdylib"]

2. crates/paramant-core-wasm/src/lib.rs (ONE file, <= 400 lines):
   - #[wasm_bindgen] wrappers, mirror @paramant/core API surface
   - Inputs/outputs as Uint8Array

3. crates/paramant-core-wasm/scripts/build.sh:
   - wasm-pack build --target web --release
   - wasm-pack build --target nodejs --release
   - wasm-pack build --target bundler --release
   - Fail if bundle > 800 KB gzipped

4. Bundle size optimization:
   - opt-level = "z" in release profile
   - Strip debug symbols
   - wee_alloc allocator (ADR-010)
   - Cargo features to gate unused primitives if needed

5. Browser integration in paramant-relay frontend:
   - Replace existing JS crypto on /send with import from @paramant/core-wasm
   - Run frontend test suite

6. tests/wasm_browser.html: manual test page rendering keygen + encrypt in 
   browser

7. Cross-browser smoke test: Chrome, Firefox, Safari (latest desktop + mobile)

Acceptance:
- WASM bundle < 800 KB gzipped
- paramant.app/send runs on WASM
- No JS-crypto fallback
- Performance > 50% of native (documented in benchmarks.md)
- 5 browsers tested

Commits: feat(wasm), perf(wasm): bundle size, docs(adr): 10. Signed.
```

### M7  --  GOEDE EERSTE BETA

```
M7 from BLUEPRINT.md. The milestone.

Goal: IoT sector-relay runs 60+ days on paramant-core, no regressions.

Pre-flight (in paramant-relay repo):
- [ ] @paramant/core M5 binding works for all crypto used by IoT relay
- [ ] @paramant/core-wasm M6 works for IoT browser endpoints
- [ ] Performance benchmarks meet criteria

Tasks:

1. In paramant-relay/sectors/iot/config.js: feature flag PARAMANT_CORE_ENABLED
   - true: route crypto through @paramant/core
   - false: legacy code path
   - Default: false during rollout

2. Staged rollout (observation windows, not blueprint-imposed time):
   - Phase 1: 5% traffic
   - Phase 2: 25%
   - Phase 3: 50%
   - Phase 4: 100% for 60+ days

3. docs/monitoring-m7.md:
   - Metrics: p50/p95/p99 latency per crypto op, error rate, memory, CPU
   - Baseline from before paramant-core adoption
   - Comparison dashboard

4. Alert thresholds:
   - p95 > 1.2x baseline: warn
   - p95 > 1.5x baseline: pause rollout
   - Error rate > 0.1%: pause rollout
   - Any crash: rollback

5. docs/m7-soak-log.md:
   - Daily summary: date, traffic %, p50/p95/p99, errors, notes
   - Weekly write-up

6. M7 acceptance:
   - 60+ consecutive days at 100% IoT traffic
   - 0 crashes
   - 0 functional regressions
   - p95 within 1.1x baseline
   - Memory stable, no leaks
   - 0 client complaints attributable to paramant-core

7. When M7 closes:
   - Tag paramant-core v0.7.0-beta.1
   - Draft blog post "paramant-core is now in beta"
   - Begin M8 prep (external reviewers)

Commits in paramant-core: docs(monitoring): M7 plan, docs(m7-soak): log template. 
In paramant-relay: feat(iot): paramant-core integration, feat(iot): feature 
flag. Signed.
```

### M8-M14 (sketch only)

Vanaf M8 wordt het externe audit + governance werk. Geen exacte prompts nodig op deze schaal.

- **M8 External Review:** Ryan Williams + 2 nieuwe reviewers (EUR 500-1500 honorarium per persoon), 4-week window, triage findings, blog post bij sluiting
- **M9 Audit Prepared:** Cure53 of NCC Group boeken bij M7-voltooiing (6-12 maanden wachttijd), audit-pakket leveren (architecture, threat model, KAT-resultaten, fuzz-uren, constant-time analyse, benchmarks, coverage, cargo-deny, SBOM)
- **M10 Audited:** rapport ontvangen, findings remedieren, re-test, publicatie op paramant.app/audits
- **M11 GA:** v1.0.0 op crates.io + npm + GitHub Releases (signed binaries), persrelease + LinkedIn-launch
- **M12 Specification:** Wire format v1 spec als zelfstandig document, Conformance Test Suite (CTS) vrijgegeven
- **M13 Second Implementation:** Go-implementatie, CTS draait er groen op, interop met paramant-core werkt
- **M14 Standardized:** IETF Internet-Draft of ETSI TR, NLnet/GAIA-X grant aangevraagd

---

## 8. TEST VECTOR EXTRACTION

paramant-relay (build 2.5.0) is de spec. `scripts/extract-kat.js` extracts deterministic vectors per primitief.

Bidirectional eis: Rust-output door paramant-relay decodeerbaar en vice versa. Gegarandeerd geen breaking change voor klanten wanneer paramant-relay intern overschakelt op paramant-core.

Voor stochastische ops: deterministic seeds via mock-RNG. AEAD: fixed nonces in test mode. BIP-0039: equivalente entropie + deterministisch decoding-pad.

---

## 9. AUDIT PREP VANAF COMMIT 1

**Per commit:**
- cargo clippy -- -D warnings passes
- Geen unsafe zonder safety-comment + ADR-verwijzing
- Constant-time properties via subtle waar relevant
- Secret-types via secrecy::Secret<T>, automatic zeroize
- Coverage gerapporteerd via cargo-tarpaulin in CI

**Doorlopend:**
- cargo-fuzz campaign per primitief
- cargo-deny: license + advisory scan
- SBOM in CycloneDX format
- Dependency review per major release

**Per tagged release:**
- Threat model herzien
- CHANGELOG met security-relevante wijzigingen
- Signed Git tags (GPG)
- Signed crate uploads (sigstore via cargo-sign)

---

## 10. RISICO

| Risico | Mitigatie |
|---|---|
| Mick blokkeert op productontwikkeling | Mijlpaal-gebaseerd, geen tijdsdruk |
| `oqs` breaking change | ADR-002 migratiepad naar pqcrypto-* |
| Audit-firma 6-12 mnd wachttijd | Slot reserveren bij M7-voltooiing |
| Externe reviewers blijven uit | Honorarium betalen, gericht uitnodigen |
| FFI memory bug | Alleen NAPI-RS, geen handgeschreven bindgen |
| Mick raakt overweldigd door Rust | M0-M2 pair-programmen, idiomatisch pas vanaf M3 |
| Productie-regressie bij M5/M7 | Feature-flag, staged rollout, rollback-runbook |

---

## 11. KOSTEN

| Post | Bedrag |
|---|---|
| External review M8 (3 reviewers) | EUR 4.500 - EUR 9.000 |
| Cure53 / NCC audit M9-M10 | EUR 15.000 - EUR 40.000 |
| crates.io / npm / PyPI | EUR 0 |
| GitHub Actions minutes | EUR 0 - EUR 50/mnd |
| ETSI participation (optioneel M12+) | EUR 5.000 - EUR 15.000/jr |
| Conference travel M14 | EUR 2.000 - EUR 5.000/jr |
| NLnet / GAIA-X grant (potentieel inkomst) | -EUR 30.000 tot -EUR 100.000 |
| **Netto M0-M11** | **EUR 20.000 - EUR 55.000** |

---

## 12. SCOPE-DISCIPLINE

**Wel** in paramant-core:
- Cryptografische primitieven (KEM, SIG, AEAD, KDF, mnemonic)
- Merkle log + STH
- Padding & wire format
- Envelope crypto-logica
- Secret-type management

**Niet** in paramant-core (blijft paramant-relay):
- HTTP server, multipart parsing, admin panel
- Sector routing, Stripe billing, TLS termination
- Database, persistence (relay.js blijft RAM-only)

---

## 13. BOTTOM LINE

paramant-core wordt:
- Geschat <= 2000 regels Rust core
- 12 source-bestanden in `src/`
- 12 dependencies
- 2 crates bij M0, 4 bij M11, max 6 ever
- 100% rustdoc op pub items
- Geen `unsafe`
- Geen traits zonder reden, geen generics zonder reden, geen abstractions zonder reden

Wanneer M7 is gehaald: GOEDE eerste beta. Wanneer M11: v1.0.0 op crates.io. Wanneer M14: Paramant Protocol is op weg een EU-standaard te worden.

Geen rewrite. Geen tijdsdruk. relay.js blijft draaien. Klanten merken niets. Intussen groeit paramant-core eronder, klein en sterk.

---

*Blueprint v3.1 . 26 mei 2026 . Mick Beer . paramant.app*
*Less is more.*
