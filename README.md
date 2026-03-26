# paramant-core
### PARAMANT Rust Crypto Library

> Post-quantum hybride cryptografie voor PARAMANT.  
> ML-KEM-768 + ECDH P-256 + AES-256-GCM + HKDF + dubbel ratchet.

[![Tests](https://img.shields.io/badge/tests-5%2F5-00ff9d?style=flat-square&labelColor=0c0e10)](#tests)
[![Rust](https://img.shields.io/badge/rust-1.94-2a2d35?style=flat-square&labelColor=0c0e10)](https://rustup.rs)

---

## Algoritmen

| Crate | Algoritme | Versie |
|---|---|---|
| `pqcrypto-kyber` | ML-KEM-768 (Kyber768) | 0.8 |
| `p256` | ECDH P-256 | 0.13 |
| `aes-gcm` | AES-256-GCM | 0.10 |
| `hkdf` | HKDF-SHA-256 | 0.12 |
| `zeroize` | Secure memory wipe | 1.7 |

---

## Structuur

```
src/
├── lib.rs          ← Public API
├── error.rs        ← ParamantError enum
├── identity.rs     ← Sleutelpaar generatie + fingerprint
├── ratchet.rs      ← Dubbel ratchet + KEM injectie
├── session.rs      ← Volledige handshake + sessie
├── relay.rs        ← Relay URL constanten
└── crypto/
    ├── mod.rs
    ├── kem.rs      ← ML-KEM-768 encapsulate/decapsulate
    ├── ecdh.rs     ← ECDH P-256 sleuteluitwisseling
    ├── kdf.rs      ← HKDF master + chain key derivation
    └── aead.rs     ← AES-256-GCM encrypt/decrypt
```

---

## Key exchange protocol

```
// Handshake
alice_ecdh = EcdhKeyPair::generate()
alice_kem  = KemKeyPair::generate()

// Bob encapsuleert
(ct, kem_shared) = encapsulate(&alice_kem.public_key)
ecdh_shared      = bob_ecdh.diffie_hellman(&alice_ecdh.public_key)
master           = derive_master(&ecdh_shared, &kem_shared)
// "paramant-master-v1"

// Ratchet chains
chain_a = derive_chain_key(&master, b"paramant-chain-A-v2")
chain_b = derive_chain_key(&master, b"paramant-chain-B-v2")

// Per bericht
(msg_key, next_chain) = derive_message_key(&chain_key)
encrypted = encrypt(&msg_key, plaintext, seq, "msg")
// AAD = "paramant:{seq}:{type}"

// KEM re-injectie elke 8 berichten
new_chain = HKDF(chain_key ‖ new_kem_shared, "kem-ratchet")
```

---

## Tests

```bash
cargo test
```

```
test crypto::kem::tests::test_kem_roundtrip          ... ok
test ratchet::tests::test_kem_injection_trigger      ... ok
test ratchet::tests::test_replay_rejected            ... ok
test ratchet::tests::test_ratchet_roundtrip          ... ok
test session::tests::test_full_handshake_and_messaging ... ok

test result: ok. 5 passed; 0 failed
```

---

## Gebruik

```toml
# Cargo.toml
[dependencies]
paramant-core = { path = "../paramant-core" }
```

```rust
use paramant_core::identity::Identity;
use paramant_core::crypto::kem;

// Identiteit genereren
let identity = Identity::generate()?;
println!("{}", identity.public_address());

// KEM roundtrip
let alice = kem::KemKeyPair::generate()?;
let (ct, bob_shared) = kem::encapsulate(&alice.public_key)?;
let alice_shared = alice.decapsulate(&ct)?;
assert_eq!(alice_shared.0, bob_shared.0);
```

---

## Security

- `KemKeyPair` en `SharedSecret` implementeren `Zeroize + ZeroizeOnDrop`
- `EcdhShared` gewist via `drop()`
- `EphemeralSecret` van p256 — niet serialiseerbaar, eenmalig gebruik
- Replay-bescherming via nonce-registry in de applicatielaag
