# Scripts — KAT vector generation

`extract-kat.mjs` regenerates the Known-Answer-Test vectors in
[`../tests/kat/`](../tests/kat/). Sources differ by primitive:

| File | Source |
|------|--------|
| `ml-kem-768.json`, `ml-dsa-65.json` | `@noble/post-quantum` (FIPS impl `paramant-relay` uses) |
| `aes-256-gcm.json` | `@noble/ciphers` |
| `hkdf.json` | pure Node HMAC-SHA256, anchored to RFC 5869 Appendix A |
| `argon2id.json` | `@noble/hashes`, validated against the RFC 9106 Appendix A vector before emitting |
| `bip39.json` | trezor/python-mnemonic canonical vectors; seeds re-derived with Node PBKDF2 |

Each section is independent: a missing source is skipped with a warning, so
partial regeneration works.

## Setup (one-time, out-of-tree)

Node tooling must **never** be installed inside this repo (see
[ADR-0006](../docs/adrs/0006-no-node-tooling-in-repo.md)). Install the
references somewhere under `/tmp`, fetch the trezor vectors, and point env vars
at them:

```sh
mkdir -p /tmp/noble-pq && cd /tmp/noble-pq
npm init -y >/dev/null
npm install @noble/post-quantum @noble/ciphers @noble/hashes
curl -sSLO https://raw.githubusercontent.com/trezor/python-mnemonic/master/vectors.json

export NOBLE_PQ_MLKEM=/tmp/noble-pq/node_modules/@noble/post-quantum/ml-kem.js
export ARGON2_SPEC=/tmp/noble-pq/node_modules/@noble/hashes/argon2.js
export BIP39_TREZOR_VECTORS=/tmp/noble-pq/vectors.json
```

The script derives the sibling `ml-dsa.js` / `aes.js` paths from
`NOBLE_PQ_MLKEM` automatically. HKDF needs no install (pure Node).

## Usage

```sh
node scripts/extract-kat.mjs
```

SLH-DSA and Falcon are not extracted (liboqs ships SPHINCS+ round-3, not
FIPS-205 SLH-DSA, and Falcon's encoding varies between implementations — see
[ADR-0009](../docs/adrs/0009-sphincs-vs-slh-dsa.md)); they are round-trip tested
in-crate instead.

## Why out-of-tree

See [ADR-0006](../docs/adrs/0006-no-node-tooling-in-repo.md).
