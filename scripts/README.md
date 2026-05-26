# Scripts — KAT vector generation

`extract-kat.mjs` regenerates the Known-Answer-Test vectors in
[`../tests/kat/`](../tests/kat/) from `@noble/post-quantum`, the FIPS
implementation `paramant-relay` uses.

## Setup (one-time, out-of-tree)

Node tooling must **never** be installed inside this repo (see
[ADR-0006](../docs/adrs/0006-no-node-tooling-in-repo.md)). Install `@noble`
somewhere under `/tmp` and point an env var at it:

```sh
mkdir -p /tmp/noble-pq && cd /tmp/noble-pq
npm init -y >/dev/null
npm install @noble/post-quantum@0.6.1
export NOBLE_PQ_MLKEM=/tmp/noble-pq/node_modules/@noble/post-quantum/ml-kem.js
```

The script derives the sibling `ml-dsa.js` / `slh-dsa.js` paths automatically.

## Usage

```sh
node scripts/extract-kat.mjs
```

Writes `tests/kat/ml-kem-768.json` and `tests/kat/ml-dsa-65.json`. SLH-DSA and
Falcon are not extracted (liboqs ships SPHINCS+ round-3, not FIPS-205 SLH-DSA,
and Falcon's encoding varies between implementations — see
[ADR-0009](../docs/adrs/0009-sphincs-vs-slh-dsa.md)); they are round-trip tested
in-crate instead.

## Why out-of-tree

See [ADR-0006](../docs/adrs/0006-no-node-tooling-in-repo.md).
