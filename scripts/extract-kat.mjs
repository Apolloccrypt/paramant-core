#!/usr/bin/env node
// Generate deterministic ML-KEM-768 Known-Answer-Test vectors from
// @noble/post-quantum — the FIPS 203 implementation paramant-relay (build
// 2.5.0) uses. paramant-core verifies decaps(secret_key, ciphertext) ==
// shared_secret byte-for-byte against these. See docs/adrs/0005-kem-kat-strategy.md.
//
// Usage:
//   npm i @noble/post-quantum && node scripts/extract-kat.mjs
//   # or point at an existing install:
//   NOBLE_PQ_MLKEM=/path/to/@noble/post-quantum/ml-kem.js node scripts/extract-kat.mjs

import { createHash } from 'node:crypto';
import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const { ml_kem768 } = await import(
  process.env.NOBLE_PQ_MLKEM ?? '@noble/post-quantum/ml-kem.js'
);

const COUNT = 30;
const hex = (u8) => Buffer.from(u8).toString('hex');

// Deterministic byte string of length `n` from a label (chained SHA-512).
function bytesFrom(label, n) {
  let buf = Buffer.alloc(0);
  for (let i = 0; buf.length < n; i++) {
    buf = Buffer.concat([buf, createHash('sha512').update(`${label}:${i}`).digest()]);
  }
  return new Uint8Array(buf.subarray(0, n));
}

const vectors = [];
for (let i = 0; i < COUNT; i++) {
  const seed = bytesFrom(`paramant/ml-kem-768/keygen/${i}`, 64); // FIPS 203 d||z
  const msg = bytesFrom(`paramant/ml-kem-768/encaps/${i}`, 32);  // FIPS 203 m
  const { publicKey, secretKey } = ml_kem768.keygen(seed);
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey, msg);
  vectors.push({
    test_id: `kem-${String(i).padStart(3, '0')}`,
    input: { seed_hex: hex(seed), msg_hex: hex(msg) },
    expected: {
      public_key_hex: hex(publicKey),
      secret_key_hex: hex(secretKey),
      ciphertext_hex: hex(cipherText),
      shared_secret_hex: hex(sharedSecret),
    },
  });
}

const out = {
  primitive: 'ml-kem-768',
  source: '@noble/post-quantum (FIPS 203) — the implementation used by paramant-relay build 2.5.0',
  note: 'Deterministic via seed (keygen, 64B) and msg (encaps, 32B). paramant-core verifies decaps(secret_key, ciphertext) == shared_secret byte-for-byte; see docs/adrs/0005-kem-kat-strategy.md.',
  count: vectors.length,
  vectors,
};

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
mkdirSync(join(root, 'tests/kat'), { recursive: true });
writeFileSync(join(root, 'tests/kat/ml-kem-768.json'), JSON.stringify(out, null, 2) + '\n');
console.log(`wrote ${vectors.length} ML-KEM-768 vectors to tests/kat/ml-kem-768.json`);
