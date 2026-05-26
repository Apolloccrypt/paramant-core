#!/usr/bin/env node
// Generate deterministic Known-Answer-Test vectors from @noble/post-quantum —
// the FIPS implementation paramant-relay (build 2.5.0) uses. paramant-core
// checks these byte-for-byte on the deterministic paths (KEM decaps, signature
// verify). See docs/adrs/0005-kem-kat-strategy.md.
//
// Usage:
//   npm i @noble/post-quantum && node scripts/extract-kat.mjs
//   # or point at an existing install (sibling ml-*.js files are derived):
//   NOBLE_PQ_MLKEM=/path/to/@noble/post-quantum/ml-kem.js node scripts/extract-kat.mjs

import { createHash } from 'node:crypto';
import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const mlkemSpec = process.env.NOBLE_PQ_MLKEM ?? '@noble/post-quantum/ml-kem.js';
const mldsaSpec = process.env.NOBLE_PQ_MLDSA ?? mlkemSpec.replace('ml-kem.js', 'ml-dsa.js');
const { ml_kem768 } = await import(mlkemSpec);
const { ml_dsa65 } = await import(mldsaSpec);

const COUNT = 30;
const hex = (u8) => Buffer.from(u8).toString('hex');
const root = join(dirname(fileURLToPath(import.meta.url)), '..');

// Deterministic byte string of length `n` from a label (chained SHA-512).
function bytesFrom(label, n) {
  let buf = Buffer.alloc(0);
  for (let i = 0; buf.length < n; i++) {
    buf = Buffer.concat([buf, createHash('sha512').update(`${label}:${i}`).digest()]);
  }
  return new Uint8Array(buf.subarray(0, n));
}

function write(name, doc) {
  mkdirSync(join(root, 'tests/kat'), { recursive: true });
  writeFileSync(join(root, `tests/kat/${name}.json`), JSON.stringify(doc, null, 2) + '\n');
  console.log(`wrote ${doc.count} vectors to tests/kat/${name}.json`);
}

// ── ML-KEM-768 (FIPS 203): decaps(secret_key, ciphertext) == shared_secret ──
{
  const vectors = [];
  for (let i = 0; i < COUNT; i++) {
    const seed = bytesFrom(`paramant/ml-kem-768/keygen/${i}`, 64); // d||z
    const msg = bytesFrom(`paramant/ml-kem-768/encaps/${i}`, 32); // m
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
  write('ml-kem-768', {
    primitive: 'ml-kem-768',
    source: '@noble/post-quantum (FIPS 203) — paramant-relay build 2.5.0',
    note: 'paramant-core verifies decaps(secret_key, ciphertext) == shared_secret byte-for-byte.',
    count: vectors.length,
    vectors,
  });
}

// ── ML-DSA-65 (FIPS 204): verify(public_key, msg, signature) == true ──
// Deterministic signing via extraEntropy:false (FIPS 204 deterministic variant).
{
  const vectors = [];
  for (let i = 0; i < COUNT; i++) {
    const seed = bytesFrom(`paramant/ml-dsa-65/keygen/${i}`, 32); // xi
    const msg = bytesFrom(`paramant/ml-dsa-65/msg/${i}`, 48);
    const { publicKey, secretKey } = ml_dsa65.keygen(seed);
    const signature = ml_dsa65.sign(msg, secretKey, { extraEntropy: false });
    vectors.push({
      test_id: `dsa-${String(i).padStart(3, '0')}`,
      input: { seed_hex: hex(seed), msg_hex: hex(msg) },
      expected: {
        public_key_hex: hex(publicKey),
        secret_key_hex: hex(secretKey),
        signature_hex: hex(signature),
      },
    });
  }
  write('ml-dsa-65', {
    primitive: 'ml-dsa-65',
    source: '@noble/post-quantum (FIPS 204) — paramant-relay build 2.5.0',
    note: 'paramant-core verifies verify(public_key, msg, signature) == true byte-for-byte; deterministic signing (extraEntropy:false).',
    count: vectors.length,
    vectors,
  });
}
