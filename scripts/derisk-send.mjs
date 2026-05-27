#!/usr/bin/env node
// De-risk M4 phase 2b (anonymous Send mode) BEFORE writing any Rust.
//
// Proves that the deterministic crypto paramant-core will mirror in Rust
// (HKDF-SHA256 via HMAC + AES-256-GCM via AWS-LC) is byte-identical to what
// paramant-relay's `sdk-js` actually does  --  which uses WebCrypto HKDF/AES-GCM
// and the relay's own `wireEncode`. For each fixed input we:
//
//   1. derive ctKem + sharedSecret deterministically with @noble/post-quantum
//      ML-KEM-768 (seed-based keygen + msg-based encapsulate);
//   2. derive the AES key + ciphertext two ways  --  WebCrypto (exactly the relay
//      code path) and pure-Node HMAC/AES-GCM (the path Rust reproduces)  --  and
//      assert they are byte-equal;
//   3. frame the envelope with the relay's *own* `wireEncode` and print the
//      core SHA-256.
//
// If step 2 ever disagrees, STOP: Rust cannot be trusted to match the relay.
//
// Run (out-of-tree @noble per ADR-0006):
//   NOBLE_PQ_MLKEM=/tmp/paramant-kat-tooling/node_modules/@noble/post-quantum/ml-kem.js \
//   node scripts/derisk-send.mjs

import { createHmac, createHash, createCipheriv, webcrypto } from 'node:crypto';

const RELAY_WIRE =
  process.env.RELAY_WIRE ?? '/tmp/paramant-relay-ref/sdk-js/src/wire-format.js';
const mlkemSpec = process.env.NOBLE_PQ_MLKEM ?? '@noble/post-quantum/ml-kem.js';

const { encode: wireEncode, buildAAD } = await import(RELAY_WIRE);
const { ml_kem768 } = await import(mlkemSpec);
const subtle = webcrypto.subtle;

const hex = (u8) => Buffer.from(u8).toString('hex');
const sha256 = (u8) => createHash('sha256').update(Buffer.from(u8)).digest();
const INFO = new TextEncoder().encode('paramant-v1-aes-key'); // relay's HKDF info

function bytesFrom(label, n) {
  let b = Buffer.alloc(0);
  for (let i = 0; b.length < n; i++) {
    b = Buffer.concat([b, createHash('sha512').update(`${label}:${i}`).digest()]);
  }
  return new Uint8Array(b.subarray(0, n));
}

// Pure-Node HKDF-SHA256 (RFC 5869)  --  the algorithm kdf::hkdf implements in Rust.
const hkdfExtract = (salt, ikm) =>
  createHmac('sha256', salt.length ? Buffer.from(salt) : Buffer.alloc(32))
    .update(Buffer.from(ikm))
    .digest();
function hkdfExpand(prk, info, len) {
  const n = Math.ceil(len / 32);
  let t = Buffer.alloc(0);
  const out = [];
  for (let i = 1; i <= n; i++) {
    t = createHmac('sha256', prk)
      .update(Buffer.concat([t, Buffer.from(info), Buffer.from([i])]))
      .digest();
    out.push(t);
  }
  return new Uint8Array(Buffer.concat(out).subarray(0, len));
}

// Path A: WebCrypto  --  exactly what sdk-js/index.js `_encrypt` runs.
async function webcryptoPath(sharedSecret, salt, nonce, aad, plaintext) {
  const base = await subtle.importKey('raw', sharedSecret, { name: 'HKDF' }, false, ['deriveKey']);
  const aesKey = await subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: INFO },
    base,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt'],
  );
  const rawKey = new Uint8Array(await subtle.exportKey('raw', aesKey));
  const ct = new Uint8Array(
    await subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad }, aesKey, plaintext),
  );
  return { rawKey, ct };
}

// Path B: pure-Node HMAC-HKDF + AES-256-GCM  --  what paramant-core does in Rust.
function nodePath(sharedSecret, salt, nonce, aad, plaintext) {
  const prk = hkdfExtract(salt, sharedSecret);
  const key = hkdfExpand(prk, INFO, 32);
  const c = createCipheriv('aes-256-gcm', Buffer.from(key), Buffer.from(nonce));
  c.setAAD(Buffer.from(aad));
  const body = Buffer.concat([c.update(Buffer.from(plaintext)), c.final()]);
  const tag = c.getAuthTag();
  return { rawKey: key, ct: new Uint8Array(Buffer.concat([body, tag])) };
}

const CASES = [
  { id: 'derisk-empty', ptLen: 0 },
  { id: 'derisk-short', ptLen: 13 },
  { id: 'derisk-block', ptLen: 1024 },
  { id: 'derisk-odd', ptLen: 4095 },
  { id: 'derisk-large', ptLen: 70000 },
];

let allOk = true;
for (const { id, ptLen } of CASES) {
  const seed = bytesFrom(`paramant/send/${id}/seed`, 64);
  const msg = bytesFrom(`paramant/send/${id}/msg`, 32);
  const { publicKey, secretKey } = ml_kem768.keygen(seed);
  const { cipherText: ctKem, sharedSecret } = ml_kem768.encapsulate(publicKey, msg);
  const senderPub = publicKey; // anonymous: senderPub = own KEM pubkey (opaque id)
  const nonce = bytesFrom(`paramant/send/${id}/nonce`, 12);
  const plaintext = bytesFrom(`paramant/send/${id}/pt`, ptLen);

  const salt = ctKem.slice(0, 32);
  const aad = buildAAD({ kemId: 0x0002, sigId: 0x0000, flags: 0x00, chunkIndex: 0 });

  const a = await webcryptoPath(sharedSecret, salt, nonce, aad, plaintext);
  const b = nodePath(sharedSecret, salt, nonce, aad, plaintext);

  const keyOk = hex(a.rawKey) === hex(b.rawKey);
  const ctOk = hex(a.ct) === hex(b.ct);
  allOk &&= keyOk && ctOk;

  const core = wireEncode({
    kemId: 0x0002,
    sigId: 0x0000,
    flags: 0x00,
    ctKem,
    senderPub,
    nonce,
    ciphertext: a.ct,
  });

  console.log(`${id}: key=${keyOk ? 'OK' : 'MISMATCH'} ct=${ctOk ? 'OK' : 'MISMATCH'} ` +
    `coreLen=${core.length} coreSha=${hex(sha256(core)).slice(0, 16)} ` +
    `(sk=${secretKey.length}B ctKem=${ctKem.length}B)`);
}

if (!allOk) {
  console.error('\nDE-RISK FAILED: WebCrypto and pure-Node paths diverge. Do NOT write Rust.');
  process.exit(1);
}
console.log('\nDE-RISK OK: relay WebCrypto path == pure-Node HKDF+AES-GCM == relay wireEncode framing.');
