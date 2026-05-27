#!/usr/bin/env node
// De-risk M4 phase 2c ParaShare (signed, device-paired) BEFORE writing Rust.
//
// ParaShare = paramant-relay sdk-js `_encrypt` with SIG_ID != 0x0000 (default
// ML-DSA-65 0x0002). It is the Send-mode crypto (single ML-KEM-768, HKDF, AES-
// 256-GCM, header as AAD) PLUS an ML-DSA-65 signature over
//
//   msg = ct_kem || sender_pub || nonce || ciphertext || aad
//
// where sender_pub is the sender's ML-DSA-65 *public* key (not the KEM key) and
// aad = PQHB header(10) || chunk_index_be32. This script reproduces that exactly
// with @noble (deterministic ML-KEM-768 + ML-DSA-65) and the relay's own
// wireEncode/wireDecode/buildAAD, asserting: pure-Node AES/HKDF == WebCrypto
// (the path Rust mirrors), the @noble signature verifies, and the core decodes
// back to the same fields. STOP if anything diverges.
//
// Run:
//   NOBLE_PQ_MLKEM=/tmp/paramant-kat-tooling/node_modules/@noble/post-quantum/ml-kem.js \
//   node scripts/derisk-parashare.mjs

import { createHmac, createHash, createCipheriv, webcrypto } from 'node:crypto';

const RELAY_WIRE = process.env.RELAY_WIRE ?? '/tmp/paramant-relay-ref/sdk-js/src/wire-format.js';
const mlkemSpec = process.env.NOBLE_PQ_MLKEM ?? '@noble/post-quantum/ml-kem.js';
const mldsaSpec = process.env.NOBLE_PQ_MLDSA ?? mlkemSpec.replace('ml-kem.js', 'ml-dsa.js');

const { encode: wireEncode, decode: wireDecode, buildAAD } = await import(RELAY_WIRE);
const { ml_kem768 } = await import(mlkemSpec);
const { ml_dsa65 } = await import(mldsaSpec);
const subtle = webcrypto.subtle;

const hex = (u8) => Buffer.from(u8).toString('hex');
const sha256 = (u8) => createHash('sha256').update(Buffer.from(u8)).digest();
const concat = (...a) => { const t = Buffer.concat(a.map(Buffer.from)); return new Uint8Array(t); };
const INFO = new TextEncoder().encode('paramant-v1-aes-key');

function bytesFrom(label, n) {
  let b = Buffer.alloc(0);
  for (let i = 0; b.length < n; i++) b = Buffer.concat([b, createHash('sha512').update(`${label}:${i}`).digest()]);
  return new Uint8Array(b.subarray(0, n));
}
const hkdfExtract = (salt, ikm) =>
  createHmac('sha256', salt.length ? Buffer.from(salt) : Buffer.alloc(32)).update(Buffer.from(ikm)).digest();
function hkdfExpand(prk, info, len) {
  const n = Math.ceil(len / 32);
  let t = Buffer.alloc(0);
  const out = [];
  for (let i = 1; i <= n; i++) {
    t = createHmac('sha256', prk).update(Buffer.concat([t, Buffer.from(info), Buffer.from([i])])).digest();
    out.push(t);
  }
  return new Uint8Array(Buffer.concat(out).subarray(0, len));
}
async function webcryptoCt(sharedSecret, salt, nonce, aad, plaintext) {
  const base = await subtle.importKey('raw', sharedSecret, { name: 'HKDF' }, false, ['deriveKey']);
  const aesKey = await subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: INFO }, base,
    { name: 'AES-GCM', length: 256 }, true, ['encrypt']);
  const rawKey = new Uint8Array(await subtle.exportKey('raw', aesKey));
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad }, aesKey, plaintext));
  return { rawKey, ct };
}
function nodeCt(sharedSecret, salt, nonce, aad, plaintext) {
  const key = hkdfExpand(hkdfExtract(salt, sharedSecret), INFO, 32);
  const c = createCipheriv('aes-256-gcm', Buffer.from(key), Buffer.from(nonce));
  c.setAAD(Buffer.from(aad));
  const body = Buffer.concat([c.update(Buffer.from(plaintext)), c.final()]);
  return { rawKey: key, ct: new Uint8Array(Buffer.concat([body, c.getAuthTag()])) };
}

const CASES = [
  { id: 'ps-empty', ptLen: 0 },
  { id: 'ps-short', ptLen: 11 },
  { id: 'ps-block', ptLen: 1024 },
  { id: 'ps-large', ptLen: 50000 },
];

let allOk = true;
for (const { id, ptLen } of CASES) {
  const { publicKey: kemPk, secretKey: kemSk } = ml_kem768.keygen(bytesFrom(`paramant/ps/${id}/kemseed`, 64));
  const { cipherText: ctKem, sharedSecret } = ml_kem768.encapsulate(kemPk, bytesFrom(`paramant/ps/${id}/kemmsg`, 32));
  const { publicKey: sigPk, secretKey: sigSk } = ml_dsa65.keygen(bytesFrom(`paramant/ps/${id}/sigseed`, 32));
  const nonce = bytesFrom(`paramant/ps/${id}/nonce`, 12);
  const plaintext = bytesFrom(`paramant/ps/${id}/pt`, ptLen);

  const salt = ctKem.slice(0, 32);
  const aad = buildAAD({ kemId: 0x0002, sigId: 0x0002, flags: 0x00, chunkIndex: 0 });
  const a = await webcryptoCt(sharedSecret, salt, nonce, aad, plaintext);
  const b = nodeCt(sharedSecret, salt, nonce, aad, plaintext);
  const aeadOk = hex(a.rawKey) === hex(b.rawKey) && hex(a.ct) === hex(b.ct);

  const msg = concat(ctKem, sigPk, nonce, a.ct, aad);
  const signature = ml_dsa65.sign(msg, sigSk, { extraEntropy: false });
  const verifyOk = ml_dsa65.verify(signature, msg, sigPk) === true;

  const core = wireEncode({ kemId: 0x0002, sigId: 0x0002, flags: 0x00, ctKem, senderPub: sigPk, signature, nonce, ciphertext: a.ct });
  const dec = wireDecode(core);
  const decodeOk = dec.sigId === 0x0002 && dec.signature && hex(dec.signature) === hex(signature) &&
    hex(dec.senderPub) === hex(sigPk) && hex(dec.ctKem) === hex(ctKem) && hex(dec.ciphertext) === hex(a.ct);

  allOk &&= aeadOk && verifyOk && decodeOk;
  console.log(`${id}: aead=${aeadOk ? 'OK' : 'BAD'} verify=${verifyOk ? 'OK' : 'BAD'} decode=${decodeOk ? 'OK' : 'BAD'} ` +
    `coreLen=${core.length} sig=${signature.length}B coreSha=${hex(sha256(core)).slice(0, 16)} (kemSk=${kemSk.length}B)`);
}

if (!allOk) {
  console.error('\nDE-RISK FAILED: ParaShare path diverges. Do NOT write Rust.');
  process.exit(1);
}
console.log('\nDE-RISK OK: ParaShare AES/HKDF == WebCrypto, ML-DSA-65 sig verifies, relay wireEncode/decode round-trips.');
