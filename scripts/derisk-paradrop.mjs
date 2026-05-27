#!/usr/bin/env node
// De-risk M4 phase 2c ParaDrop (BIP-39 mnemonic drop) BEFORE writing Rust.
//
// ParaDrop = paramant-relay sdk-js `drop`/`pickup`. It does NOT use the PQHB
// wire format. From 16 bytes of BIP-39 entropy:
//
//   aes_key   = HKDF-SHA256(ikm=entropy, salt="paramant-drop-v1", info="aes-key",   32)
//   id_bytes  = HKDF-SHA256(ikm=entropy, salt="paramant-drop-v1", info="lookup-id", 32)
//   lookup_id = SHA-256(id_bytes)            (hex; the relay storage key)
//
// then AES-256-GCM(aes_key, nonce, plaintext) with NO AAD, and
//
//   packet = nonce(12) || u32be(ct.length) || ct           (ct = ciphertext||tag)
//
// padded with random bytes to a block. This script reproduces _deriveDropKeys
// and the AEAD two ways -- WebCrypto (the relay path) and pure-Node HKDF +
// AES-256-GCM (the path Rust mirrors) -- and asserts byte-equality. STOP on any
// divergence.
//
// Run:  node scripts/derisk-paradrop.mjs

import { createHmac, createHash, createCipheriv, webcrypto } from 'node:crypto';

const subtle = webcrypto.subtle;
const hex = (u8) => Buffer.from(u8).toString('hex');
const sha256 = (u8) => createHash('sha256').update(Buffer.from(u8)).digest();
const SALT = new TextEncoder().encode('paramant-drop-v1');
const INFO_AES = new TextEncoder().encode('aes-key');
const INFO_ID = new TextEncoder().encode('lookup-id');

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
const u32be = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n, 0); return b; };

async function webcryptoDrop(entropy, nonce, plaintext) {
  const base = await subtle.importKey('raw', entropy, { name: 'HKDF' }, false, ['deriveKey', 'deriveBits']);
  const aesKey = await subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: SALT, info: INFO_AES }, base,
    { name: 'AES-GCM', length: 256 }, true, ['encrypt']);
  const rawKey = new Uint8Array(await subtle.exportKey('raw', aesKey));
  const idBytes = new Uint8Array(await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: SALT, info: INFO_ID }, base, 256));
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: nonce }, aesKey, plaintext)); // NO additionalData
  return { rawKey, lookupId: hex(sha256(idBytes)), ct };
}
function nodeDrop(entropy, nonce, plaintext) {
  const prk = hkdfExtract(SALT, entropy);
  const aesKey = hkdfExpand(prk, INFO_AES, 32);
  const idBytes = hkdfExpand(prk, INFO_ID, 32);
  const c = createCipheriv('aes-256-gcm', Buffer.from(aesKey), Buffer.from(nonce)); // no setAAD
  const ct = new Uint8Array(Buffer.concat([c.update(Buffer.from(plaintext)), c.final(), c.getAuthTag()]));
  return { rawKey: aesKey, lookupId: hex(sha256(idBytes)), ct };
}

const CASES = [
  { id: 'pd-empty', ptLen: 0 },
  { id: 'pd-short', ptLen: 9 },
  { id: 'pd-block', ptLen: 1024 },
  { id: 'pd-large', ptLen: 40000 },
];

let allOk = true;
for (const { id, ptLen } of CASES) {
  const entropy = bytesFrom(`paramant/drop/${id}/entropy`, 16);
  const nonce = bytesFrom(`paramant/drop/${id}/nonce`, 12);
  const plaintext = bytesFrom(`paramant/drop/${id}/pt`, ptLen);
  const a = await webcryptoDrop(entropy, nonce, plaintext);
  const b = nodeDrop(entropy, nonce, plaintext);
  const ok = hex(a.rawKey) === hex(b.rawKey) && a.lookupId === b.lookupId && hex(a.ct) === hex(b.ct);
  allOk &&= ok;
  const packet = new Uint8Array(Buffer.concat([Buffer.from(nonce), u32be(b.ct.length), Buffer.from(b.ct)]));
  console.log(`${id}: key=${hex(a.rawKey) === hex(b.rawKey) ? 'OK' : 'BAD'} ` +
    `lookup=${a.lookupId === b.lookupId ? 'OK' : 'BAD'} ct=${hex(a.ct) === hex(b.ct) ? 'OK' : 'BAD'} ` +
    `packetLen=${packet.length} packetSha=${hex(sha256(packet)).slice(0, 16)} lookupId=${b.lookupId.slice(0, 12)}`);
}

if (!allOk) {
  console.error('\nDE-RISK FAILED: ParaDrop path diverges. Do NOT write Rust.');
  process.exit(1);
}
console.log('\nDE-RISK OK: ParaDrop _deriveDropKeys + AES-256-GCM (no AAD) == WebCrypto == pure-Node.');
