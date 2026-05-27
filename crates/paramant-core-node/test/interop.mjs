// Interop test for @paramant/core (the napi binding).
//
// Two kinds of check:
//   1. Cross-implementation: the binding reproduces the relay-anchored KAT
//      vectors in tests/kat/ (the same @noble/relay anchors paramant-core uses),
//      proving @paramant/core is byte-compatible with paramant-relay.
//   2. Self round-trips: every encrypt/decrypt and keygen/sign/verify pair the
//      binding exposes round-trips correctly.
//
// Usage:  PARAMANT_ADDON=/path/to/paramant-core.node node test/interop.mjs

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createRequire } from 'node:module';

const here = dirname(fileURLToPath(import.meta.url));
const katDir = join(here, '..', '..', '..', 'tests', 'kat');
const addonPath = process.env.PARAMANT_ADDON;
if (!addonPath) {
  console.error('set PARAMANT_ADDON to the built .node addon');
  process.exit(2);
}
const core = createRequire(import.meta.url)(addonPath);

const kat = (name) => JSON.parse(readFileSync(join(katDir, `${name}.json`), 'utf8')).vectors;
const hb = (h) => Buffer.from(h, 'hex');
let checks = 0;
function assert(cond, msg) {
  if (!cond) {
    console.error(`FAIL: ${msg}`);
    process.exit(1);
  }
  checks++;
}

// 1a. ML-KEM-768: decaps(secret_key, ciphertext) == shared_secret (vs @noble).
for (const v of kat('ml-kem-768')) {
  const ss = core.kemDecaps(hb(v.expected.secret_key_hex), hb(v.expected.ciphertext_hex));
  assert(ss.toString('hex') === v.expected.shared_secret_hex, `kem decaps ${v.test_id}`);
}

// 1b. AES-256-GCM: encrypt(key, nonce, aad, pt) == ciphertext||tag (vs @noble).
for (const v of kat('aes-256-gcm')) {
  const ct = core.aeadEncrypt(hb(v.input.key_hex), hb(v.input.nonce_hex), hb(v.input.aad_hex), hb(v.input.plaintext_hex));
  assert(ct.toString('hex') === v.expected.ciphertext_hex, `aead encrypt ${v.test_id}`);
}

// 1c. ML-DSA-65: verify(public_key, msg, signature) accepts @noble signatures.
for (const v of kat('ml-dsa-65')) {
  assert(core.mldsaVerify(hb(v.expected.public_key_hex), hb(v.input.msg_hex ?? v.input.message_hex ?? ''), hb(v.expected.signature_hex)) === true,
    `mldsa verify ${v.test_id}`);
}

// 2. Self round-trips through the binding.
{
  const kp = core.kemKeygen();
  const enc = core.kemEncaps(kp.publicKey);
  assert(Buffer.compare(core.kemDecaps(kp.secretKey, enc.ciphertext), enc.sharedSecret) === 0, 'kem roundtrip');

  const sk = core.mldsaKeygen();
  const msg = Buffer.from('paramant napi interop');
  const sig = core.mldsaSign(sk.secretKey, msg);
  assert(core.mldsaVerify(sk.publicKey, msg, sig) === true, 'mldsa roundtrip');

  const key = Buffer.alloc(32, 7);
  const nonce = Buffer.alloc(12, 9);
  const aad = Buffer.from('hdr');
  const pt = Buffer.from('the quick brown fox');
  const ct = core.aeadEncrypt(key, nonce, aad, pt);
  assert(Buffer.compare(core.aeadDecrypt(key, nonce, aad, ct), pt) === 0, 'aead roundtrip');

  const rcpt = core.kemKeygen();
  const sblob = core.sendEncrypt(rcpt.publicKey, kp.publicKey, pt, 8192);
  assert(sblob.length === 8192, 'send pad');
  assert(Buffer.compare(core.sendDecrypt(rcpt.secretKey, sblob), pt) === 0, 'send roundtrip');

  const signer = core.mldsaKeygen();
  const pblob = core.parashareEncrypt(rcpt.publicKey, signer.secretKey, signer.publicKey, pt, 16384);
  const opened = core.parashareDecrypt(rcpt.secretKey, pblob);
  assert(Buffer.compare(opened.plaintext, pt) === 0, 'parashare roundtrip');
  assert(Buffer.compare(opened.senderPub, signer.publicKey) === 0, 'parashare sender_pub');

  const drop = core.paradropDrop(pt, 4096);
  assert(drop.mnemonic.split(' ').length === 12, 'paradrop mnemonic');
  assert(Buffer.compare(core.paradropPickup(drop.mnemonic, drop.blob), pt) === 0, 'paradrop roundtrip');
}

console.log(`interop OK: ${checks} checks passed (KEM/AEAD/ML-DSA vs relay KAT + all envelope round-trips)`);
