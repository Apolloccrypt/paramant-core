#!/usr/bin/env node
// Generate deterministic Known-Answer-Test vectors for paramant-core.
//
// Two sourcing strategies, by primitive:
//
//   * KEM / signatures / AEAD  --  generated from @noble/post-quantum and
//     @noble/ciphers, the FIPS implementations paramant-relay (build 2.5.0)
//     uses. paramant-core checks these byte-for-byte. See ADR-0005.
//
//   * KDF / mnemonic  --  anchored to RFC/canonical sources:
//       - HKDF (RFC 5869): pure-Node HMAC-SHA256, anchored to Appendix A
//         cases 1-3 (the generator self-checks against them on every run).
//       - Argon2id (RFC 9106): @noble/hashes, *validated against the RFC 9106
//         Appendix A vector on every run* before emitting OWASP-2024-param
//         vectors. RFC 9106 Appendix A has only one Argon2id vector, so volume
//         comes from an independent reference impl at our real params; the RFC
//         vector remains the ground-truth anchor (see kdf.rs unit test too).
//       - BIP-0039: trezor/python-mnemonic canonical vectors (out-of-tree,
//         like @noble per ADR-0006); seeds re-derived with pure-Node
//         PBKDF2-HMAC-SHA512 and asserted equal to the canonical seed.
//
// All Node tooling lives OUT of the repo (ADR-0006). Point env vars at an
// out-of-tree install; sections whose source is unavailable are skipped with a
// warning so partial regeneration works.
//
// Usage (see scripts/README.md):
//   NOBLE_PQ_MLKEM=/tmp/.../@noble/post-quantum/ml-kem.js \
//   ARGON2_SPEC=/tmp/.../@noble/hashes/argon2.js \
//   BIP39_TREZOR_VECTORS=/tmp/.../trezor-vectors.json \
//   node scripts/extract-kat.mjs

import { createHash, createHmac, createCipheriv, pbkdf2Sync } from 'node:crypto';
import { writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const mlkemSpec = process.env.NOBLE_PQ_MLKEM ?? '@noble/post-quantum/ml-kem.js';
const mldsaSpec = process.env.NOBLE_PQ_MLDSA ?? mlkemSpec.replace('ml-kem.js', 'ml-dsa.js');
const ciphersSpec =
  process.env.NOBLE_CIPHERS ?? mlkemSpec.replace('post-quantum/ml-kem.js', 'ciphers/aes.js');
const argon2Spec = process.env.ARGON2_SPEC ?? '@noble/hashes/argon2.js';
const bip39Source = process.env.BIP39_TREZOR_VECTORS ?? null;

// Lazy, fault-tolerant import: a missing out-of-tree source skips its section
// rather than aborting the whole run (ADR-0006 keeps tooling outside the repo).
async function tryImport(spec) {
  try {
    return await import(spec);
  } catch {
    return null;
  }
}
const ml_kem768 = (await tryImport(mlkemSpec))?.ml_kem768;
const ml_dsa65 = (await tryImport(mldsaSpec))?.ml_dsa65;
const gcm = (await tryImport(ciphersSpec))?.gcm;
const argon2id = (await tryImport(argon2Spec))?.argon2id;

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

// -- ML-KEM-768 (FIPS 203): decaps(secret_key, ciphertext) == shared_secret --
if (ml_kem768) {
  const COUNT = 50;
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
    source: '@noble/post-quantum (FIPS 203)  --  paramant-relay build 2.5.0',
    note: 'paramant-core verifies decaps(secret_key, ciphertext) == shared_secret byte-for-byte.',
    count: vectors.length,
    vectors,
  });
} else {
  console.warn(`skip ml-kem-768: ${mlkemSpec} not importable (set NOBLE_PQ_MLKEM)`);
}

// -- ML-DSA-65 (FIPS 204): verify(public_key, msg, signature) == true --
// Deterministic signing via extraEntropy:false (FIPS 204 deterministic variant).
if (ml_dsa65) {
  const COUNT = 50;
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
    source: '@noble/post-quantum (FIPS 204)  --  paramant-relay build 2.5.0',
    note: 'paramant-core verifies verify(public_key, msg, signature) == true byte-for-byte; deterministic signing (extraEntropy:false).',
    count: vectors.length,
    vectors,
  });
} else {
  console.warn(`skip ml-dsa-65: ${mldsaSpec} not importable (set NOBLE_PQ_MLDSA)`);
}

// -- AES-256-GCM (FIPS 197 + SP 800-38D): encrypt(key,nonce,aad,pt) == ct||tag --
// AES-GCM is deterministic given (key, nonce, aad, pt), so this is a true
// byte-equal cross-implementation KAT. Varies aad/pt lengths, including empty.
if (gcm) {
  const N = 40;
  const vectors = [];
  for (let i = 0; i < N; i++) {
    const key = bytesFrom(`paramant/aes-256-gcm/key/${i}`, 32);
    const nonce = bytesFrom(`paramant/aes-256-gcm/nonce/${i}`, 12);
    const aad = bytesFrom(`paramant/aes-256-gcm/aad/${i}`, i % 5 === 0 ? 0 : (i * 3) % 61);
    const pt = bytesFrom(`paramant/aes-256-gcm/pt/${i}`, i % 7 === 0 ? 0 : (i * 11) % 197);
    const ct = gcm(key, nonce, aad).encrypt(pt); // ciphertext || 16-byte tag
    vectors.push({
      test_id: `gcm-${String(i).padStart(3, '0')}`,
      input: {
        key_hex: hex(key),
        nonce_hex: hex(nonce),
        aad_hex: hex(aad),
        plaintext_hex: hex(pt),
      },
      expected: { ciphertext_hex: hex(ct) },
    });
  }
  write('aes-256-gcm', {
    primitive: 'aes-256-gcm',
    source: '@noble/ciphers',
    note: 'ciphertext_hex = ciphertext || tag; encrypt(key, nonce, aad, plaintext) must equal it byte-for-byte.',
    count: vectors.length,
    vectors,
  });
} else {
  console.warn(`skip aes-256-gcm: ${ciphersSpec} not importable (set NOBLE_CIPHERS)`);
}

// -- HKDF-SHA256 (RFC 5869): extract then expand --
// Pure-Node HMAC-SHA256  --  HKDF is HMAC all the way down, so no third-party
// dependency is needed and the RFC is the only authority. The generator
// self-checks against RFC 5869 Appendix A cases 1-3 before emitting.
{
  function hkdfExtract(salt, ikm) {
    // RFC 5869 Sec.2.2: an absent/empty salt is HashLen (32) zero bytes.
    const key = salt.length ? Buffer.from(salt) : Buffer.alloc(32);
    return createHmac('sha256', key).update(Buffer.from(ikm)).digest();
  }
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

  // RFC 5869 Appendix A test cases 1-3 (SHA-256), with published PRK/OKM.
  const rfc = [
    {
      ikm: '0b'.repeat(22),
      salt: '000102030405060708090a0b0c',
      info: 'f0f1f2f3f4f5f6f7f8f9',
      len: 42,
      prk: '077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5',
      okm: '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
    },
    {
      ikm: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f',
      salt: '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf',
      info: 'b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
      len: 82,
      prk: '06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244',
      okm: 'b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87',
    },
    {
      ikm: '0b'.repeat(22),
      salt: '',
      info: '',
      len: 42,
      prk: '19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04',
      okm: '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8',
    },
  ];

  const vectors = [];
  rfc.forEach((c, i) => {
    const prk = hkdfExtract(Buffer.from(c.salt, 'hex'), Buffer.from(c.ikm, 'hex'));
    const okm = hkdfExpand(prk, Buffer.from(c.info, 'hex'), c.len);
    if (hex(prk) !== c.prk) throw new Error(`HKDF RFC TC${i + 1} PRK mismatch  --  generator broken`);
    if (hex(okm) !== c.okm) throw new Error(`HKDF RFC TC${i + 1} OKM mismatch  --  generator broken`);
    vectors.push({
      test_id: `hkdf-rfc-${String(i + 1).padStart(2, '0')}`,
      input: { ikm_hex: c.ikm, salt_hex: c.salt, info_hex: c.info, length: c.len },
      expected: { prk_hex: hex(prk), okm_hex: hex(okm) },
    });
  });

  // 17 generated cases: varying IKM / salt / info / output lengths.
  for (let i = 0; i < 17; i++) {
    const ikm = bytesFrom(`paramant/hkdf/ikm/${i}`, 1 + ((i * 7) % 64));
    const salt =
      i % 4 === 0 ? new Uint8Array(0) : bytesFrom(`paramant/hkdf/salt/${i}`, 1 + ((i * 5) % 48));
    const info =
      i % 3 === 0 ? new Uint8Array(0) : bytesFrom(`paramant/hkdf/info/${i}`, 1 + ((i * 11) % 40));
    const len = 1 + ((i * 13) % 200); // 1..199 bytes (< 255*32)
    const prk = hkdfExtract(salt, ikm);
    const okm = hkdfExpand(prk, info, len);
    vectors.push({
      test_id: `hkdf-gen-${String(i).padStart(2, '0')}`,
      input: { ikm_hex: hex(ikm), salt_hex: hex(salt), info_hex: hex(info), length: len },
      expected: { prk_hex: hex(prk), okm_hex: hex(okm) },
    });
  }

  write('hkdf', {
    primitive: 'hkdf-sha256',
    source: 'RFC 5869 Appendix A (cases 1-3) + generated; pure HMAC-SHA256',
    note: 'extract(salt, ikm) == prk; expand(prk, info, length) == okm. Empty salt = 32 zero bytes (RFC 5869 Sec.2.2).',
    count: vectors.length,
    vectors,
  });
}

// -- Argon2id (RFC 9106): hash_password(pw, salt) == tag at OWASP-2024 params --
// @noble/hashes is validated against the single RFC 9106 Appendix A vector
// before any OWASP-param vectors are emitted, so a parameter-conversion bug
// (KiB vs bytes, parallelism vs lanes) in either impl is caught here.
if (argon2id) {
  // RFC 9106 Appendix A ground-truth anchor: validate the reference impl.
  {
    const got = argon2id(new Uint8Array(32).fill(1), new Uint8Array(16).fill(2), {
      t: 3,
      m: 32,
      p: 4,
      dkLen: 32,
      key: new Uint8Array(8).fill(3),
      personalization: new Uint8Array(12).fill(4),
      version: 0x13,
    });
    const RFC_9106_TAG = '0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659';
    if (hex(got) !== RFC_9106_TAG) {
      throw new Error('Argon2id reference does not match RFC 9106 Appendix A  --  refusing to emit');
    }
  }

  // OWASP 2024 Password Storage Cheat Sheet params (see ADR-0011).
  const M = 19456; // KiB
  const T = 2;
  const P = 1;
  const DK = 32;
  const N = 15;
  const vectors = [];
  for (let i = 0; i < N; i++) {
    const pw = bytesFrom(`paramant/argon2id/pw/${i}`, 8 + ((i * 3) % 33)); // 8..40 bytes
    const salt = bytesFrom(`paramant/argon2id/salt/${i}`, 16); // >= 8 bytes (Argon2 minimum)
    const tag = argon2id(pw, salt, { t: T, m: M, p: P, dkLen: DK, version: 0x13 });
    vectors.push({
      test_id: `argon2id-${String(i).padStart(2, '0')}`,
      input: { password_hex: hex(pw), salt_hex: hex(salt) },
      params: { m_kib: M, t: T, p: P, dk_len: DK, version: 19 },
      expected: { tag_hex: hex(tag) },
    });
  }
  write('argon2id', {
    primitive: 'argon2id',
    source:
      '@noble/hashes (validated vs RFC 9106 Appendix A on generation); params = OWASP 2024 m=19456 KiB, t=2, p=1',
    note: 'hash_password(pw, salt) must equal tag_hex byte-for-byte; verify_password must accept the tag and reject any flipped bit.',
    count: vectors.length,
    vectors,
  });
} else {
  console.warn(`skip argon2id: ${argon2Spec} not importable (set ARGON2_SPEC)`);
}

// -- BIP-0039 (12/18/24-word English): entropy  ->  mnemonic  ->  seed --
// trezor/python-mnemonic canonical vectors (out-of-tree per ADR-0006). Seeds
// are re-derived with pure-Node PBKDF2-HMAC-SHA512 and asserted byte-equal to
// the canonical seed, so a parse/selection error cannot slip through.
if (bip39Source) {
  const PASSPHRASE = 'TREZOR'; // the passphrase trezor's published seeds use
  function bip39Seed(mnemonic, passphrase) {
    return new Uint8Array(
      pbkdf2Sync(
        Buffer.from(mnemonic.normalize('NFKD'), 'utf8'),
        Buffer.from(('mnemonic' + passphrase).normalize('NFKD'), 'utf8'),
        2048,
        64,
        'sha512',
      ),
    );
  }
  const all = JSON.parse(readFileSync(bip39Source, 'utf8')).english; // [entropy, mnemonic, seed, xprv]
  // 15 vectors: all eight 16-byte-entropy (12-word) cases first so
  // generate_from_entropy is exercised, then the next seven (18/24-word).
  const sixteen = all.filter((r) => r[0].length === 32);
  const longer = all.filter((r) => r[0].length !== 32);
  const chosen = [...sixteen, ...longer].slice(0, 15);
  const vectors = chosen.map((r, i) => {
    const [entropy, mnemonic, canonicalSeed] = r;
    const seed = bip39Seed(mnemonic, PASSPHRASE);
    if (hex(seed) !== canonicalSeed) {
      throw new Error(`BIP-39 seed mismatch for vector ${i}  --  generator or source broken`);
    }
    return {
      test_id: `bip39-${String(i).padStart(2, '0')}`,
      input: { entropy_hex: entropy, passphrase: PASSPHRASE },
      expected: { mnemonic, seed_hex: canonicalSeed, word_count: mnemonic.split(' ').length },
    };
  });
  write('bip39', {
    primitive: 'bip39',
    source:
      'trezor/python-mnemonic canonical vectors; seed re-derived via PBKDF2-HMAC-SHA512 (RFC 2898)',
    note: 'generate_from_entropy(entropy) == mnemonic (16-byte entropy only); parse(mnemonic).to_seed("TREZOR") == seed_hex.',
    count: vectors.length,
    vectors,
  });
} else {
  console.warn('skip bip39: set BIP39_TREZOR_VECTORS to trezor vectors.json path');
}

// -- Merkle tree (RFC 6962): root + inclusion proofs --
// Pure Node SHA-256  --  RFC 6962 is the only authority and needs no third-party
// dependency. The generator self-checks against the canonical RFC 6962 roots
// (empty, 1-leaf, the 8-leaf reference tree) before emitting; the proofs it
// emits are then re-derived independently by paramant-core (Rust).
{
  const sha256 = (...parts) => {
    const h = createHash('sha256');
    for (const p of parts) h.update(Buffer.from(p));
    return new Uint8Array(h.digest());
  };
  const hashLeaf = (data) => sha256(Uint8Array.of(0x00), data);
  const hashChildren = (l, r) => sha256(Uint8Array.of(0x01), l, r);
  const splitPoint = (n) => {
    let k = 1;
    while (k * 2 < n) k *= 2;
    return k;
  };
  const mth = (lh) => {
    if (lh.length === 0) return sha256(new Uint8Array(0));
    if (lh.length === 1) return lh[0];
    const k = splitPoint(lh.length);
    return hashChildren(mth(lh.slice(0, k)), mth(lh.slice(k)));
  };
  const auditPath = (m, lh) => {
    if (lh.length === 1) return [];
    const k = splitPoint(lh.length);
    return m < k
      ? [...auditPath(m, lh.slice(0, k)), mth(lh.slice(k))]
      : [...auditPath(m - k, lh.slice(k)), mth(lh.slice(0, k))];
  };

  // RFC 6962 Sec.2.1.4 canonical reference leaves and their known roots.
  const RFC_LEAVES = [
    '',
    '00',
    '10',
    '2021',
    '3031',
    '40414243',
    '5051525354555657',
    '606162636465666768696a6b6c6d6e6f',
  ].map((s) => Uint8Array.from(Buffer.from(s, 'hex')));
  const RFC_ROOTS = {
    0: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    1: '6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d',
    8: '5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328',
  };
  for (const [n, want] of Object.entries(RFC_ROOTS)) {
    const got = hex(mth(RFC_LEAVES.slice(0, Number(n)).map(hashLeaf)));
    if (got !== want) throw new Error(`Merkle RFC root mismatch for n=${n}  --  generator broken`);
  }

  const vectorFor = (id, leaves) => {
    const lh = leaves.map(hashLeaf);
    const indices = leaves.length === 0 ? [] : [...new Set([0, leaves.length - 1])];
    return {
      test_id: id,
      input: { leaves_hex: leaves.map(hex) },
      expected: {
        tree_size: leaves.length,
        root_hash_hex: hex(mth(lh)),
        proofs: indices.map((leaf_index) => ({
          leaf_index,
          proof_hex: auditPath(leaf_index, lh).map(hex),
        })),
      },
    };
  };

  const vectors = [
    vectorFor('merkle-rfc-empty', RFC_LEAVES.slice(0, 0)),
    vectorFor('merkle-rfc-single', RFC_LEAVES.slice(0, 1)),
    vectorFor('merkle-rfc-eight', RFC_LEAVES.slice(0, 8)),
  ];
  // 17 generated trees of varying size (powers of two, off-by-one, large).
  const SIZES = [2, 3, 4, 5, 6, 7, 9, 11, 16, 17, 31, 32, 100, 127, 128, 256, 1000];
  SIZES.forEach((n, i) => {
    const leaves = Array.from({ length: n }, (_, j) => bytesFrom(`paramant/merkle/${i}/${j}`, 24));
    vectors.push(vectorFor(`merkle-gen-${String(i).padStart(2, '0')}`, leaves));
  });

  write('merkle', {
    primitive: 'merkle-rfc6962',
    source: 'RFC 6962 Sec.2.1 (self-checked roots: empty, 1-leaf, 8-leaf) + generated; pure SHA-256',
    note: 'root_hash_hex = MTH(leaves); proof_hex = inclusion proof for leaf_index. leaf = H(0x00||data), node = H(0x01||l||r).',
    count: vectors.length,
    vectors,
  });

  // -- Signed Tree Head: ML-DSA-65 over tree_size_be || timestamp_be || root --
  // Cross-impl like ml-dsa-65.json (deterministic @noble signing); paramant-core
  // reconstructs the 48-byte message and must verify the @noble signature.
  if (ml_dsa65) {
    const sthMessage = (treeSize, timestamp, root) => {
      const m = Buffer.alloc(48);
      m.writeBigUInt64BE(BigInt(treeSize), 0);
      m.writeBigUInt64BE(BigInt(timestamp), 8);
      Buffer.from(root).copy(m, 16);
      return new Uint8Array(m);
    };
    const sthVectors = [];
    for (let i = 0; i < 10; i++) {
      const treeSize = 1 + i * 3; // 1,4,7,...,28 leaves
      const leaves = Array.from({ length: treeSize }, (_, j) =>
        bytesFrom(`paramant/merkle-sth/${i}/${j}`, 16),
      );
      const root = mth(leaves.map(hashLeaf));
      const timestamp = 1_700_000_000_000 + i * 86_400_000;
      const seed = bytesFrom(`paramant/merkle-sth/seed/${i}`, 32);
      const { publicKey, secretKey } = ml_dsa65.keygen(seed);
      const message = sthMessage(treeSize, timestamp, root);
      const signature = ml_dsa65.sign(message, secretKey, { extraEntropy: false });
      sthVectors.push({
        test_id: `sth-${String(i).padStart(2, '0')}`,
        input: { leaves_hex: leaves.map(hex), tree_size: treeSize, timestamp, seed_hex: hex(seed) },
        expected: {
          public_key_hex: hex(publicKey),
          root_hash_hex: hex(root),
          message_hex: hex(message),
          signature_hex: hex(signature),
        },
      });
    }
    write('merkle-sth', {
      primitive: 'merkle-sth-ml-dsa-65',
      source: '@noble/post-quantum (FIPS 204)  --  paramant-relay build 2.5.0; RFC 6962 root',
      note: 'message = tree_size_be(8) || timestamp_be(8) || root(32); paramant-core verifies the ML-DSA-65 signature byte-for-byte.',
      count: sthVectors.length,
      vectors: sthVectors,
    });
  } else {
    console.warn(`skip merkle-sth: ${mldsaSpec} not importable (set NOBLE_PQ_MLDSA)`);
  }
}

// -- Block padding: unpad recovers the original data --
// Padding is deterministic only in the unpad direction (pad uses random filler),
// so vectors are described compactly by a recipe rather than stored in full
// (a single 5 MiB block would otherwise dominate the repo). The plaintext is the
// pattern byte_j = j % 251; the length suffix is the little-endian u32 the layout
// commits to. paramant-core rebuilds the block-aligned blob and must unpad it to
// the original `plaintext_len` bytes  --  locking the LE suffix and the block sizes.
{
  const BLOCKS = { Block4K: 4096, Block64K: 65536, Block512K: 524288, Block5M: 5242880 };
  const LEN_SUFFIX = 4;
  const selectFor = (len) => {
    const need = len + LEN_SUFFIX;
    if (need <= 4096) return 'Block4K';
    if (need <= 65536) return 'Block64K';
    if (need <= 524288) return 'Block512K';
    return 'Block5M';
  };
  const suffixLe = (n) => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n);
    return new Uint8Array(b);
  };
  // 25 lengths: empty, exact-block, boundary+/-1 across all four tiers, plus
  // multi-block 5 MiB cases.
  const LENGTHS = [
    0, 1, 100, 2048, 3000, 4000, 4091, 4092, // Block4K
    4093, 10000, 30000, 50000, 65531, 65532, // Block64K
    65533, 100000, 400000, 524283, 524284, // Block512K
    524285, 1000000, 5242876, 6000000, 7000000, 10000000, // Block5M (incl. multi-block)
  ];
  const vectors = LENGTHS.map((len, i) => {
    const scheme = selectFor(len);
    const bs = BLOCKS[scheme];
    const paddedLen = Math.ceil((len + LEN_SUFFIX) / bs) * bs;
    return {
      test_id: `padding-${String(i).padStart(2, '0')}`,
      input: {
        scheme,
        plaintext_len: len,
        padded_len: paddedLen,
        filler_byte: (i * 37 + 11) & 0xff,
      },
      expected: { length_suffix_hex: hex(suffixLe(len)) },
    };
  });
  write('padding', {
    primitive: 'block-padding',
    source: 'generated; layout = original_data || random_filler || original_length (u32 LE), block-aligned',
    note: 'Rebuild blob: bytes[0..plaintext_len] = j%251, filler = filler_byte, last 4 = length_suffix_hex (LE of plaintext_len). unpad(blob, scheme) must equal the j%251 pattern; padded_len is a multiple of the scheme block size.',
    count: vectors.length,
    vectors,
  });
}

// -- Wire format v1 (PQHB envelope): encode(fields) == blob --
// The canonical source is paramant-relay/docs/wire-format-v1.md (approved
// 2026-04-24) and relay/crypto/wire-format.js. The encoder is re-implemented
// here in pure Node and *self-checked against the two published SHA-256 anchor
// vectors* (signed 5090 B, anonymous 1778 B) before any vector is emitted, so a
// byte-level divergence from the relay is caught at generation time  --  the same
// "validate vs canonical ground truth, then emit" discipline used for HKDF,
// Argon2id and Merkle. paramant-core's wire.rs must reproduce every blob.
{
  // Each variable field is {pattern_hex, repeat}: the pattern bytes repeated
  // `repeat` times. Single-byte patterns give arbitrary lengths; multi-byte
  // patterns reproduce the relay spec's `<pattern> x N` anchor notation.
  const expand = (f) => {
    if (!f) return null;
    const p = Buffer.from(f.pattern_hex, 'hex');
    const out = Buffer.alloc(p.length * f.repeat);
    for (let i = 0; i < f.repeat; i++) p.copy(out, i * p.length);
    return new Uint8Array(out);
  };
  // Big-endian PQHB encoder, byte-for-byte equal to relay/crypto/wire-format.js.
  const encodeWire = (input) => {
    const ctKem = expand(input.ct_kem);
    const senderPub = expand(input.sender_pub);
    const signature = expand(input.signature);
    const ciphertext = expand(input.ciphertext);
    const nonce = Buffer.from(input.nonce_hex, 'hex');
    const signed = input.sig_id !== 0x0000;
    const parts = [];
    const u32be = (n) => {
      const b = Buffer.alloc(4);
      b.writeUInt32BE(n, 0);
      return b;
    };
    const header = Buffer.alloc(10);
    Buffer.from([0x50, 0x51, 0x48, 0x42]).copy(header, 0); // MAGIC "PQHB"
    header.writeUInt8(0x01, 4); // VERSION
    header.writeUInt16BE(input.kem_id, 5);
    header.writeUInt16BE(input.sig_id, 7);
    header.writeUInt8(input.flags, 9);
    parts.push(header, u32be(ctKem.length), Buffer.from(ctKem));
    parts.push(u32be(senderPub.length), Buffer.from(senderPub));
    if (signed) parts.push(u32be(signature.length), Buffer.from(signature));
    parts.push(Buffer.from(nonce), u32be(ciphertext.length), Buffer.from(ciphertext));
    return new Uint8Array(Buffer.concat(parts));
  };
  const finalize = (test_id, input) => {
    const blob = encodeWire(input);
    return {
      test_id,
      input,
      expected: { total_len: blob.length, header_hex: hex(blob.subarray(0, 10)), sha256_hex: hex(createHash('sha256').update(blob).digest()) },
    };
  };

  // Two published anchor vectors (paramant-relay docs/wire-format-v1.md Sec.Test
  // vectors). Their SHA-256 is the cross-implementation ground truth.
  const anchorSigned = finalize('wire-anchor-signed', {
    kem_id: 0x0002, sig_id: 0x0002, flags: 0x00,
    ct_kem: { pattern_hex: '00112233445566778899aabbccddeeff', repeat: 68 },
    sender_pub: { pattern_hex: 'cafe', repeat: 296 },
    signature: { pattern_hex: 'babe', repeat: 1654 },
    nonce_hex: '000102030405060708090a0b',
    ciphertext: { pattern_hex: 'deadbeef', repeat: 16 },
  });
  const anchorAnon = finalize('wire-anchor-anonymous', {
    kem_id: 0x0002, sig_id: 0x0000, flags: 0x00,
    ct_kem: { pattern_hex: '00112233445566778899aabbccddeeff', repeat: 68 },
    sender_pub: { pattern_hex: 'cafe', repeat: 296 },
    signature: null,
    nonce_hex: '000102030405060708090a0b',
    ciphertext: { pattern_hex: 'deadbeef', repeat: 16 },
  });
  const ANCHOR_SIGNED_SHA = '002b4f6aad4fa992804a3e94c46d514b4f842e9f5c283f7a31d7c76722d0476a';
  const ANCHOR_ANON_SHA = '46bce75b12e90ed312420fafcbead4108d55aa25273aee3ce4f2b4f61b3d19ef';
  if (anchorSigned.expected.total_len !== 5090 || anchorSigned.expected.sha256_hex !== ANCHOR_SIGNED_SHA) {
    throw new Error('wire-format signed anchor mismatch  --  encoder diverged from relay');
  }
  if (anchorAnon.expected.total_len !== 1778 || anchorAnon.expected.sha256_hex !== ANCHOR_ANON_SHA) {
    throw new Error('wire-format anonymous anchor mismatch  --  encoder diverged from relay');
  }

  const nonceFor = (id) => hex(createHash('sha256').update(`paramant/wire/nonce/${id}`).digest().subarray(0, 12));
  const fld = (byteHex, len) => ({ pattern_hex: byteHex, repeat: len });
  const mk = (test_id, kem_id, sig_id, ctKemLen, spLen, sigLen, ctLen) =>
    finalize(test_id, {
      kem_id, sig_id, flags: 0x00,
      ct_kem: fld('a1', ctKemLen),
      sender_pub: fld('b2', spLen),
      signature: sig_id === 0x0000 ? null : fld('c3', sigLen),
      nonce_hex: nonceFor(test_id),
      ciphertext: fld('d4', ctLen),
    });

  const SIGNED = [
    0x0001, 0x0002, 0x0003, 0x0100, 0x0101, 0x0200, 0x0201, 0x0202, 0x0203,
    0x0204, 0x0205, 0x0206, 0x0207, 0x0208, 0x0209, 0x020a, 0x020b,
  ];
  const vectors = [anchorSigned, anchorAnon];
  // Boundary / edge cases.
  vectors.push(mk('wire-edge-empty-ciphertext-anon', 0x0002, 0x0000, 1088, 592, null, 0));
  vectors.push(mk('wire-edge-empty-all-signed', 0x0001, 0x0002, 0, 0, 0, 0));
  vectors.push(mk('wire-edge-large-ml-dsa-87', 0x0003, 0x0003, 1568, 2592, 4627, 5000));
  vectors.push(mk('wire-edge-minimal-anon', 0x0001, 0x0000, 1, 1, null, 1));
  // 24 cycling combinations across every KEM and signature family.
  for (let i = 0; i < 24; i++) {
    const kemId = [0x0001, 0x0002, 0x0003][i % 3];
    const anon = i % 5 === 0;
    const sigId = anon ? 0x0000 : SIGNED[i % SIGNED.length];
    const ctKemLen = 700 + ((i * 37) % 900);
    const spLen = 100 + ((i * 53) % 1500);
    const sigLen = anon ? null : 600 + ((i * 101) % 4000);
    const ctLen = (i * 131) % 512;
    vectors.push(mk(`wire-gen-${String(i).padStart(2, '0')}`, kemId, sigId, ctKemLen, spLen, sigLen, ctLen));
  }

  write('wire-format-v1', {
    primitive: 'wire-format-v1',
    source: 'paramant-relay docs/wire-format-v1.md + relay/crypto/wire-format.js (approved 2026-04-24); signed/anonymous anchors self-checked by SHA-256',
    note: 'Expand each {pattern_hex, repeat} field, build the PQHB envelope (big-endian, length-prefixed), and assert Envelope::encode == expected (total_len, header_hex, sha256_hex) and decode then encode round-trips. SIG_ID 0x0000 omits the signature section.',
    count: vectors.length,
    vectors,
  });
}

// -- Send-mode envelope (anonymous, SIG_ID 0x0000) --
// Mirrors paramant-relay/sdk-js sendAnonymous: ML-KEM-768 encapsulation,
// HKDF-SHA256(ikm=sharedSecret, salt=ctKem[0:32], info='paramant-v1-aes-key'),
// AES-256-GCM with the 10-byte PQHB header bound as AAD. The WebCrypto vs
// pure-Node equivalence is proven in scripts/derisk-send.mjs; here pure-Node
// HMAC-HKDF + AES-256-GCM generate the vectors. ct_kem/shared_secret/secret_key
// come from @noble ML-KEM-768 (deterministic seeds)  --  paramant-core takes them
// as KAT inputs because oqs cannot derandomise encapsulation (ADR-0005), exactly
// like ml-kem-768.json. Plaintext is the j%251 pattern (compact for large cases).
if (ml_kem768) {
  const INFO = new TextEncoder().encode('paramant-v1-aes-key');
  const hkdfExtract = (salt, ikm) =>
    createHmac('sha256', salt.length ? Buffer.from(salt) : Buffer.alloc(32)).update(Buffer.from(ikm)).digest();
  const hkdfExpand = (prk, info, len) => {
    const n = Math.ceil(len / 32);
    let t = Buffer.alloc(0);
    const out = [];
    for (let i = 1; i <= n; i++) {
      t = createHmac('sha256', prk).update(Buffer.concat([t, Buffer.from(info), Buffer.from([i])])).digest();
      out.push(t);
    }
    return new Uint8Array(Buffer.concat(out).subarray(0, len));
  };
  const headerBytes = (kemId, sigId) => {
    const h = Buffer.alloc(10);
    Buffer.from([0x50, 0x51, 0x48, 0x42]).copy(h, 0);
    h.writeUInt8(0x01, 4);
    h.writeUInt16BE(kemId, 5);
    h.writeUInt16BE(sigId, 7);
    h.writeUInt8(0x00, 9);
    return h;
  };
  const u32be = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n, 0); return b; };
  const wireEncodeAnon = (kemId, ctKem, senderPub, nonce, ct) =>
    new Uint8Array(Buffer.concat([
      headerBytes(kemId, 0x0000),
      u32be(ctKem.length), Buffer.from(ctKem),
      u32be(senderPub.length), Buffer.from(senderPub),
      Buffer.from(nonce),
      u32be(ct.length), Buffer.from(ct),
    ]));
  const mkPt = (n) => { const b = Buffer.alloc(n); for (let j = 0; j < n; j++) b[j] = j % 251; return new Uint8Array(b); };

  const LENGTHS = [
    0, 1, 15, 16, 17, 31, 32, 33, 100, 255, 256, 257, 1023, 1024,
    4095, 4096, 4097, 60000, 250000, 1000000,
  ];
  const vectors = LENGTHS.map((len, i) => {
    const id = `send-${String(i).padStart(2, '0')}`;
    const seed = bytesFrom(`paramant/send/${i}/seed`, 64);
    const msg = bytesFrom(`paramant/send/${i}/msg`, 32);
    const { publicKey, secretKey } = ml_kem768.keygen(seed);
    const { cipherText: ctKem, sharedSecret } = ml_kem768.encapsulate(publicKey, msg);
    const senderPub = publicKey; // anonymous: senderPub = own KEM pubkey (opaque id)
    const nonce = bytesFrom(`paramant/send/${i}/nonce`, 12);
    const plaintext = mkPt(len);

    const aesKey = hkdfExpand(hkdfExtract(ctKem.slice(0, 32), sharedSecret), INFO, 32);
    const aad = Buffer.concat([headerBytes(0x0002, 0x0000), u32be(0)]); // header || chunk_index_be32
    const cipher = createCipheriv('aes-256-gcm', Buffer.from(aesKey), Buffer.from(nonce));
    cipher.setAAD(aad);
    const body = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
    const ct = new Uint8Array(Buffer.concat([body, cipher.getAuthTag()]));

    const core = wireEncodeAnon(0x0002, ctKem, senderPub, nonce, ct);
    return {
      test_id: id,
      input: {
        kem_id: 0x0002,
        sig_id: 0x0000,
        seed_hex: hex(seed),
        msg_hex: hex(msg),
        secret_key_hex: hex(secretKey),
        ct_kem_hex: hex(ctKem),
        shared_secret_hex: hex(sharedSecret),
        sender_pub_hex: hex(senderPub),
        nonce_hex: hex(nonce),
        plaintext: { pattern: 'mod251', len },
      },
      expected: {
        aes_key_hex: hex(aesKey),
        header_hex: hex(core.subarray(0, 10)),
        core_len: core.length,
        core_sha256_hex: hex(createHash('sha256').update(core).digest()),
      },
    };
  });

  write('envelope-send', {
    primitive: 'envelope-send',
    source: 'paramant-relay sdk-js sendAnonymous (SIG_ID 0x0000): ML-KEM-768 + HKDF-SHA256(salt=ctKem[0:32], info="paramant-v1-aes-key") + AES-256-GCM(aad=PQHB header); WebCrypto==pure-Node verified by scripts/derisk-send.mjs; ct_kem/shared_secret from @noble ML-KEM-768 (deterministic), plaintext = j%251.',
    note: 'derive_key(ct_kem, shared_secret) == aes_key_hex; seal_core(MlKem768, ct_kem, shared_secret, sender_pub, nonce, plaintext) encodes to core_len bytes with header_hex and core_sha256_hex; decaps(secret_key, ct_kem) == shared_secret links Rust oqs to @noble; open_core recovers plaintext.',
    count: vectors.length,
    vectors,
  });
} else {
  console.warn(`skip envelope-send: ${mlkemSpec} not importable (set NOBLE_PQ_MLKEM)`);
}
