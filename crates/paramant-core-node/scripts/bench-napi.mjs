// Throughput benchmark for @paramant/core (the napi binding).
//
// Measures ops/sec for the operations a paramant-relay endpoint runs through the
// binding. The binding executes the identical compiled paramant-core code as a
// native call, so the only delta vs native is N-API marshalling; this reports
// the binding's absolute throughput to confirm it is production-adequate.
//
// Usage:  PARAMANT_ADDON=/path/to/paramant-core.node node scripts/bench-napi.mjs

import { createRequire } from 'node:module';

const addonPath = process.env.PARAMANT_ADDON;
if (!addonPath) {
  console.error('set PARAMANT_ADDON to the built .node addon');
  process.exit(2);
}
const core = createRequire(import.meta.url)(addonPath);

function bench(name, fn, iters) {
  fn(); // warm up
  const t0 = process.hrtime.bigint();
  for (let i = 0; i < iters; i++) fn();
  const ns = Number(process.hrtime.bigint() - t0);
  const opsSec = (iters / ns) * 1e9;
  console.log(`${name.padEnd(22)} ${Math.round(opsSec).toLocaleString().padStart(12)} ops/sec  (${iters} iters)`);
  return opsSec;
}

const kp = core.kemKeygen();
const enc = core.kemEncaps(kp.publicKey);
const sk = core.mldsaKeygen();
const msg = Buffer.from('paramant relay endpoint payload');
const sig = core.mldsaSign(sk.secretKey, msg);
const key = Buffer.alloc(32, 1);
const nonce = Buffer.alloc(12, 2);
const aad = Buffer.alloc(14, 3);
const pt1k = Buffer.alloc(1024, 4);

console.log('@paramant/core NAPI throughput:\n');
bench('kemKeygen', () => core.kemKeygen(), 10000);
bench('kemEncaps', () => core.kemEncaps(kp.publicKey), 10000);
bench('kemDecaps', () => core.kemDecaps(kp.secretKey, enc.ciphertext), 10000);
bench('mldsaSign', () => core.mldsaSign(sk.secretKey, msg), 5000);
bench('mldsaVerify', () => core.mldsaVerify(sk.publicKey, msg, sig), 10000);
bench('aeadEncrypt(1KiB)', () => core.aeadEncrypt(key, nonce, aad, pt1k), 50000);
