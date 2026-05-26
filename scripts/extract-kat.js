// Generate Known Answer Test vectors for paramant-core's ML-KEM-768 from the
// exact primitive paramant-relay 2.5.0 ships: @noble/post-quantum `ml_kem768`.
//
// Strategy (see docs/adrs/0005-kem-kat-strategy.md): the `oqs` crate does not
// expose liboqs' derandomised entry points, so paramant-core cannot replay a
// keygen/encaps seed. We therefore prove parity on the *deterministic* operation
// — decapsulation — by fixing noble-produced (pk, sk, ct, ss) tuples and having
// the Rust test assert oqs `decaps(sk, ct) == ss` byte-for-byte. Seeds are still
// recorded so this file regenerates identically.
//
// Run:  cd scripts && npm install && node extract-kat.js
// Out:  ../crates/paramant-core/tests/kat/ml-kem-768.json

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { ml_kem768 } = require("@noble/post-quantum/ml-kem.js");

const COUNT = 30;
const OUT = path.join(
  __dirname,
  "..",
  "crates",
  "paramant-core",
  "tests",
  "kat",
  "ml-kem-768.json",
);

// Exact version of the primitive, read straight from disk (noble's `exports`
// map hides ./package.json from require()).
const nobleVersion = JSON.parse(
  fs.readFileSync(
    path.join(__dirname, "node_modules", "@noble", "post-quantum", "package.json"),
    "utf8",
  ),
).version;

// Deterministic, well-distributed seeds. d||z keygen seed = 64 bytes; encaps
// message = 32 bytes. Derived by hashing a fixed label with the vector index.
const keygenSeed = (i) =>
  crypto.createHash("sha512").update(`paramant-core ml-kem-768 keygen ${i}`).digest();
const encapsMsg = (i) =>
  crypto.createHash("sha256").update(`paramant-core ml-kem-768 encaps ${i}`).digest();

const hex = (u8) => Buffer.from(u8).toString("hex");

// Optional fidelity check: run the actual relay 2.5.0 wrapper and confirm it
// agrees byte-for-byte. Skipped (with a warning) if the relay checkout or its
// node_modules are not reachable — the version pin already guarantees the
// primitive is identical. Point RELAY_MLKEM768 at the wrapper to enable it.
function loadRelayWrapper() {
  const p =
    process.env.RELAY_MLKEM768 ||
    "/home/mick/paramant-audit/repo/relay/crypto/impls/mlkem768.js";
  try {
    // Make the wrapper's bare `require("@noble/...")` resolve to our pinned copy.
    require("module").Module._initPaths();
    process.env.NODE_PATH = path.join(__dirname, "node_modules");
    require("module").Module._initPaths();
    return require(p);
  } catch (e) {
    console.warn(`! relay wrapper sanity-check skipped (${e.code || e.message})`);
    return null;
  }
}

function main() {
  const relay = loadRelayWrapper();
  const vectors = [];

  for (let i = 0; i < COUNT; i++) {
    const seed = keygenSeed(i);
    const msg = encapsMsg(i);

    const { publicKey, secretKey } = ml_kem768.keygen(seed);
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey, msg);

    // Self-check: noble decaps recovers the same secret it just encapsulated.
    const back = ml_kem768.decapsulate(cipherText, secretKey);
    if (!Buffer.from(back).equals(Buffer.from(sharedSecret))) {
      throw new Error(`noble decaps mismatch on vector ${i}`);
    }

    // Fidelity check against relay 2.5.0's actual wrapper, if available.
    if (relay) {
      const r = relay.decapsulate(cipherText, secretKey);
      if (!Buffer.from(r).equals(Buffer.from(sharedSecret))) {
        throw new Error(`relay wrapper decaps mismatch on vector ${i}`);
      }
    }

    vectors.push({
      test_id: `kem-${String(i).padStart(3, "0")}`,
      input: { keygen_seed_hex: hex(seed), encaps_msg_hex: hex(msg) },
      expected: {
        public_key_hex: hex(publicKey),
        secret_key_hex: hex(secretKey),
        ciphertext_hex: hex(cipherText),
        shared_secret_hex: hex(sharedSecret),
      },
    });
  }

  const doc = {
    primitive: "ml-kem-768",
    source: `paramant-relay build 2.5.0 (@noble/post-quantum ml_kem768 v${nobleVersion})`,
    strategy:
      "decaps parity — see docs/adrs/0005-kem-kat-strategy.md. Vectors fix noble-produced (pk, sk, ct, ss); the Rust test asserts oqs decapsulation equals shared_secret byte-for-byte. Keygen is not seed-reproducible through oqs.",
    vectors,
  };

  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, JSON.stringify(doc, null, 2) + "\n");
  console.log(
    `wrote ${vectors.length} vectors -> ${path.relative(path.join(__dirname, ".."), OUT)}` +
      `\nprimitive: ${doc.source}` +
      `\nrelay wrapper cross-check: ${relay ? "PASS" : "skipped"}`,
  );
}

main();
