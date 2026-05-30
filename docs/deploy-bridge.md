# Deploy bridge: swapping one paramant-relay endpoint onto @paramant/core

This runbook is the **M5b** procedure, run in the `paramant-relay` repo on the
DEV host (not in paramant-core). It replaces one endpoint's JS crypto with the
napi binding `@paramant/core` and verifies parity. Per Mick's guidance M5 lands
on a DEV endpoint with no customer traffic; an IoT/production endpoint waits for
M7.

## 0. Prerequisites

- A built addon. In paramant-core:
  ```
  npm install -g @napi-rs/cli            # out-of-tree, ADR-0006
  rustup target add aarch64-unknown-linux-gnu   # only for the arm64 artifact
  bash crates/paramant-core-node/scripts/build.sh
  ```
  This emits `paramant-core.<platform>.node` plus the generated `index.js`
  loader in `crates/paramant-core-node/`.
- liboqs/aws-lc-rs build deps (cmake, ninja, clang) present, as for the rest of
  the workspace.

## 1. Install the binding into paramant-relay

Initially via a local file link (no npm publish needed for DEV):

```
cd paramant-relay
npm install /abs/path/to/paramant-core/crates/paramant-core-node
# package name is @paramant/core
```

`require('@paramant/core')` then exposes: `kemKeygen`, `kemEncaps`, `kemDecaps`,
`mldsaKeygen`, `mldsaSign`, `mldsaVerify`, `aeadEncrypt`, `aeadDecrypt`,
`sendEncrypt`, `sendDecrypt`, `parashareEncrypt`, `parashareDecrypt`. All take/return Node `Buffer`s; errors throw.

## 2. Swap ONE endpoint

Pick an endpoint that does ML-KEM-768 keygen (e.g. the pubkey-provisioning
route). Replace the existing crypto call:

```js
// before: const { publicKey, secretKey } = legacyKemKeygen();
const { kemKeygen } = require('@paramant/core');
const { publicKey, secretKey } = kemKeygen();   // Buffers
```

The wire format is unchanged (the binding is byte-equivalent to the relay's
existing crypto -- verified against the shared KAT vectors in
`crates/paramant-core-node/test/interop.mjs`), so downstream encode/decode is
untouched.

## 3. Verify

- Run paramant-relay's existing test suite; it must pass unchanged.
- Run the binding interop test against the same KAT vectors:
  ```
  PARAMANT_ADDON=.../paramant-core.linux-x64-gnu.node \
    node crates/paramant-core-node/test/interop.mjs
  ```
- Soak the DEV endpoint with representative traffic and compare error rate and
  latency to the pre-swap baseline.
- Benchmark: `node crates/paramant-core-node/scripts/bench-napi.mjs` for the
  binding; compare to the legacy path on the same host (record in
  `docs/benchmarks.md`). Target: binding >= 80% of native.

## 4. Rollback

The swap is a single commit in paramant-relay. To revert:

```
git revert <swap-commit>          # restore the legacy crypto call
npm install <previous-version>    # or: npm uninstall @paramant/core
```

No wire-format change means a rollback needs no data migration: blobs produced
during the swapped window decode identically with the legacy code.

## 5. Monitoring

Watch, before and after, for the swapped endpoint:

- request error rate (5xx / crypto exceptions),
- p50/p99 latency,
- process RSS (the addon loads liboqs/aws-lc-rs once per process),
- for keygen endpoints, the rate of malformed-key downstream errors (should be
  zero -- byte-equivalence is asserted by the interop test).
