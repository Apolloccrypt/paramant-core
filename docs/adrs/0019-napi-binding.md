# 0019. paramant-core-node: thin napi-rs binding (@paramant/core)

Date: 2026-05-27
Status: Accepted

## Context

M5 ("Bridge") connects paramant-relay (Node) to paramant-core (Rust) so the relay
runs PQ crypto through the audited core instead of its own JS. The mechanism is a
napi-rs binding crate published to npm as `@paramant/core`.

paramant-relay is a separate repo on a server, so the milestone splits:

- **M5a (this repo):** the binding crate, an interop test, a benchmark, and the
  swap runbook.
- **M5b (paramant-relay repo, Mick):** install `@paramant/core`, swap one DEV
  endpoint, soak/bench against the live legacy path.

The binding's `package.json` is permitted by [ADR-0018](0018-allow-binding-manifests.md).

## Decision

1. **Thin wrappers only.** `crates/paramant-core-node/src/lib.rs` is one `#[napi]`
   function per paramant-core public function (KEM, ML-DSA-65, AES-256-GCM, and
   the three envelope modes). Inputs/outputs are Node `Buffer`s; `CoreError`
   becomes a JS `Error`. No batching, no logic -- all crypto stays in
   paramant-core, so the binding inherits its KATs and constant-time properties.
2. **Byte-equivalence is tested against the relay anchors, not just round-trips.**
   `test/interop.mjs` runs the binding over the committed `tests/kat/` vectors
   (ML-KEM decaps, AES-GCM encrypt, ML-DSA verify -- all anchored to
   @noble/relay) plus self round-trips for every envelope mode. This proves
   `@paramant/core` produces relay-compatible bytes.
3. **CI loads the raw cdylib as a `.node`.** The `napi-interop` job builds
   `cargo build -p paramant-core-node --release` and copies the `.so` to a
   `.node` -- no `@napi-rs/cli` in CI. The napi CLI (for platform-named release
   artifacts, `scripts/build.sh`) stays out-of-tree per ADR-0006 and is only
   needed for M5b packaging.
4. **napi is minimal.** `napi`/`napi-derive` 2.16 with `default-features = false,
   features = ["napi6"]` (no async runtime); `napi-build` in build-deps.
5. **Artifacts are not committed.** `*.node` and the napi-generated `index.js`
   are gitignored; only the manifest, build script, and Rust source are tracked.

## Consequences

- The relay gets the audited core with a sub-microsecond FFI overhead
  (`docs/benchmarks.md`), comfortably above the 80%-of-native target.
- Adding a new exported function is a new thin wrapper plus an interop line; the
  binding cannot drift from the core's behaviour because it calls it directly.
- The live endpoint swap and the legacy-vs-binding benchmark are M5b, run where
  the relay lives (`docs/deploy-bridge.md`).

## Alternatives

- **Re-expose crypto logic in the binding**: rejected -- it would duplicate
  paramant-core and could diverge; the wrapper-only rule keeps one source.
- **WASM instead of napi for the relay**: rejected -- the relay is Node; WASM is
  for the browser (`paramant.app/send`, M6). Both wrap the same core.
- **Run `@napi-rs/cli` in CI**: rejected for the interop gate -- the raw cdylib
  loads as a `.node` directly; the CLI is only needed for cross-platform release
  naming (M5b).
