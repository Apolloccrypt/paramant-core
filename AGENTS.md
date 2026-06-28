# AGENTS.md

## Cursor Cloud specific instructions

`paramant-core` is a Rust Cargo workspace (a post-quantum crypto **library**, not a
network service). There are **no long-running daemons, servers, or ports** in this
repo: "running the application" means building the workspace and running the test
suites + the NAPI binding interop check. Full product-level e2e (frontend -> relay
-> core) lives in the separate `paramant-relay` repo and cannot be exercised here.

### Standard commands
Build/test/lint commands are documented in `README.md` (Quick start) and
`.github/workflows/ci.yml`. The canonical flow is `cargo build` then
`cargo test --all` (unit + KAT vectors + proptests), plus
`cargo test -p cross-impl-validator`, `cargo fmt --all -- --check`, and
`cargo clippy --all-targets --all-features -- -D warnings`.

### Non-obvious caveats
- **Native C builds from source.** The `oqs` (liboqs) and `aws-lc-rs` (AWS-LC)
  crates compile C libraries via CMake + bindgen, so the system packages
  `cmake`, `ninja-build`, `clang`, and `libclang-dev` are mandatory (see the
  `Install liboqs build deps` step in `.github/workflows/ci.yml`). Without them
  `cargo build`/`cargo test` fail. Only `cross-impl-validator` (pure RustCrypto)
  builds without them. A clean `cargo build` takes ~40s because of these C builds.
- **Rust toolchain is pinned** to 1.95.0 via `rust-toolchain.toml` and is
  installed automatically by rustup; do not override it.
- **End-to-end "hello world" / binding check** (exercises KEM, AEAD, ML-DSA, and
  the send/parashare envelopes through the published `@paramant/core` addon):
  ```sh
  cargo build -p paramant-core-node --release
  cp target/release/libparamant_core_node.so /tmp/paramant-core.node
  PARAMANT_ADDON=/tmp/paramant-core.node node crates/paramant-core-node/test/interop.mjs
  ```
  It loads the raw `.node` cdylib directly; `@napi-rs/cli` is intentionally kept
  out of the repo (ADR-0006), so no `npm install` is needed.
- **Commit hygiene gotchas.** `.githooks/pre-commit` rejects non-ASCII typography
  in text files (use `--` not em-dash, straight quotes), `node_modules`/lockfiles,
  and stray `package.json` outside a binding crate root. Commits must use
  Conventional Commits and a DCO sign-off (`git commit --signoff`); see
  `CONTRIBUTING.md`.
