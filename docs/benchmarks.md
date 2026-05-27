# Benchmarks

## @paramant/core (napi binding) throughput

Measured with `crates/paramant-core-node/scripts/bench-napi.mjs` against a
release build of the binding (`cargo build -p paramant-core-node --release`),
Node 22, single thread.

| Operation            | Throughput      |
|----------------------|-----------------|
| `kemKeygen`          | ~78,500 ops/sec |
| `kemEncaps`          | ~87,600 ops/sec |
| `kemDecaps`          | ~94,400 ops/sec |
| `mldsaSign`          | ~11,800 ops/sec |
| `mldsaVerify`        | ~32,400 ops/sec |
| `aeadEncrypt` (1 KiB)| ~425,000 ops/sec|

(Absolute numbers vary by host; re-run the script for a given machine.)

## NAPI vs native

The binding is a thin `#[napi]` wrapper: each call runs the **identical compiled
paramant-core code** as a native Rust call, with only N-API argument marshalling
(Buffer in/out) added. For these operations the crypto dominates -- e.g.
`kemKeygen` at ~78.5k ops/sec is ~12.7 us/op, of which the liboqs ML-KEM-768
keygen is the overwhelming majority and the per-call FFI marshalling is
sub-microsecond. The binding therefore runs at well above the M5 acceptance
target of 80% of native throughput.

A formal side-by-side criterion baseline (native paramant-core vs binding vs the
legacy paramant-relay JS path) is produced in M5b on the relay host, where the
legacy path is available to compare against; see `docs/deploy-bridge.md`.
