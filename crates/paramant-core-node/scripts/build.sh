#!/usr/bin/env bash
# Build the @paramant/core native addons for the published platforms.
#
# Requires the napi CLI, kept OUT of the repo per ADR-0006 (install once):
#   npm install -g @napi-rs/cli      # provides `napi`
# and, for the aarch64 target, a cross linker (e.g. gcc-aarch64-linux-gnu) plus
#   rustup target add aarch64-unknown-linux-gnu
#
# liboqs/aws-lc-rs build deps (cmake, ninja, clang) must be present, as for the
# rest of the workspace.
set -euo pipefail

cd "$(dirname "$0")/.."

napi build --release --platform --target x86_64-unknown-linux-gnu
napi build --release --platform --target aarch64-unknown-linux-gnu

echo "built: $(ls ./*.node 2>/dev/null | tr '\n' ' ')"
