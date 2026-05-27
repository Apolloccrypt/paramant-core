# 0018. Allow binding-crate package.json manifests

Date: 2026-05-27
Status: Accepted
Amends: [ADR-0006](0006-no-node-tooling-in-repo.md)

## Context

ADR-0006 forbade every `package.json` (in the pre-commit hook and `.gitignore`)
after a parallel session accidentally `git add -A`'d KAT-generator tooling
(`scripts/node_modules/`, `scripts/package.json`, lockfiles). The blanket ban was
the simplest way to keep that bloat out.

M5 introduces `crates/paramant-core-node`, a napi-rs binding published to npm as
`@paramant/core`. A napi-rs crate intrinsically needs a `package.json` at its
root: it is the npm package manifest, `napi build` reads it, and it carries the
package name/version/binary metadata. This is not stray tooling -- it belongs to
the Rust crate as surely as its `Cargo.toml`. The blanket ban makes M5 (and the
M6 wasm binding) uncommittable.

## Decision

Loosen the ban to a path allow-list, not a generic prohibition.

**Allowed (tracked):**
- `crates/<crate>/package.json` -- a binding crate's own manifest (M5
  `paramant-core-node`, M6 `paramant-core-wasm`, future bindings).

**Still forbidden (hook rejects, `.gitignore` ignores):**
- `node_modules/` anywhere.
- `package-lock.json` and `yarn.lock` anywhere (lockfiles are not committed).
- `scripts/package.json` and any `package.json` outside a single-segment
  `crates/<crate>/` root.

The pre-commit hook checks `node_modules/`/lockfiles globally, then any
`package.json` not matching `^crates/[^/]+/package\.json$`. `.gitignore` keeps
`package.json` ignored but re-includes `!crates/*/package.json`. KAT generator
tooling still lives out-of-tree (`/tmp`, via env vars) per ADR-0006.

## Consequences

- The napi (and later wasm) binding manifests are version-controlled with their
  crate, as expected by their toolchains and by anyone publishing the package.
- The original incident class -- stray `scripts/` tooling and `node_modules`
  bloat -- stays blocked; the allow-list is narrow and explicit.
- A new binding under `crates/` is covered automatically; nothing outside
  `crates/` ever is.

## Alternatives

- **Keep the blanket ban, generate the manifest in build.sh (gitignored)**:
  rejected -- it diverges from napi-rs conventions, complicates publishing
  `@paramant/core`, and hides a real source artifact from review.
- **Drop the ban entirely**: rejected -- the ADR-0006 incident (hundreds of
  `node_modules` files) is exactly what the hook should keep preventing.
