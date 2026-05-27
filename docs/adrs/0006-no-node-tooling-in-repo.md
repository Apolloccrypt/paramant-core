# 0006. No Node tooling in the repo

Datum: 2026-05-27
Status: Geaccepteerd

## Context

KAT-vector extraction uses `@noble/post-quantum`, a Node package. A parallel CLI
session installed it with `npm install` inside `scripts/`, and a `git add -A`
(commit `e3dc8ea`) then committed `scripts/package.json`,
`scripts/package-lock.json`, and 308 files under `scripts/node_modules/`, plus a
duplicate crate-local `crates/paramant-core/tests/kat/`.

## Beslissing

Node tooling lives **outside** the repo:

- `scripts/extract-kat.mjs` reads the `NOBLE_PQ_MLKEM` env var pointing at a
  pre-installed `@noble/post-quantum` checkout (e.g. under `/tmp`).
- `scripts/README.md` documents the one-time setup.
- A pre-commit hook (`.githooks/pre-commit`, wired via `core.hooksPath`) refuses
  to stage `package.json`, `package-lock.json`, `yarn.lock`, anything under
  `node_modules/`, or crate-local `tests/kat/` paths.
- `.gitignore` reinforces this at the working-tree level.
- **Never `git add -A` / `git add .`**  --  always explicit paths. This was the
  proximate cause of the incident.

## Consequenties

Contributors install `@noble` out-of-tree (slight onboarding friction) in
exchange for no repo bloat, no lockfile churn, and no supply-chain artifacts in
source. KAT vectors themselves (`tests/kat/*.json`) are committed; the generator
inputs are not.

## Alternatieven

- **In-tree `node_modules`**: rejected  --  hundreds of files, lockfile metadata,
  supply-chain surface in a Rust-first repo.
- **npm workspace / monorepo**: rejected  --  paramant-core is Rust-first; Node is
  incidental tooling.
- **Git submodule for tooling**: rejected  --  overcomplicates a simple
  "install once, set one env var" workflow.
