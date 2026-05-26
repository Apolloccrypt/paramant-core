# Contributing to paramant-core

paramant-core is the post-quantum cryptographic core of Paramant. It is
security-critical and audited code. Contributions are welcome, but the bar is
high and deliberate. **Less is more** — see [ADR-0004](docs/adrs/0004-code-minimization.md).

## Ground rules

- **Conventional Commits.** `feat:`, `fix:`, `docs:`, `test:`, `ci:`, `chore:`,
  `perf:`, `refactor:`. One logical change per commit.
- **Signed-off commits.** Every commit must carry a DCO sign-off:
  `git commit --signoff`. By signing off you certify the
  [Developer Certificate of Origin](https://developercertificate.org/).
- **CI must be green.** `cargo check`, `cargo test`, `cargo clippy -- -D warnings`,
  `cargo fmt -- --check`, `cargo audit`, and `cargo deny check` all pass.

## Documentation is part of the change

- Rustdoc on **every** `pub` item, with an example where it aids understanding.
- `cargo doc --no-deps` renders without warnings.
- Update `CHANGELOG.md` under `## [Unreleased]` with the right type
  (Added/Changed/Fixed/Removed/Security).
- Any architectural decision gets an ADR in `docs/adrs/NNNN-title.md`
  (template in [docs/doc-conventions.md](docs/doc-conventions.md)).

## Safety rules

- **No `unsafe`** without a `// SAFETY:` comment *and* a referenced ADR
  justifying it. The default answer is no.
- Secret material uses `zeroize::Zeroizing<T>` (handled inline per module, no
  `secret.rs`); never log or `Debug`-print it.
- Constant-time comparisons via `subtle` wherever a timing side-channel matters.
- No new dependency without a one-line justification in the PR and, for anything
  on a security path, an ADR. The banned list (no `tokio`, `anyhow`, `tracing`,
  `clap`, `rayon` in the core) is in the blueprint §4.

## PR process

1. Branch from `main`.
2. Make the change with tests + docs.
3. Open a PR describing *what* and *why*.
4. CI passes, one approving review, then squash-or-rebase merge.

Reports of security issues do **not** go through public PRs — see
[SECURITY.md](SECURITY.md).
