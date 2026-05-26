# Documentation Conventions

Documentation is part of every change, not an afterthought. Someone opening the
repo should understand what it is within 60 seconds.

## Rustdoc

- Every `pub` item (function, struct, enum, trait, module) has a rustdoc comment.
- Public APIs include a `# Examples` block that compiles as a doctest.
- Document errors (`# Errors`) and, for crypto, security-relevant notes
  (`# Security`: constant-time guarantees, secret handling).
- `cargo doc --no-deps` renders without warnings. CI enforces this.

## CHANGELOG

[Keep a Changelog](https://keepachangelog.com/) format. Every PR updates
`## [Unreleased]` under one of: **Added**, **Changed**, **Deprecated**,
**Removed**, **Fixed**, **Security**. On release the section is renamed to
`## [x.y.z] - YYYY-MM-DD`.

## Commits

Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `ci:`, `chore:`,
`perf:`, `refactor:`), one logical change each, all `--signoff` (DCO).

## Architecture Decision Records

Any non-obvious architectural choice gets an ADR in `docs/adrs/NNNN-title.md`,
numbered sequentially. Template:

```markdown
# NNNN. Title

Datum: YYYY-MM-DD
Status: Voorgesteld | Geaccepteerd | Vervangen door NNNN

## Context
What situation required this decision?

## Beslissing
What did we choose?

## Consequenties
What changes? Which options are now closed? Which open?

## Alternatieven
What did we not choose, and why not?
```

Statuses are append-only: a superseded ADR is marked `Vervangen door NNNN`
rather than deleted, so the reasoning trail stays intact.
