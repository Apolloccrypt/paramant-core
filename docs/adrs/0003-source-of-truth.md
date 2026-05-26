# 0003. GitHub is the source of truth

Datum: 2026-05-26
Status: Geaccepteerd

## Context

Today `paramant-relay` lives on a server and GitHub trails behind: manual
deploys, no clean history, one box between the code and data loss, not
auditable. paramant-core is a fresh start and can avoid that from commit 1.

## Beslissing

**GitHub is the single source of truth.** The server pulls released artifacts
via CI; nobody SSHes into production to change code. This is feasible because
**cryptographic code contains no secrets** — no API keys, no production `.env`
in the hot path. All environment-specific values live in GitHub Actions secrets,
Hetzner secrets, or `.env` files that are git-ignored. No exceptions.

## Consequenties

- The repository can be source-available from the first commit.
- Every change flows through PR + CI; history is clean and auditable.
- Secrets management is an operational concern, never a repository concern; a
  gitleaks pre-commit/CI hook is added before public launch.
- As relay crypto migrates here (M5–M7), the source of truth shifts with it.

## Alternatieven

- **Server-first (status quo of paramant-relay)**: rejected — fragile,
  unauditable, the very thing this project moves away from.
- **Private repo indefinitely**: not required for security (no secrets in code);
  the visibility decision is operational, not a safety constraint.
