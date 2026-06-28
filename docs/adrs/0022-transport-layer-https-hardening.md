# 0022. Transport-layer HTTPS hardening (next-level HTTPS)

Date: 2026-06-28
Status: Proposed

## Context

Paramant's confidentiality model is **application-layer**: ML-KEM-768 (or hybrid
KEM), AES-256-GCM, and ML-DSA-65 envelopes protect user data even when the
relay operator is malicious ([threat-model.md](../threat-model.md)). HTTPS is
still essential: it protects routing metadata, API authentication tokens, billing
callbacks, and admin surfaces. Today production runs on paramant-relay (Node.js)
behind Docker on Hetzner; TLS termination is not governed by paramant-core.

paramant-core already ships a **hybrid KEM** (ML-KEM-768 + ECDH P-256) per
`draft-ietf-tls-hybrid-design` ([ADR-0010](0010-hybrid-kem-construction.md)), but
it is experimental and not on any live envelope path. Post-quantum TLS at the
transport layer reuses the same primitive family, giving defense-in-depth without
replacing envelope crypto.

This ADR scopes **transport hardening** across repos. Implementation lives
primarily in paramant-relay and its reverse proxy; paramant-core supplies PQ
primitives when PQ-TLS is adopted.

## Decision

Adopt a **three-phase transport strategy**:

### Phase 1 -- Baseline+ (now, paramant-relay)

Terminate TLS at a **reverse proxy** (Caddy preferred; Traefik acceptable). The
Node.js relay listens on plain HTTP on an internal Docker network only.

| Control | Requirement |
|---------|-------------|
| TLS version | TLS 1.3 only (TLS 1.2 disabled at proxy) |
| Certificates | Automated ACME (Let's Encrypt); expiry alerting |
| HTTP | HTTP/3 + QUIC enabled at proxy; HTTP/2 fallback |
| Headers | HSTS (preload-ready), CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy` |
| Edge | Rate limiting and DDoS protection (Cloudflare or proxy-native) |
| Monitoring | Cert expiry, TLS version/cipher telemetry, `/health` soak (existing M5b timer) |

paramant-core is **not** modified in Phase 1. See
[transport-https-runbook.md](../transport-https-runbook.md) for the relay-side
procedure.

### Phase 2 -- PQ transport readiness (M7--M8, cross-repo)

Before enabling PQ-TLS in production:

1. Promote hybrid KEM from experimental to **production-ready** in paramant-core:
   cross-implementation KAT, NAPI export, soak on a DEV sector.
2. Implement **PSS (pre-shared secret)** hardening on Send envelopes (deferred in
   [envelope-send.md](../envelope-send.md); relay-MITM layer).
3. Add **certificate pinning** in native SDK clients (paramant-relay `sdk-js` /
   mobile bindings).

PQ-TLS itself is **optional in Phase 2**; pinning and PSS deliver value without
waiting for OpenSSL 3.5+ / managed PQ-TLS.

### Phase 3 -- PQ-TLS pilot (M9+, post-audit)

Pilot **hybrid PQ-TLS** (ML-KEM-768 + ECDH P-256) on one sector relay after M9
external audit scope includes transport boundaries.

| Option | When to choose |
|--------|----------------|
| **Managed edge** (Cloudflare PQ-TLS) | Fastest path; acceptable for GA if audit agrees |
| **OpenSSL 3.5+ / BoringSSL** at proxy | Self-hosted control; aligns with ADR-0010 combiner |
| **rustls PQ extensions** | Only if relay stack moves to Rust TLS (not planned per blueprint) |

Envelope algorithms stay on **single ML-KEM-768** for ParaShare/Send until a
separate envelope ADR approves hybrid on the application layer. Transport PQ and
application PQ are independent choices.

### Out of scope (unchanged)

- Rewriting paramant-relay HTTP in Rust ([BLUEPRINT.md](../../BLUEPRINT.md) section 6).
- Embedding a TLS stack inside paramant-core (transport != application crypto).
- Replacing envelope security with TLS alone (violates zero-knowledge relay model).

## Consequences

- **paramant-relay** owns Phase 1 proxy config, security headers, and Docker
  networking changes. No wire-format or crypto changes.
- **paramant-core** owns hybrid KEM promotion (Phase 2 prerequisite for PQ-TLS).
- **Audit scope (M9)** must explicitly cover: TLS termination, header policy,
  certificate lifecycle, and the boundary between transport and envelope crypto.
- Phase 1 can ship during the active M5b soak without touching `@paramant/core`.
- PQ-TLS adds handshake bytes and CPU; benchmark on a DEV sector before fleet-wide
  rollout (same discipline as M5b).

## Alternatives

- **Node.js `https` module with manual certs**: rejected -- no HTTP/3, manual
  renewal, TLS concerns mixed into application code.
- **TLS termination only at Cloudflare with no origin TLS**: rejected for admin
  and inter-relay traffic; internal network must not carry plaintext API tokens.
- **Hybrid KEM on envelopes now**: rejected -- larger artifacts, no cross-impl KAT
  yet; transport PQ gives earlier defense-in-depth with smaller blast radius.
- **Single PQ KEM (no classical hybrid) in TLS**: rejected -- same rationale as
  ADR-0010; hybrid resilience while PQ confidence matures.

## Milestone mapping

| Phase | Blueprint anchor | Owner repo |
|-------|------------------|------------|
| 1 Baseline+ | Parallel to M5b soak / M7 | paramant-relay |
| 2 PQ readiness | M7--M8 | paramant-core + relay SDK |
| 3 PQ-TLS pilot | M9--M11 | paramant-relay + proxy |
