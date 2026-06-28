# Next-level HTTPS for paramant-relay

This playbook translates the current `paramant-core` + `paramant-relay`
architecture into an execution backlog for transport security.

Important boundary: `paramant-core` is a crypto library, not the HTTP edge.
Most items below must be implemented in `paramant-relay` and its ingress stack.

## Goal

Raise relay transport security from "HTTPS enabled" to "defense in depth":

- TLS 1.3 only at the public edge.
- Strict browser and API transport policy (HSTS + secure defaults).
- Replay-resistant API semantics on sensitive routes.
- Optional mTLS for internal service-to-service traffic.
- Observable, testable controls with rollback-safe rollout.

## Scope and non-scope

In scope:

- Public ingress TLS policy and certificate lifecycle.
- App-level HTTP security headers and cookie policy.
- Replay defenses for sensitive `/v2/*` routes.
- Internal mTLS between trusted services.
- Operational checks and alerting.

Out of scope:

- Product-level end-to-end relay deployment steps in this repository.
- Replacing all relay business logic with Rust.
- Direct browser PKI UX changes.

## Success criteria

Ship is successful when all are true:

1. External scans show TLS 1.3 only and modern cipher suites.
2. HSTS is present on all HTTPS responses with target max-age.
3. Sensitive write endpoints reject replayed request signatures/nonces.
4. Internal service links enforce mTLS where enabled.
5. Dashboards and alerts detect cert expiry, handshake errors, and replay spikes.

## Delivery plan (phased backlog)

### Phase 0: Baseline and guardrails

| ID | Work item | Definition of done |
|---|---|---|
| H0-1 | Capture current TLS config and response headers from production and staging. | Baseline report committed in relay ops docs with command outputs and date. |
| H0-2 | Define rollback switches for each later phase. | Every phase has a one-command rollback note tested once in staging. |
| H0-3 | Add transport security acceptance checks to CI smoke jobs. | CI fails if required headers/TLS policy regress in staging smoke tests. |

### Phase 1: Public edge hardening (highest priority)

| ID | Work item | Definition of done |
|---|---|---|
| H1-1 | Enforce TLS 1.3 only on public ingress. | TLS 1.2 handshake fails, TLS 1.3 succeeds on staging and production. |
| H1-2 | Restrict ciphers to modern AEAD suites and disable weak legacy options. | External scanner grade improves and no weak-suite finding remains. |
| H1-3 | Enable OCSP stapling and strict certificate chain config. | Scanner confirms stapling and valid chain from at least two regions. |
| H1-4 | Add HSTS (`max-age=31536000; includeSubDomains`), then preload candidate after soak. | Header is present on all HTTPS responses; preload decision logged after soak. |
| H1-5 | Redirect all HTTP traffic to HTTPS with permanent redirects. | HTTP endpoint always returns 301/308 to canonical HTTPS URL. |

### Phase 2: App-layer HTTP policy

| ID | Work item | Definition of done |
|---|---|---|
| H2-1 | Standardize strict response headers (`X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, CSP where applicable). | Header contract test passes for API and frontend routes. |
| H2-2 | Harden cookies (`Secure`, `HttpOnly`, `SameSite`) and session transport assumptions. | No auth/session cookie is set without secure attributes in staging tests. |
| H2-3 | Ensure proxy trust and forwarded headers are validated and not spoofable. | Direct spoofed `X-Forwarded-*` input is rejected or ignored as designed. |

### Phase 3: Replay resistance for sensitive APIs

| ID | Work item | Definition of done |
|---|---|---|
| H3-1 | Define signed request envelope for high-risk `/v2/*` write routes (`timestamp`, `nonce`, request hash). | ADR or ops spec approved and referenced from relay docs. |
| H3-2 | Implement nonce store with bounded TTL and duplicate rejection. | Replayed signed request is rejected in integration tests and staging. |
| H3-3 | Add idempotency keys for retry-prone endpoints. | Safe retries succeed once and duplicate side effects are blocked. |
| H3-4 | Monitor replay reject metrics and alert on anomalies. | Alert fires in drill and dashboard panel exists with runbook. |

### Phase 4: Internal mTLS (service-to-service)

| ID | Work item | Definition of done |
|---|---|---|
| H4-1 | Introduce internal CA or workload identity for relay service mesh links. | Internal cert issuance + rotation documented and tested in staging. |
| H4-2 | Enforce mTLS on sector relay and admin internal paths. | Plain TLS/no-cert client is rejected on protected internal routes. |
| H4-3 | Add cert rotation automation and expiry alerting. | Rotation drill succeeds with no downtime and alerts cover expiry windows. |
| H4-4 | Pin service identity policy (SAN/CN mapping) in config tests. | Misissued identity cert is denied by policy tests. |

## Suggested implementation snippets (relay repo)

Nginx-style ingress policy skeleton:

- `ssl_protocols TLSv1.3;`
- `add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;`
- `return 308 https://$host$request_uri;` on port 80 listener.

Node/Express middleware policy skeleton:

- Set strict headers centrally with one middleware.
- Reject requests outside allowed timestamp skew for signed endpoints.
- Deduplicate nonce/idempotency key in low-latency store (for example Redis).

## Verification checklist per release

Run these checks in staging before production rollout:

1. TLS policy check with SSL scanner and `openssl s_client` probes.
2. Header contract checks via scripted `curl` tests.
3. Replay test: send same signed request twice and confirm second is rejected.
4. mTLS test (if phase 4 active): connect without client cert and expect denial.
5. Cert expiry drill: validate alert pipeline and runbook path.

## Suggested ticket order

1. H0-1, H0-2, H0-3
2. H1-1, H1-2, H1-5, H1-3, H1-4
3. H2-1, H2-2, H2-3
4. H3-1, H3-2, H3-3, H3-4
5. H4-1, H4-2, H4-3, H4-4

This order front-loads internet-facing risk reduction, then raises protocol
semantics and internal trust hardening.
