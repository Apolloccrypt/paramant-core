# Security Policy

paramant-core is post-quantum cryptographic code. We take vulnerabilities
seriously and welcome coordinated disclosure.

## Reporting a vulnerability

Email **privacy@paramant.app**. Encrypt sensitive reports to our age public key:

```
# age public key (placeholder — replace before public launch / M8)
age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsplaceholder
```

Please include:

- The affected version / commit.
- A description of the issue and its impact.
- Steps to reproduce, ideally a minimal proof of concept.
- Any suggested remediation.

Do **not** open a public GitHub issue or pull request for a security problem.

## What to expect

- **Acknowledgement** within 3 business days.
- **Triage and severity assessment** within 10 business days.
- **Coordinated disclosure**: we agree a timeline with you, default 90 days, and
  credit you in the advisory and `CHANGELOG.md` unless you prefer otherwise.

## Scope

In scope: the cryptographic primitives, wire format, envelope logic, and the
Secret-handling in this repository.

Out of scope: the `paramant-relay` service (its own
[SECURITY.md](https://github.com/Apolloccrypt/paramant-relay/blob/main/SECURITY.md)),
third-party dependencies (report upstream; we track advisories via `cargo audit`
and `cargo deny`), and findings that require a compromised build host or
malicious local operator already inside the trust boundary (see
[docs/threat-model.md](docs/threat-model.md)).

## Safe harbor

Good-faith research that respects user privacy, avoids service disruption, and
follows this policy will not be pursued by us as a violation of applicable
anti-hacking law. If in doubt, ask first at privacy@paramant.app.
