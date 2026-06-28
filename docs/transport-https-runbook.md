# Transport HTTPS runbook (Phase 1)

This runbook implements [ADR-0022](adrs/0022-transport-layer-https-hardening.md)
**Phase 1** in the **paramant-relay** repo on a DEV host first (same discipline
as [deploy-bridge.md](deploy-bridge.md): no customer traffic until soak passes).

paramant-core is not modified.

## 0. Prerequisites

- Docker Compose fleet running (5 sector relays + admin).
- DNS A/AAAA records for `paramant.app` and sector hostnames pointing at the
  relay host.
- Ports **443/tcp** and **443/udp** (QUIC) open on the host firewall.

## 1. Add Caddy as TLS terminator

Create `Caddyfile` at the relay repo root:

```caddyfile
{
    # Enable HTTP/3 (QUIC). Caddy obtains certs via ACME automatically.
    servers {
        protocols h1 h2 h3
    }
}

paramant.app {
    reverse_proxy relay:3000

    header {
        Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        Referrer-Policy "strict-origin-when-cross-origin"
        # Tighten per-route once frontend asset hashes are pinned:
        # Content-Security-Policy "default-src 'self'; ..."
    }
}

# Repeat per sector hostname, or use a wildcard if DNS supports it:
# sector-eu.paramant.app { reverse_proxy sector-eu:3000 }
```

Add a `caddy` service to `docker-compose.yml`:

```yaml
  caddy:
    image: caddy:2-alpine
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
      - "443:443/udp"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy_data:/data
      - caddy_config:/config
    depends_on:
      - relay

volumes:
  caddy_data:
  caddy_config:
```

Remove public port bindings from the Node.js `relay` service (keep it on the
internal Docker network only).

## 2. Relay security headers (defense in depth)

Even with Caddy, set the same headers in the Node.js middleware so direct
internal access (admin, health checks) inherits the policy:

```js
app.use((_req, res, next) => {
  res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});
```

## 3. Verify

| Check | Command / expectation |
|-------|----------------------|
| TLS 1.3 only | `openssl s_client -connect paramant.app:443 -tls1_2` must fail |
| HTTP/3 | `curl --http3-only -I https://paramant.app/health` returns 200 |
| HSTS | Response includes `Strict-Transport-Security` |
| Internal plain HTTP | `curl http://relay:3000/health` works inside Docker; not reachable from WAN |
| Existing soak | M5b timer: zero DOWN, zero `ml-kem-768=false`, empty errors log |
| Wire format | No crypto or API changes; interop and relay test suite green |

## 4. Monitoring additions

Extend the existing systemd soak timer (116.203.86.81) with:

- **Cert expiry**: alert 14 days before `notAfter` (Caddy renews at ~30 days;
  alert catches ACME failures).
- **TLS telemetry**: weekly `testssl.sh` or SSL Labs scan on DEV; record cipher
  suite and TLS version in deploy notes.

## 5. Rollback

```sh
docker compose stop caddy
# Re-expose relay port 443 directly (previous compose binding)
docker compose up -d relay
```

No data migration: envelopes and wire format are unchanged.

## 6. Phase 2+ (not in this runbook)

- Hybrid KEM promotion and NAPI export: paramant-core (ADR-0010, ADR-0022).
- SDK certificate pinning: paramant-relay `sdk-js`.
- PQ-TLS pilot: revisit after M9 audit scope includes transport.
