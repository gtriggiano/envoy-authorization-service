# ASN Match Database Controller `asn-match-database`

## Overview

`asn-match-database` checks whether the client Autonomous System Number (ASN) exists in an external data source (Redis or PostgreSQL) and reports the result as a `MatchVerdict`. The controller consumes ASN information produced by the `maxmind-asn` analysis controller (or any analysis controller that emits the same report schema).

Use your authorization policy to decide whether a match allows or blocks traffic (e.g., `!asn-blocklist` for a deny list or `trusted-asn` for an allow list). The controller does **not** take an `action` setting.

## Features

- Redis and PostgreSQL backends
- Optional TTL-based in-memory cache
- TLS support for both backends
- Configurable failure handling (`matchesOnFailure`)
- Prometheus metrics for queries, cache, and availability

## Configuration Examples

### Redis ASN Blocklist

```yaml
analysisControllers:
  - name: asn-detect
    type: maxmind-asn
    settings:
      databasePath: config/GeoLite2-ASN.mmdb

matchControllers:
  - name: asn-blocklist
    type: asn-match-database
    settings:
      matchesOnFailure: false
      cache:
        ttl: 10m
      database:
        type: redis
        connectionTimeout: 200ms
        redis:
          keyPrefix: "asn:block:"
          host: redis.example.com
          port: 6379
          db: 0

authorizationPolicy: "!asn-blocklist"
```

### PostgreSQL ASN Allowlist

```yaml
analysisControllers:
  - name: asn-detect
    type: maxmind-asn
    settings:
      databasePath: config/GeoLite2-ASN.mmdb

matchControllers:
  - name: partner-asn-allow
    type: asn-match-database
    settings:
      matchesOnFailure: true   # fail open for allow-list semantics
      cache:
        ttl: 15m
      database:
        type: postgres
        connectionTimeout: 500ms
        postgres:
          query: "SELECT 1 FROM trusted_asns WHERE asn = $1 LIMIT 1"
          host: postgres.example.com
          port: 5432
          databaseName: security
          usernameEnv: POSTGRES_USER
          passwordEnv: POSTGRES_PASSWORD

authorizationPolicy: "partner-asn-allow"
```

## Settings Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `matchesOnFailure` | bool | No | Whether `IsMatch` should be `true` when the database query fails or times out. Defaults to `false`. |
| `cache` | object | No | TTL cache configuration (`ttl` duration). |
| `database` | object | Yes | Backend configuration. |

### Database

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | `redis` or `postgres`. |
| `connectionTimeout` | string | No | Query timeout (default `500ms`). |
| `redis` | object | When type is `redis` | Host, port, db, optional credentials/TLS, `keyPrefix` used to build keys like `keyPrefix + <asn>`. |
| `postgres` | object | When type is `postgres` | SQL `query` with `$1` placeholder, host, port, db name, credentials (`usernameEnv`, `passwordEnv`), optional pool and TLS settings. |

## Metrics

Metrics are published under the `envoy_authz_asn_match_database` subsystem for requests, queries, cache usage, and availability.
