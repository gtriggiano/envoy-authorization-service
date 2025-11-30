# IP Match Database Controller `ip-match-database`

## Overview

`ip-match-database` checks whether the client IP exists in an external data source (Redis or PostgreSQL) and reports the result as a `MatchVerdict`. The policy engine decides whether a match should allow or block the request (e.g., `!blocklist` or `allowlist && !blocklist`). The controller no longer exposes an `action` setting.

## Features

- Redis and PostgreSQL backends
- Optional TTL-based in-memory cache
- TLS support for both backends
- Configurable failure handling (`alwaysDenyOnDbUnavailable`)
- Prometheus metrics for queries, cache, and availability

## Configuration Examples

### Redis Blocklist

```yaml
matchControllers:
  - name: scraper-blocker
    type: ip-match-database
    settings:
      cache:
        ttl: 10m
      database:
        type: redis
        connectionTimeout: 200ms
        redis:
          keyPrefix: "scraper:"
          host: redis.example.com
          port: 6379
          db: 0

authorizationPolicy: "!scraper-blocker"
```

### PostgreSQL Allowlist

```yaml
matchControllers:
  - name: partner-allow
    type: ip-match-database
    settings:
      alwaysDenyOnDbUnavailable: true   # fail closed on DB errors
      cache:
        ttl: 15m
      database:
        type: postgres
        connectionTimeout: 500ms
        postgres:
          query: "SELECT 1 FROM trusted_ips WHERE ip = $1 LIMIT 1"
          host: postgres.example.com
          port: 5432
          databaseName: security
          usernameEnv: POSTGRES_USER
          passwordEnv: POSTGRES_PASSWORD

authorizationPolicy: "partner-allow"
```

## Settings Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `alwaysDenyOnDbUnavailable` | bool | No | Treat database errors as matches (fail closed). |
| `cache` | object | No | TTL cache configuration (`ttl` duration). |
| `database` | object | Yes | Backend configuration. |

### Database

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | `redis` or `postgres`. |
| `connectionTimeout` | string | No | Query timeout (default `500ms`). |
| `redis` | object | When type is `redis` | Host, port, db, optional credentials/TLS, `keyPrefix`. |
| `postgres` | object | When type is `postgres` | SQL `query` with `$1` placeholder, host, port, db name, credentials (`usernameEnv`, `passwordEnv`), optional pool and TLS settings. |

## Metrics

Metrics are published under the `envoy_authz_ip_match_database` subsystem for requests, queries, cache usage, and availability.
