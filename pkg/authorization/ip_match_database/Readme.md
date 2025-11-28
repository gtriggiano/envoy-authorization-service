# IP Match Database Authorization Controller `ip-match-database`

The IP Match Database authorization controller performs IP address authorization checks against external data sources (Redis or PostgreSQL).

This enables dynamic IP blocking/allowing based on behavioral analysis, threat intelligence, or partner management systems.

## Features

- **Multiple Data Sources**: Support for Redis and PostgreSQL
- **Optional Caching**: TTL-based in-memory caching to minimize database queries
- **TLS Support**: Full TLS/SSL support for both Redis and PostgreSQL connections
- **Flexible Actions**: Support for both `allow` (whitelist) and `deny` (blacklist) modes
- **Error Handling**: Configurable behavior when database is unavailable
- **Metrics**: Comprehensive Prometheus metrics for monitoring

## Use Cases

1. **Scraper Detection**: Block IPs identified as scrapers by behavioral analysis tools
2. **Dynamic Allowlists**: Whitelist IPs of trusted partners managed in a database
3. **Threat Intelligence**: Block IPs from external threat feeds

## Configuration

### Redis Example

```yaml
authorizationControllers:
  - name: scraper-blocker
    type: ip-match-database
    settings:
      action: deny  # Block matching IPs
      
      cache:
        ttl: 10m  # Cache results for 10 minutes
      
      database:
        type: redis
        connectionTimeout: 200ms  # Query timeout
        
        redis:
          keyPrefix: "scraper:"  # Will check "scraper:<IP>"
          host: redis.example.com
          port: 6379
          usernameEnv: REDIS_USERNAME  # Optional
          passwordEnv: REDIS_PASSWORD  # Optional
          db: 0
```

### PostgreSQL Example

```yaml
authorizationControllers:
  - name: partner-allowlist
    type: ip-match-database
    settings:
      action: allow  # Allow only matching IPs
      
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
          
          pool:
            maxConnections: 10
            minConnections: 2
```

## Configuration Reference

### Top-Level Settings

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `action` | string | Yes | - | Authorization action: `allow` or `deny` |
| `alwaysDenyOnDbUnavailable` | bool | No | `false` | Always deny when database is unavailable |
| `cache` | object | No | - | Caching configuration |
| `database` | object | Yes | - | Database configuration |

### Cache Settings

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `ttl` | string | Yes (if cache is set) | - | Time-to-live for cache entries (e.g., `10m`, `1h`) |

### Database Settings

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `type` | string | Yes | - | Database type: `redis` or `postgres` |
| `connectionTimeout` | string | No | `500ms` | Database connection timeout duration |
| `redis` | object | Required if `type=redis` | - | Redis configuration |
| `postgres` | object | Required if `type=postgres` | - | PostgreSQL configuration |

### Redis Configuration

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `keyPrefix` | string | Yes | - | Prefix for Redis keys (e.g., `scraper:`) |
| `host` | string | Yes | - | Redis server hostname |
| `port` | int | No | `6379` | Redis server port |
| `usernameEnv` | string | No | - | Name of env var containing username |
| `passwordEnv` | string | No | - | Name of env var containing password |
| `db` | int | No | `0` | Redis database number |
| `tls` | object | No | - | TLS configuration |

### PostgreSQL Configuration

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `query` | string | Yes | - | SQL query with `$1` placeholder for IP |
| `host` | string | Yes | - | PostgreSQL server hostname |
| `port` | int | No | `5432` | PostgreSQL server port |
| `databaseName` | string | Yes | - | Database name |
| `usernameEnv` | string | Yes | - | Name of env var containing username |
| `passwordEnv` | string | Yes | - | Name of env var containing password |
| `pool` | object | No | - | Connection pool configuration |
| `tls` | object | No | - | TLS configuration |

### PostgreSQL Pool Configuration

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `maxConnections` | int | No | `10` | Maximum connections in pool |
| `minConnections` | int | No | `2` | Minimum connections in pool |
| `maxIdleTime` | string | No | `5m` | Maximum connection idle time |
| `connectionTimeout` | string | No | `5s` | Connection establishment timeout |

### TLS Configuration (Redis)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `insecureSkipVerify` | bool | No | `false` | Skip certificate verification |
| `caCert` | string | No | - | Path to CA certificate file (PEM format) |
| `clientCert` | string | No | - | Path to client certificate file (PEM format) |
| `clientKey` | string | No | - | Path to client private key file (PEM format) |

### TLS Configuration (PostgreSQL)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `mode` | string | No | `prefer` | SSL mode: `allow`, `prefer`, `require`, `verify-ca`, `verify-full` |
| `caCert` | string | No | - | Path to CA certificate file (PEM format) |
| `clientCert` | string | No | - | Path to client certificate file (PEM format) |
| `clientKey` | string | No | - | Path to client private key file (PEM format) |

## Authorization Logic

### Action: `deny` (Blocklist)

| Condition | Result |
|-----------|--------|
| IP matches in database | **DENY** (PermissionDenied) |
| IP not found in database | **ALLOW** (OK) |
| Database unavailable (default) | **ALLOW** (fail-open) |
| Database unavailable (`alwaysDenyOnDbUnavailable: true`) | **DENY** (fail-closed) |

### Action: `allow` (Allowlist)

| Condition | Result |
|-----------|--------|
| IP matches in database | **ALLOW** (OK) |
| IP not found in database | **DENY** (PermissionDenied) |
| Database unavailable (default) | **DENY** (fail-closed) |
| Database unavailable (`alwaysDenyOnDbUnavailable: true`) | **DENY** (fail-closed) |

## Data Source Setup

### Redis

The controller checks for key existence using the `EXISTS` command:

```bash
# Set a key to block an IP
SET scraper:1.2.3.4 1

# Or with expiry (auto-removal after 1 hour)
SET scraper:1.2.3.4 1 EX 3600

# Check if IP is blocked
EXISTS scraper:1.2.3.4
```

The value doesn't matter - only key existence is checked.

### PostgreSQL

Create a table to store IP addresses:

```sql
CREATE TABLE scrapers (
    ip_address INET PRIMARY KEY,
    detected_at TIMESTAMP DEFAULT NOW(),
    confidence FLOAT,
    notes TEXT
);

-- Add an IP
INSERT INTO scrapers (ip_address, confidence) VALUES ('1.2.3.4', 0.95);

-- Query used by controller
SELECT 1 FROM scrapers WHERE ip_address = $1 AND confidence >= 0.90 LIMIT 1;
```

The query must accept exactly one parameter (`$1`) which will be the IP address.

Any rows returned = match, zero rows = no match.

## Caching

Caching is optional but highly recommended to reduce database load:

- **Cache both results**: Both "found" and "not found" results are cached equally
- **TTL-based expiration**: Entries expire after the configured TTL
- **No size limit**: TTL provides natural memory bounds

Example latency impact:
- Without cache: ~5-50ms per request (database query)
- With cache (hit): ~0.1ms per request (memory lookup)

## Metrics

The controller exposes Prometheus metrics:

```
# Authorization requests by result
envoy_authorization_service_ip_match_database_requests_total{controller="name", result="allow|deny|error"}

# Database queries by result
envoy_authorization_service_ip_match_database_queries_total{controller="name", database="redis|postgres", result="found|not_found|error"}

# Database query duration
envoy_authorization_service_ip_match_database_query_duration_seconds{controller="name", database="redis|postgres"}

# Cache operations
envoy_authorization_service_ip_match_database_cache_requests_total{controller="name", result="hit|miss"}

# Current cache size
envoy_authorization_service_ip_match_database_cache_entries{controller="name"}

# Database unavailability events
envoy_authorization_service_ip_match_database_unavailable_total{controller="name", database="redis|postgres"}
```

## Error Handling on Database Unavailability

### Default Behavior

- **`action: deny`** → Fail-open (allow) when database is unavailable
  - Reasoning: Can't verify IP is blocked, so allow it
- **`action: allow`** → Fail-closed (deny) when database is unavailable
  - Reasoning: Can't verify IP is allowed, so deny it

### Override Behavior

Set `alwaysDenyOnDbUnavailable: true` to always deny when database is unavailable, regardless of action.
