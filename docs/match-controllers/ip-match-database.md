# IP Match Database

The `ip-match-database` controller matches the request IP against an external data source: Redis or PostgreSQL.

## Redis Example

Checks if in the Redis database the key `<keyPrefix><Request IP>` exists.

```yaml
matchControllers:
  - name: suspect-scraper
    type: ip-match-database
    settings:
      matchesOnFailure: false # Default
      cache:
        ttl: 10m
      database:
        type: redis
        redis:
          keyPrefix: "suspect-scraper:"
          host: redis.example.com
          port: 6379
          # Optional TLS configuration
          tls:
            insecureSkipVerify: false
            caCert: /path/to/ca.crt
            clientCert: /path/to/client.crt
            clientKey: /path/to/client.key
```

## PostgreSQL Example

Checks if the controller's SQL query, when executed with the request IP as parameter, returns any rows.

```yaml
matchControllers:
  - name: customer-whitelisted-ip
    type: ip-match-database
    settings:
      matchesOnFailure: false # Default
      database:
        type: postgres
        connectionTimeout: 500ms
        postgres:
          query: "SELECT 1 FROM customer_whitelisted_ips WHERE ip = $1 LIMIT 1"
          host: postgres.example.com
          port: 5432
          databaseName: security
          usernameEnv: POSTGRES_USER
          passwordEnv: POSTGRES_PASSWORD
          # Optional TLS configuration
          tls:
            mode: verify-full
            caCert: /path/to/ca.crt
            clientCert: /path/to/client.crt
            clientKey: /path/to/client.key
```

## Key Settings

- **`matchesOnFailure`** (bool, default: `false`): Controls `IsMatch` if database query fails.
- **`cache.ttl`** (duration): Enables in-memory caching of IP lookups.
- **`database.type`**: `redis` or `postgres`
- **`database.redis`**: redis-specific configuration.
- **`database.postgres`**: postgres-specific configuration.
- **`database.connectionTimeout`**: Initialization connection timeout (default `500ms`).

## Metrics
Exposes request, query, cache, and availability metrics under `envoy_authz_match_database_*` (see Metrics Reference).
