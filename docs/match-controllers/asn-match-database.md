# ASN Match Database

The `asn-match-database` controller matches the client ASN against an external data source: Redis or PostgreSQL.

## Redis Example

Checks if in the Redis database the key `<keyPrefix><Client AS Number>` exists.

```yaml
analysisControllers:
  - name: asn
    type: maxmind-asn
    settings:
      databasePath: config/GeoLite2-ASN.mmdb

matchControllers:
  - name: asn-blocklist
    type: asn-match-database
    settings:
      matchesOnFailure: false # Default
      cache:
        ttl: 5m
      database:
        type: redis
        redis:
          keyPrefix: "asn:block:"
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

Checks if the controller's SQL query, when executed with the client AS number as parameter, returns any rows.

```yaml
matchControllers:
  - name: trusted-asn
    type: asn-match-database
    settings:
      matchesOnFailure: false # Default
      database:
        type: postgres
        postgres:
          query: "SELECT 1 FROM trusted_asns WHERE asn = $1 LIMIT 1"
          host: postgres.example.com
          databaseName: security
          port: 5432
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
- **`cache.ttl`** (duration): Enables in-memory caching of ASN lookups.
- **`database.type`**: `redis` or `postgres`.
- **`database.redis`**: redis-specific configuration.
- **`database.postgres`**: postgres-specific configuration.
- **`database.connectionTimeout`**: Initialization connection timeout (default `500ms`).

## Metrics
Publishes query, cache, and availability metrics under the shared `envoy_authz_match_database_*` subsystem (see Metrics Reference).
