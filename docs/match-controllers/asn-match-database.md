# ASN Match Database

The `asn-match-database` controller sets `IsMatch=true` when the client ASN exists in an external data source (Redis or PostgreSQL). It relies on an analysis controller (typically `maxmind-asn`) to populate the ASN in analysis reports.

## Redis Example

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
        ttl: 5m
      database:
        type: redis
        redis:
          keyPrefix: "asn:block:"
          host: redis.example.com
          port: 6379
```

## PostgreSQL Example

```yaml
matchControllers:
  - name: trusted-asn
    type: asn-match-database
    settings:
      matchesOnFailure: true
      database:
        type: postgres
        postgres:
          query: "SELECT 1 FROM trusted_asns WHERE asn = $1 LIMIT 1"
          host: postgres.example.com
          port: 5432
          databaseName: security
          usernameEnv: POSTGRES_USER
          passwordEnv: POSTGRES_PASSWORD
```

## Key Settings

- **`matchesOnFailure`** (bool, default: `false`): Sets `IsMatch` on database failures.
- **`cache.ttl`** (duration): Enables in-memory caching of ASN lookups.
- **`database.type`**: `redis` or `postgres` with backend-specific fields; the Redis `keyPrefix` should build keys like `keyPrefix + <asn>`.
