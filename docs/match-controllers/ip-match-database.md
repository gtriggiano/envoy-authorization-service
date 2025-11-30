# IP Match Database

The `ip-match-database` controller sets `IsMatch=true` when the client IP exists in an external data source (Redis or PostgreSQL). Use the authorization policy to decide whether a match allows or denies (e.g., `authorizationPolicy: "!scraper-blocker"` for a deny list).

## Redis Example

```yaml
matchControllers:
  - name: suspect-scraper
    type: ip-match-database
    settings:
      matchesOnFailure: false
      cache:
        ttl: 10m
      database:
        type: redis
        redis:
          keyPrefix: "suspect-scraper:"
          host: redis.example.com
          port: 6379
```

## PostgreSQL Example

```yaml
matchControllers:
  - name: customer-whitelisted-ip
    type: ip-match-database
    settings:
      matchesOnFailure: false
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
```

## Key Settings

- **`matchesOnFailure`** (bool, default: `false`): Controls `IsMatch` when database queries fail.  
  - Deny list (e.g., `!scraper`): use `false` to fail-open.  
  - Allow list (e.g., `trusted-partner`): use `true` to fail-open.
- **`cache.ttl`** (duration): Enables in-memory caching of match results to reduce database load; caches both positive and negative results.
- **`database.type`**: Either `redis` or `postgres`, each with backend-specific configuration fields.
