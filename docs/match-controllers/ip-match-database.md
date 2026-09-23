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
          # Optional credentials: inline (use ${VAR} to read the environment) or from files
          # username: ${REDIS_USER}
          # password: ${REDIS_PASSWORD}
          # usernameFile: /secrets/redis/username
          # passwordFile: /secrets/redis/password
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
          # Credentials: inline (use ${VAR} to read the environment) or from files (a mounted Secret).
          # username/usernameFile and password/passwordFile are mutually exclusive
          username: ${POSTGRES_USER}
          password: ${POSTGRES_PASSWORD}
          # usernameFile: /secrets/postgres/username
          # passwordFile: /secrets/postgres/password
          pool: # Optional
            maxConnections: 10 # Default 10
            minConnections: 2 # Default 2
            maxIdleTime: 5m # Default 5m
            connectionTimeout: 5s # Default 5s
          # Optional TLS configuration
          tls:
            mode: verify-full
            caCert: /path/to/ca.crt
            clientCert: /path/to/client.crt
            clientKey: /path/to/client.key
```

## Key Settings

- **`matchesOnFailure`** (bool, default: `false`): Controls `IsMatch` if the database query fails.
- **`cache.ttl`** (duration, e.g. `10m`): Enables in-memory caching of IP lookups. Required, and greater than 0, when `cache` is present.
- **`database.type`**: `redis` or `postgres`.
- **`database.connectionTimeout`** (duration, default `500ms`): Timeout for the initial connection at startup.
- **`database.redis`** / **`database.postgres`**: connection settings, see the examples above.
- **Credentials**: PostgreSQL requires a user name and a password, Redis accepts them optionally. Each is given inline (`username`, `password`, normally as `${VAR}` references expanded from the environment at load time) **or** read from a file (`usernameFile`, `passwordFile`); a single trailing newline in a file is dropped. `username` and `usernameFile` are mutually exclusive, and so are `password` and `passwordFile`.
- **`database.postgres.pool`**: `maxConnections`, `minConnections`, `maxIdleTime` and `connectionTimeout` (durations greater than 0).
- **TLS**: `caCert`, `clientCert` and `clientKey` are PEM files; `clientCert` and `clientKey` go together. PostgreSQL also takes `mode` (`allow`, `prefer`, `require`, `verify-ca`, `verify-full`), Redis `insecureSkipVerify`.
- **Paths**: relative `*File`, `caCert`, `clientCert` and `clientKey` paths are resolved from the configuration file's directory.

Credential files and certificate files are checked at startup; with `validate --offline` a missing one is a warning, so a ConfigMap can be validated before the Secret exists.

## Metrics
Exposes request, query, cache, and availability metrics under `envoy_authz_match_database_*` (see Metrics Reference).
