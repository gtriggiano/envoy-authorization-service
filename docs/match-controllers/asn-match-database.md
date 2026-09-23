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
          # Optional credentials: inline (use ${VAR} to read the environment) or from files
          # username: ${REDIS_USER}
          # password: ${REDIS_PASSWORD}
          # usernameFile: /secrets/redis/username
          # passwordFile: /secrets/redis/password
          # Optional TLS configuration (TLS 1.2 or newer)
          tls:
            insecureSkipVerify: false # true skips server verification and logs a warning at startup
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
          # Optional TLS configuration (libpq sslmode semantics)
          tls:
            mode: verify-full # disable | allow | prefer (default) | require | verify-ca | verify-full
            caCert: /path/to/ca.crt # PEM bundle the server certificate must chain to
            clientCert: /path/to/client.crt # Optional, for mutual TLS
            clientKey: /path/to/client.key
```

## Key Settings

- **`matchesOnFailure`** (bool, default: `false`): Controls `IsMatch` if the database query fails.
- **`cache.ttl`** (duration, e.g. `10m`): Enables in-memory caching of ASN lookups. Required, and greater than 0, when `cache` is present.
- **`database.type`**: `redis` or `postgres`.
- **`database.connectionTimeout`** (duration, default `500ms`): Timeout for the initial connection at startup.
- **`database.redis`** / **`database.postgres`**: connection settings, see the examples above.
- **Credentials**: PostgreSQL requires a user name and a password, Redis accepts them optionally. Each is given inline (`username`, `password`, normally as `${VAR}` references expanded from the environment at load time) **or** read from a file (`usernameFile`, `passwordFile`); a single trailing newline in a file is dropped. `username` and `usernameFile` are mutually exclusive, and so are `password` and `passwordFile`.
- **`database.postgres.pool`**: `maxConnections`, `minConnections`, `maxIdleTime` and `connectionTimeout` (durations greater than 0).
- **TLS**: `caCert`, `clientCert` and `clientKey` are PEM files; `clientCert` and `clientKey` go together and enable mutual TLS.
  - PostgreSQL `mode` follows the libpq `sslmode` semantics: `disable`, `allow`, `prefer` (default: TLS when the server offers it, plaintext otherwise), `require` (TLS, server not authenticated unless `caCert` is set, which upgrades it to `verify-ca`), `verify-ca` (certificate chain checked against `caCert`) and `verify-full` (chain and host name checked against `host`). `verify-ca` and `verify-full` fall back to the system trust store when `caCert` is omitted. Any other mode, including the default when `tls` is omitted, logs a warning at startup because the server identity is not verified. The configured mode always wins over a `PGSSLMODE` environment variable.
  - Redis always verifies the server certificate (against `caCert` or the system trust store) and negotiates TLS 1.2 or newer. `insecureSkipVerify: true` disables verification and logs a warning at startup, as does omitting `tls` (plaintext connection).
- **Paths**: relative `*File`, `caCert`, `clientCert` and `clientKey` paths are resolved from the configuration file's directory.

Credential files and certificate files are checked at startup; with `validate --offline` a missing one is a warning, so a ConfigMap can be validated before the Secret exists.

## Metrics
Publishes query, cache, and availability metrics under the shared `envoy_authz_match_database_*` subsystem (see Metrics Reference).
