# IP Match Database

The `ip-match-database` controller matches the request IP against an external data source: Redis, PostgreSQL, or SQL Server.

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

## SQL Server Example

Checks if the controller's SQL query, when executed with the request IP as parameter, returns any rows.

```yaml
matchControllers:
  - name: customer-whitelisted-ip
    type: ip-match-database
    settings:
      matchesOnFailure: false # Default
      database:
        type: sqlserver
        connectionTimeout: 500ms
        sqlserver:
          query: "SELECT 1 FROM trusted_ips WHERE ip = @p1"
          # host defaults to localhost and port defaults to 1433
          host: sqlserver-primary.example.com
          port: 1433
          instance: SQLEXPRESS
          databaseName: security
          usernameEnv: SQLSERVER_USER
          passwordEnv: SQLSERVER_PASSWORD
          # Optional failover configuration
          failoverPartner: sqlserver-secondary.example.com
          failoverPort: 1433
          # Optional connection behavior
          applicationIntent: ReadOnly
          protocol: tcp
          appName: envoy-authz
          # Optional TLS configuration
          tls:
            encrypt: strict
            trustServerCertificate: false
            caCert: /path/to/ca.crt
            hostNameInCertificate: sqlserver.example.com
            tlsMin: "1.2"
```

## SQL Server DSN Example (URL / ADO / ODBC)

When you need advanced SQL Server routing/auth options, you can provide a full driver connection string directly (URL, ADO, or ODBC format supported by `go-mssqldb`).

```yaml
matchControllers:
  - name: customer-whitelisted-ip
    type: ip-match-database
    settings:
      database:
        type: sqlserver
        sqlserver:
          query: "SELECT 1 FROM trusted_ips WHERE ip = @p1"
          connectionStringEnv: SQLSERVER_DSN
```

Example `SQLSERVER_DSN` values:
- URL: `sqlserver://user:pass@host:1433/INSTANCE?database=security&encrypt=strict`
- ADO: `server=host\\INSTANCE;user id=user;password=pass;database=security;encrypt=strict`
- ODBC: `odbc:server=host;user id=user;password={pass};database=security;encrypt=true`

## Key Settings

- **`matchesOnFailure`** (bool, default: `false`): Controls `IsMatch` if database query fails.
- **`cache.ttl`** (duration): Enables in-memory caching of IP lookups.
- **`database.type`**: `redis`, `postgres`, or `sqlserver`
- **`database.redis`**: redis-specific configuration.
- **`database.postgres`**: postgres-specific configuration.
- **`database.sqlserver`**: sqlserver-specific configuration.
- **`database.sqlserver.host`** / **`database.sqlserver.port`**: defaults to `localhost:1433`.
- **`database.sqlserver.connectionString`** / **`database.sqlserver.connectionStringEnv`**: optional raw SQL Server connection string mode.
- **Raw connection string mode note**: when using `connectionString`/`connectionStringEnv`, put TLS/failover/instance options directly in that string.
- **`database.sqlserver.failoverPartner`** / **`database.sqlserver.failoverPort`**: optional SQL Server failover routing.
- **`database.sqlserver.tls`**: sqlserver TLS options (`encrypt`, `trustServerCertificate`, `caCert`, `hostNameInCertificate`, `tlsMin`).
- **`database.connectionTimeout`**: Initialization connection timeout (default `500ms`).

## Metrics
Exposes request, query, cache, and availability metrics under `envoy_authz_match_database_*` (see Metrics Reference).
