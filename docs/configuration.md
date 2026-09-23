# Configuration

The Envoy Authorization Service is configured with a single YAML file that wires together logging, server endpoints, analysis controllers, match controllers, and the authorization policy that connects them.

## Configuration Structure

::: tip Paths resolution

Every file path in the configuration (`databasePath`, `cidrList`, `asnList`, `featuresFile`, TLS material, credential files) can be:
- **Absolute**: `/etc/auth-service/GeoLite2-City.mmdb`
- **Relative**: `GeoLite2-City.mmdb`, resolved from the **directory that contains the configuration file**, whatever the working directory of the process is

:::

::: tip Durations
Timeouts and TTLs are written as Go durations: `500ms`, `10s`, `10m`, `1h30m`. Anything else is rejected at load time.
:::

```yaml
# Optional: logging configuration
logging:
  level: info # debug, info, warn (alias: warning), error. Optional, defaults to info

# Policy expression combining match controllers (Optional. If absent or empty, all requests are allowed)
authorizationPolicy: "controller1 && (controller2 || !controller3)"

# Optional: bypass policy for testing. Logs what would have been blocked but allows everything
authorizationPolicyBypass: false

# Optional: graceful shutdown timeout (a duration greater than 0)
shutdown:
  timeout: 25s # Default: 20s

# Optional: where the client IP address is read from. Only listed sources are consulted, in order.
# Default is [envoySource], i.e. the address of the peer connected to Envoy. See the Client IP Resolution guide.
clientIp:
  sources:
    - header: x-envoy-external-address # Single address written by Envoy when use_remote_address: true
    - xff: # X-Forwarded-For parsed right-to-left; trustedHops right-most entries are skipped (default 0)
        trustedHops: 1
    - envoySource # AttributeContext.source.address
  requireValid: false # Optional (default false). true denies requests whose IP could not be resolved

# gRPC authorization server
server:
  address: ":9001" # Optional listen address (default ":9001")
  tls: # Optional TLS / mTLS. Served in plaintext when omitted.
    certFile: certs/server.crt # Required when tls is set
    keyFile: certs/server.key # Required when tls is set
    caFile: certs/ca.crt # CA used to verify client certificates. Required when requireClientCert is true
    requireClientCert: false # Enable mutual TLS

# Metrics server and health endpoints (always plain HTTP)
metrics:
  address: ":9090" # Optional listen address (default ":9090")
  healthPath: /healthz # Optional (default /healthz)
  readinessPath: /readyz # Optional (default /readyz)
  trackCountry: false # Optional: populate country/continent labels on request metrics (default false to limit cardinality)
  trackGeofence: false # Optional: emit per-feature geofence match metrics (default false to limit cardinality)
  dropPrefixes: # Optional: exclude metric prefixes from the default Go registry (default shown; set to [] to keep everything)
    - go_
    - process_
    - promhttp_

# Analysis controllers (optional)
analysisControllers:
  - name: controller-name # Required, unique within analysisControllers
    type: controller-type # Required, one of the registered analysis controller types
    enabled: true # Optional (default true). Disabled controllers are not built and cannot be referenced by the policy
    settings:
      # Controller-specific settings

# Match controllers (optional)
matchControllers:
  - name: controller-name # Required, unique within matchControllers
    type: controller-type # Required, one of the registered match controller types
    enabled: true # Optional (default true)
    settings:
      # Controller-specific settings
```

::: tip Disabling a controller
`enabled: false` keeps the controller definition in the file but skips it entirely. A policy that references a disabled controller fails validation at startup, so remove it from `authorizationPolicy` as well.
:::

## Environment variables

`${NAME}` anywhere in the file is replaced with the value of the environment variable `NAME` before the YAML is parsed. `${NAME:-default}` uses `default` when the variable is unset or empty. Referencing a variable that is not set, without a default, fails the load. Write `$${` to obtain a literal `${`; a bare `$` (as in the `$1` placeholder of a PostgreSQL query) is left untouched.

```yaml
logging:
  level: ${LOG_LEVEL:-info}

matchControllers:
  - name: partners
    type: ip-match-database
    settings:
      database:
        type: postgres
        postgres:
          host: ${POSTGRES_HOST}
          port: ${POSTGRES_PORT:-5432}
          databaseName: security
          query: "SELECT 1 FROM partner_ips WHERE ip = $1 LIMIT 1"
          username: ${POSTGRES_USER}               # inline, expanded from the environment...
          passwordFile: /secrets/postgres/password # ...or a Kubernetes Secret mounted as a file
```

Credentials for the database-backed controllers are given inline (`username`, `password`), which with `${VAR}` references means "from the environment", or read from a file (`usernameFile`, `passwordFile`); the inline and file forms of the same credential are mutually exclusive. See [IP Match Database](/match-controllers/ip-match-database) and [ASN Match Database](/match-controllers/asn-match-database).

## Client IP resolution

All IP-, ASN- and geo-based controllers evaluate the address resolved through `clientIp.sources`. By default that is Envoy's `AttributeContext.source.address`, the peer that opened the connection to Envoy, which request headers cannot influence. When proxies sit in front of Envoy you must tell the service which header to trust; how to do that safely, and the Envoy settings that go with it, is covered in the [Client IP Resolution](/guides/client-ip) guide.

## Validation at startup

The file is loaded strictly and every problem is reported before the service binds a port or opens a connection. Startup fails on:

- invalid YAML or duplicate keys
- **unknown or misspelled keys**, at the top level and inside a controller's `settings` (`cidrLst` is an error, not a silently ignored key)
- missing required fields
- values of the wrong type, invalid durations (`20 seconds`), non-positive timeouts
- `logging.level` outside `debug`, `info`, `warn`, `error`
- `${VARIABLE}` references to environment variables that are not set (see [Environment variables](#environment-variables))
- non-existent or unreadable file paths
- `clientIp.sources` entries that are malformed or duplicated
- unknown controller types and invalid controller settings
- an `authorizationPolicy` with a syntax error, or referencing controllers that are not configured and enabled

An empty `authorizationPolicy` and `authorizationPolicyBypass: true` are accepted, because they are legitimate while testing, but both are logged at `warn` level at startup and exposed as the `envoy_authz_policy_configured` and `envoy_authz_policy_bypass_enabled` gauges.

::: tip Check a file without starting the server
`envoy-authorization-service validate --config config.yaml` performs the same checks and exits with status 1 on the first error. Add `--offline` to validate a file outside of its deployment environment, for example a ConfigMap in CI. See the [CLI reference](/reference/cli#validate).
:::

## Next Steps

- [Analysis Controllers](/analysis-controllers/)
- [Match Controllers](/match-controllers/)
- [Authorization Policy DSL](/policy-dsl)
- [Client IP Resolution](/guides/client-ip)
- [CLI Reference](/reference/cli) (`validate`)
- [Metrics Reference](/reference/metrics)
- [Configuration Examples](/examples/)
