# Configuration

The Envoy Authorization Service is configured with a single YAML file that wires together logging, server endpoints, analysis controllers, match controllers, and the authorization policy that connects them.

## Validation at startup

✅ Checked
- required fields
- readable file paths
- registered controller types and each controller's required settings
- policy syntax and references to configured (and enabled) match controllers

❌ Startup fails on
- invalid YAML
- missing required fields
- non-existent paths
- unknown controller types
- invalid policy expression or references to unknown/disabled controllers

## Configuration Structure

::: tip Paths resolution

All file paths in configuration file can be expressed as:
- **Absolute**: `/etc/auth-service/config.yaml`
- **Relative**: `config/database.mmdb` (is resolved from the current working directory)

:::

```yaml
# Optional: logging configuration
logging:
  level: info # debug, info, warn, error. Optional, defaults to info

# Policy expression combining match controllers (Optional. If absent all requests are allowed)
authorizationPolicy: "controller1 && (controller2 || !controller3)"

# Optional: bypass policy for testing. Logs what would have been blocked but allows everything
authorizationPolicyBypass: false

# Optional: graceful shutdown timeout
shutdown:
  timeout: 25s # Default: 20s

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
  trackGeofence: true # Optional: emit geofence match metrics (default true)
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

## Next Steps

- [Analysis Controllers](/analysis-controllers/)
- [Match Controllers](/match-controllers/)
- [Authorization Policy DSL](/policy-dsl)
- [Metrics Reference](/reference/metrics)
- [Configuration Examples](/examples/)
