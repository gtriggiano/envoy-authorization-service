# Configuration

The Envoy Authorization Service is configured with a single YAML file that wires together logging, server endpoints, analysis controllers, match controllers, and the authorization policy that connects them.

## Validation at startup

✅ Checked
- required fields
- readable file paths,
- registered controllers and their settings
- policy validation for syntax and references to configured controllers

❌ Startup fails on
- invalid YAML
- missing required fields
- non-existent paths
- unknown controller types
- invalid policy expression or missing referenced controllers

## Configuration Structure

::: tip Paths resolution

All file paths in configuration file can be espressed as:
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
  address: ":9001" # Optional listen address
  tls: # Optional TLS / mTLS
    certFile: certs/server.crt
    keyFile: certs/server.key
    caFile: certs/ca.crt # Required when requireClientCert is true
    requireClientCert: false

# Metrics server and health endpoints
metrics:
  address: ":9090" # Optional listen address
  healthPath: /healthz # Optional
  readinessPath: /readyz # Optional
  dropPrefixes: # Optional: exclude metric prefixes (default shown)
    - go_
    - process_
    - promhttp_
  tls: # Optional TLS for metrics endpoint
    certFile: certs/server.crt
    keyFile: certs/server.key

# Analysis controllers (optional)
analysisControllers:
  - name: controller-name
    type: controller-type
    settings:
      # Controller-specific settings

# Match controllers (optional)
matchControllers:
  - name: controller-name
    type: controller-type
    settings:
      # Controller-specific settings
```

## Next Steps

- [Analysis Controllers](/analysis-controllers/)
- [Match Controllers](/match-controllers/)
- [Authorization Policy DSL](/policy-dsl)
- [Metrics Reference](/reference/metrics)
- [Configuration Examples](/examples/)
