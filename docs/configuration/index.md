# Configuration Overview

The Envoy Authorization Service uses YAML configuration files to define server settings, analysis controllers, authorization controllers, and policy expressions.

## Configuration File Structure

```yaml
# Optional: logging configuration
logging:
  level: info  # debug, info, warn, error. Optional, defaults to info

# gRPC server configuration
server:
  address: ":9001" # Optional: listen address
  tls:  # Optional
    certFile: certs/server.crt
    keyFile: certs/server.key
    caFile: certs/ca.crt  # Required if requireClientCert is true
    requireClientCert: false

# Metrics server and health endpoints
metrics:
  address: ":9090" # Optional: listen address
  healthPath: /healthz # Optional
  readinessPath: /readyz # Optional
  dropPrefixes:  # Optional: exclude metric prefixes. This is the default
    - go_
    - process_
    - promhttp_

# Optional: graceful shutdown timeout
shutdown:
  timeout: 25s  # Default: 20s

# Analysis controllers (optional)
analysisControllers:
  - name: controller-name
    type: controller-type
    settings:
      # Controller-specific settings

# Authorization controllers (optional)
authorizationControllers:
  - name: controller-name
    type: controller-type
    settings:
      # Controller-specific settings

# Policy expression combining authorization controllers (Optional. If absent all requests will be allowed)
authorizationPolicy: "controller1 && (controller2 || !controller3)"

# Optional: bypass policy for testing. Logs what would have been blocked but allows everything
authorizationPolicyBypass: false
```

### Minimal Configuration

```yaml
analysisControllers:
  - name: allow-all
    type: maxmind-geoip
    settings:
      action: allow
      databasePath: /path/to/GeoLite2-City.mmdb
```

## Paths Resolution in configuration

All file paths in configuration support:
- **Absolute paths**: `/etc/auth-service/config.yaml`
- **Relative paths**: `config/database.mmdb` (relative to working directory)

## Configuration Validation

Configuration is validated at startup:

✅ **Checked**:
- Required fields present
- File paths exist and are readable
- Controller types registered
- Policy expression syntax valid
- Policy references existing controllers
- No duplicate controller names
- Valid duration formats
- Valid port numbers

❌ **Startup fails if**:
- Missing required fields
- Invalid YAML syntax
- Non-existent file paths
- Unknown controller types
- Invalid policy expression
- Policy references non-existent controller
- Duplicate controller names

## Next Steps

- [Configure Analysis Controllers](/configuration/analysis-controllers)
- [Configure Authorization Controllers](/configuration/authorization-controllers)
- [Write Policy Expressions](/configuration/policy-dsl)
- [Configure Server & Metrics](/configuration/server-metrics)
- [View Configuration Examples](/examples/)
