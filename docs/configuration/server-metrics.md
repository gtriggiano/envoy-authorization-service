# Server & Metrics Configuration

Configuration for the gRPC server, metrics endpoint, health checks, and operational settings.

## Server Configuration

### Basic Server

```yaml
server:
  address: ":9001"  # Listen on all interfaces, port 9001
```

### Server with TLS

```yaml
server:
  address: ":9001"
  tls:
    certFile: /etc/certs/server.crt
    keyFile: /etc/certs/server.key
```

### Server with Mutual TLS (mTLS)

```yaml
server:
  address: ":9001"
  tls:
    certFile: /etc/certs/server.crt
    keyFile: /etc/certs/server.key
    caFile: /etc/certs/ca.crt
    requireClientCert: true
```

## Shutdown Configuration

```yaml
shutdown:
  timeout: 30s  # Wait up to 30 seconds for graceful shutdown
```

### Graceful Shutdown

When receiving SIGTERM or SIGINT:
1. Stop accepting new connections
2. Wait for in-flight requests (up to `shutdown.timeout`)
3. Close database connections
4. Exit with code 0

**Kubernetes Example**:
```yaml
spec:
  terminationGracePeriodSeconds: 30
  containers:
    - name: auth-service
      # ... 
```

Ensure `shutdown.timeout` < `terminationGracePeriodSeconds`.

## Metrics Server Configuration

### Basic Server

```yaml
metrics:
  address: ":9090"  # Listen on all interfaces. # Default value
  healthPath: /healthz # Default value
  readinessPath: /readyz # Default value
```

### Filtered Metrics (Exclude Go Runtime)

```yaml
metrics:
  dropPrefixes: # Default value
    - go_
    - process_
    - promhttp_
```

### Server with TLS

```yaml
metrics:
  address: ":9090"
  tls:
    certFile: /etc/certs/server.crt
    keyFile: /etc/certs/server.key
```

### Metrics Endpoint (`/metrics`)
Prometheus metrics exposed at `/metrics`:

```bash
curl http://localhost:9090/metrics
```

See [Metrics Reference](/reference/metrics) for available metrics.

### Liveness Probe (`/healthz`)

Always returns `200 OK` while the process is running.

**Use for**: Kubernetes liveness probes

```bash
curl http://localhost:9090/healthz
```

### Readiness Probe (`/readyz`)

Returns `200 OK` when the service is ready to accept requests.

**Use for**: Kubernetes readiness probes

```bash
curl http://localhost:9090/readyz
```

## Complete Example

```yaml
logging:
  level: info

shutdown:
  timeout: 30s

server:
  address: ":9001"
  tls:
    certFile: /etc/certs/tls.crt
    keyFile: /etc/certs/tls.key

metrics:
  address: ":9090"
  tls:
    certFile: /etc/certs/tls.crt
    keyFile: /etc/certs/tls.key
```

## Next Steps

- [Metrics Reference](/reference/metrics)
- [Configure Analysis Controllers](/configuration/analysis-controllers)
- [Configure Authorization Controllers](/configuration/authorization-controllers)
- [Configure Server & Metrics](/configuration/server-metrics)
- [View Configuration Examples](/examples/)