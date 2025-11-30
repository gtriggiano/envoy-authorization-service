# Observability

Comprehensive observability with logging, health checks and metrics.

## Logging

Structured logs in logfmt format.

### Log Levels

- `debug`: Detailed execution info
- `info`: Normal operations
- `warn`: Potential issues
- `error`: Errors requiring attention

### Configuration

```yaml
logging:
  level: info
```

## Health Endpoints (on metrics server)

### Liveness (`/healthz`)

Always returns 200 OK while process is running.

**Use for**: Kubernetes liveness probes

```bash
curl http://localhost:9090/healthz
```

### Readiness (`/readyz`)

Returns 200 OK when service is ready.

**Use for**: Kubernetes readiness probes

```bash
curl http://localhost:9090/readyz
```

## Metrics

Envoy Authorization Service starts a Prometheus metrics server with a `/metrics` endpoint.

See [Metrics Reference](/reference/metrics).

```bash
curl http://localhost:9090/metrics
```

## Next Steps

- [Metrics Reference](/reference/metrics)
- [CLI Commands](/reference/cli)
- [Server & Metrics Configuration](/configuration)
