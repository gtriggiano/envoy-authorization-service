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

### Startup

Configuration problems are reported before any port is bound and the process exits with status 1. Two fail-open settings are accepted but logged at `warn` level on every start: `authorizationPolicy is empty: every request is allowed` and `authorizationPolicyBypass is enabled: requests denied by the policy are allowed anyway`. The same states are exposed as the `envoy_authz_policy_configured` and `envoy_authz_policy_bypass_enabled` gauges.

### Request fields

Every request-level line carries `authority`, `ip` (the resolved client address, `invalid IP` when none) and `ip_source` (`envoySource`, `header:<name>`, `xff` or `none`), followed by the fields analysis controllers add (ASN, GeoIP, User-Agent). At startup `msg="client IP resolution configured"` lists the configured sources. See [Client IP Resolution](/guides/client-ip) for what each source means.

## Health Endpoints (on metrics server)

### Liveness (`/healthz`)

Always returns 200 OK while process is running.

**Use for**: Kubernetes liveness probes

```bash
curl http://localhost:9090/healthz
```

### Readiness (`/readyz`)

Returns `200 OK` once the gRPC listener is bound **and** every configured controller's health check passes. Returns `503 Service Unavailable` otherwise.

Controller health checks are run on every probe call, in parallel, with a 5 second timeout. Only the database-backed controllers (`ip-match-database`, `asn-match-database`) have a real health check (a `PING` / connection ping against Redis or PostgreSQL); all other controllers always report healthy. A database outage therefore makes the pod unready even when `matchesOnFailure: true` is configured.

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

## Recording Rules

These rules examples favor low cardinality and keep `authority` as the primary slice.

```yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: envoy-authz-recording-rules
spec:
  groups:
    - name: envoy-authz-recordings
      interval: 30s
      rules:
        # Final vs policy decision volumes (captures bypass)
        - record: envoy_authz:authority:req_rate
          expr: sum by (authority, verdict, policy_verdict) (rate(envoy_authz_requests_total[5m]))

        # Deny rate (final) and “should-have-denied” (policy) in separate series
        - record: envoy_authz:authority:deny_rate
          expr: sum by (authority) (rate(envoy_authz_requests_total{verdict="DENY"}[5m]))
        - record: envoy_authz:authority:policy_deny_rate
          expr: sum by (authority) (rate(envoy_authz_requests_total{policy_verdict="DENY"}[5m]))

        # Latency percentiles (pre-aggregated buckets)
        - record: envoy_authz:authority:latency_p95
          expr: histogram_quantile(0.95, sum by (authority, le) (rate(envoy_authz_request_duration_seconds_bucket[5m])))
        - record: envoy_authz:authority:latency_p99
          expr: histogram_quantile(0.99, sum by (authority, le) (rate(envoy_authz_request_duration_seconds_bucket[5m])))

        # Error rates (collapsed across controllers to keep cardinality low)
        - record: envoy_authz:authority:controller_error_rate
          expr: sum by (authority) (rate(envoy_authz_controller_requests_total{result="ERROR"}[5m]))
        - record: envoy_authz:authority:db_error_rate
          expr: sum by (authority) (rate(envoy_authz_match_database_queries_total{result="ERROR"}[5m]))

        # Cache efficiency
        - record: envoy_authz:authority:cache_hit_ratio
          expr: |
            sum by (authority) (rate(envoy_authz_match_database_cache_requests_total{cache_result="HIT"}[5m]))
            /
            sum by (authority) (rate(envoy_authz_match_database_cache_requests_total[5m]))

        # Verdict and geo ratios (optional; watch cardinality for country_iso and country_name)
        - record: envoy_authz:authority:verdict_ratio
          expr: |
            sum by (authority, verdict) (rate(envoy_authz_requests_total[5m]))
            /
            sum by (authority) (rate(envoy_authz_requests_total[5m]))

        # Bypass masking rate (requests where policy wanted DENY but final was ALLOW)
        - record: envoy_authz:authority:bypass_masking_rate
          expr: |
            sum by (authority) (
              rate(envoy_authz_requests_total{verdict="ALLOW",policy_verdict="DENY"}[5m])
            )

        # GeoIP aggregations
        - record: envoy_authz:authority:country_rate
          expr: sum by (authority, country_iso) (rate(envoy_authz_requests_total[5m]))
        - record: envoy_authz:authority:country_ratio
          expr: |
            sum by (authority, country_iso) (rate(envoy_authz_requests_total[5m]))
            /
            sum by (authority) (rate(envoy_authz_requests_total[5m]))
        - record: envoy_authz:authority:country_name_rate
          expr: sum by (authority, country_name) (rate(envoy_authz_requests_total[5m]))
        - record: envoy_authz:authority:country_name_ratio
          expr: |
            sum by (authority, country_name) (rate(envoy_authz_requests_total[5m]))
            /
            sum by (authority) (rate(envoy_authz_requests_total[5m]))

        # Geofence feature matches (counts and rate) aggregated by authority, controller, and feature.
        # Available only when metrics.trackGeofence is true.
        - record: envoy_authz:authority:geofence_match_total
          expr: sum by (authority, controller_name, feature) (envoy_authz_geofence_match_totals)
        - record: envoy_authz:authority:geofence_match_rate
          expr: sum by (authority, controller_name, feature) (rate(envoy_authz_geofence_match_totals[5m]))
```

## Alerting

This alerts examples are based on the recordings described above.

```yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: envoy-authz-alerts
spec:
  groups:
    - name: envoy-authz-alerts
      rules:
        - alert: EnvoyAuthzHighDenialRate
          expr: envoy_authz:authority:deny_rate > 100
          for: 5m
          labels:
            severity: warning
          annotations:
            summary: "High denial rate for {{ $labels.authority }}"
            description: "Denials exceed 100 req/s (5m rate)."

        - alert: EnvoyAuthzHighLatencyP99
          expr: envoy_authz:authority:latency_p99 > 0.05
          for: 10m
          labels:
            severity: warning
          annotations:
            summary: "High p99 latency for {{ $labels.authority }}"
            description: "p99 authorization latency > 50ms."

        - alert: EnvoyAuthzControllerErrors
          expr: envoy_authz:authority:controller_error_rate > 1
          for: 5m
          labels:
            severity: warning
          annotations:
            summary: "Controller errors for {{ $labels.authority }}"
            description: "Controller error rate >1 req/s (5m rate)."

        - alert: EnvoyAuthzDatabaseErrors
          expr: envoy_authz:authority:db_error_rate > 5
          for: 2m
          labels:
            severity: warning
          annotations:
            summary: "Match DB errors for {{ $labels.authority }}"
            description: "Database query errors >5 req/s (5m rate)."

        - alert: EnvoyAuthzBypassMaskingDenies
          expr: envoy_authz:authority:bypass_masking_rate > 0
          for: 10m
          labels:
            severity: warning
          annotations:
            summary: "Policy bypass masking denials for {{ $labels.authority }}"
            description: "Requests allowed while policy verdict is DENY (bypass active)."

        - alert: EnvoyAuthzLowCacheHitRatio
          expr: envoy_authz:authority:cache_hit_ratio < 0.7
          for: 10m
          labels:
            severity: info
          annotations:
            summary: "Cache hit ratio below 70% for {{ $labels.authority }}"
            description: "Cache hit ratio is {{ $value | humanizePercentage }}."
```

## Next Steps

- [Metrics Reference](/reference/metrics)
- [CLI Commands](/reference/cli)
- [Server & Metrics Configuration](/configuration)
