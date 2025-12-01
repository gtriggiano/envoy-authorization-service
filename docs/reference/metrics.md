# Metrics Reference

Complete reference of Prometheus metrics exposed by the Envoy Authorization Service.

## Endpoint

Metrics are exposed at:
```
http://<service>:9090/metrics
```

## Core Metrics

These metrics track overall authorization service performance.

### `envoy_authz_inflight_requests` `Gauge`

Current number of authorization requests being processed.

| Label Name | Example Value | Description |
|------------|---------------|-------------|
| `authority` | `api.service.com` | HTTP host/:authority value of the downstream request (or `-` when absent) |


### `envoy_authz_requests_total` `Counter`

Total number of authorization requests processed by the service.

| Label Name | Example Value | Description |
|------------|---------------|-------------|
| `authority` | `api.service.com` | HTTP host/:authority value of the downstream request (or `-` when absent) |
| `verdict` | `ALLOW` | Authorization decision. Possible values: `ALLOW` (request was allowed), `DENY` (request was denied) |
| `culprit_controller_name` | `partner-ip` | Match controller name that caused the denial (`-` for allowed requests or when unavailable) |
| `culprit_controller_kind` | `ip-match-database` | Match controller kind that caused the denial (`-` for allowed requests or when unavailable) |
| `culprit_controller_verdict` | `MATCH` | Verdict from the culprit match controller (`MATCH`, `NO_MATCH`, or `-` when allowed/not available) |
| `culprit_controller_result` | `OK` | Execution result of the culprit match controller (`OK`, `ERROR`, or `-` when allowed/not available) |

### `envoy_authz_request_duration_seconds` `Histogram`

End-to-end authorization request latency in seconds.

| Label Name | Example Value | Description |
|------------|---------------|-------------|
| `authority` | `api.service.com` | HTTP host/:authority value of the downstream request (or `-` when absent) |
| `verdict` | `DENY` | Authorization decision. Possible values: `ALLOW` (request was allowed), `DENY` (request was denied) |
| `culprit_controller_name` | `scraper-ip` | Match controller name that caused the denial (`-` for allowed requests or when unavailable) |
| `culprit_controller_kind` | `ip-match` | Match controller kind that caused the denial (`-` for allowed requests or when unavailable) |
| `culprit_controller_verdict` | `MATCH` | Verdict from the culprit match controller (`MATCH`, `NO_MATCH`, or `-` when allowed/not available) |
| `culprit_controller_result` | `OK` | Execution result of the culprit match controller (`OK`, `ERROR`, or `-` when allowed/not available) |

### `envoy_authz_controller_requests_total` `Counter`

Controller invocations by phase and result.

| Label Name | Example Value | Description |
|------------|---------------|-------------|
| `authority` | `api.service.com` | HTTP host/:authority value (or `-` when absent) |
| `controller_name` | `trusted-clouds` | Controller instance name |
| `controller_kind` | `asn-match` | Controller type |
| `phase` | `MATCH` | Execution phase; possible values: `ANALYSIS`, `MATCH` |
| `result` | `OK` | Outcome; possible values: `OK` (succeeded), `ERROR` (failed) |

### `envoy_authz_controller_duration_seconds` `Histogram`

Controller phase execution time in seconds.

Same labels and allowed values as `envoy_authz_controller_requests_total`.

### `envoy_authz_match_verdicts_total` `Counter`
Final verdicts produced by each match controller.

| Label Name | Example Value | Description |
|------------|---------------|-------------|
| `authority` | `api.service.com` | HTTP host/:authority value (or `-`) |
| `controller_name` | `partner-ip` | Controller instance name |
| `controller_kind` | `ip-match-database` | Controller type |
| `verdict` | `MATCH` | Possible values: `MATCH`, `NO_MATCH` |

### `envoy_authz_geofence_match_totals` `Counter`
Feature matches detected by the configured `geofence-match` controllers.

| Label Name | Example Value | Description |
|------------|---------------|-------------|
| `authority` | `api.service.com` | HTTP host/:authority value (or `-`) |
| `controller_name` | `main-markets` | Controller instance name |
| `feature` | `us-east-coast` | Name of the matched GeoJSON feature |

## Match Database Metrics

Metrics for `*-match-database` controllers are unified under the `envoy_authz_match_database_*` subsystem.

Every metric shares these base labels:

| Label Name | Example Value | Description |
|------------|---------------|-------------|
| `authority` | `api.service.com` | HTTP host/:authority value (or `-`) |
| `controller_name` | `partner-ip` | Controller instance name |
| `controller_kind` | `ip-match-database` | Controller type |
| `db_type` | `POSTGRES` | Backend database type (`POSTGRES`, `REDIS`) |

### `envoy_authz_match_database_requests_total` `Counter`
Authorization verdicts emitted by database-backed match controllers.

Added labels:

| Label Name | Example Value | Description |
|------------|---------------|-------------|
| `verdict` | `MATCH` | Possible values: `MATCH`, `NO_MATCH` |
| `result` | `OK` | Possible values: `OK` (controller run succeeded), `ERROR` (failed) |

### `envoy_authz_match_database_queries_total` `Counter`
Database queries executed by the controller.

Added labels:

| Label Name | Example Value | Description |
|------------|---------------|-------------|
| `verdict` | `MATCH` | Possible values: `MATCH`, `NO_MATCH` (whether the query found a match) |
| `result` | `OK` | Possible values: `OK` (query succeeded), `ERROR` |

### `envoy_authz_match_database_query_duration_seconds` `Histogram`
Duration of database queries.

Added labels:

| Label Name | Example Value | Description |
|------------|---------------|-------------|
| `verdict` | `MATCH` | Possible values: `MATCH`, `NO_MATCH` |
| `result` | `OK` | Possible values: `OK` (query succeeded), `ERROR` |

### `envoy_authz_match_database_unavailable_total` `Counter`
Database unavailability incidents (connection failures, timeouts, etc.).

### `envoy_authz_match_database_cache_requests_total` `Counter`
Cache lookups performed by the controller.

Added labels:

| Label Name | Example Value | Description |
|------------|---------------|-------------|
| `cache_result` | `HIT` | Cache outcome (`HIT`, `MISS`) |

### `envoy_authz_match_database_cache_entries` `Gauge`
Current cache entries per controller/backend pair.

## Recording Rules

Recommended Prometheus recording rules for efficient queries:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: envoy-authz-recording-rules
  namespace: monitoring
spec:
  groups:
    - name: auth-service-recordings
      interval: 30s
      rules:
        # Request rate
        - record: job:envoy_authz:request_rate
          expr: sum by (authority) (rate(envoy_authz_requests_total[5m]))
        
        # Denial rate
        - record: job:envoy_authz:denial_rate
          expr: sum by (authority) (rate(envoy_authz_requests_total{verdict="DENY"}[5m]))
        
        # p99 latency
        - record: job:envoy_authz:latency_p99
          expr: |
            histogram_quantile(0.99,
              rate(envoy_authz_request_duration_seconds_bucket[5m])
            ) by (authority)
        
        # Controller p99 latency by name
        - record: job:envoy_authz:controller_latency_p99:by_name
          expr: |
            histogram_quantile(0.99,
              rate(envoy_authz_controller_duration_seconds_bucket[5m])
            ) by (authority, controller_name)
        
        # Cache hit rate
        - record: job:envoy_authz:cache_hit_rate
          expr: |
            sum by (authority) (rate(envoy_authz_match_database_cache_requests_total{cache_result="HIT"}[5m]))
            /
            sum by (authority) (rate(envoy_authz_match_database_cache_requests_total[5m]))
```

## Alerting

Recommended Prometheus alerting rules.

```yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: envoy-authz-alerts
  namespace: monitoring
spec:
  groups:
    - name: auth-service-alerts
      rules:
        # High denial rate
        - alert: EnvoyAuthzHighDenialRate
          expr: |
            sum by (authority) (
              rate(envoy_authz_requests_total{verdict="DENY"}[5m])
            ) > 100
          for: 5m
          labels:
            severity: warning
          annotations:
            summary: "High authorization denial rate for {{ $labels.authority }}"
            description: "Denial rate is {{ $value }} req/s for authority {{ $labels.authority }}"
        
        # High latency
        - alert: EnvoyAuthzHighLatency
          expr: |
            histogram_quantile(0.99,
              rate(envoy_authz_request_duration_seconds_bucket[5m])
            ) by (authority) > 0.05
          for: 10m
          labels:
            severity: warning
          annotations:
            summary: "High authorization latency for {{ $labels.authority }}"
            description: "p99 latency is {{ $value }}s for authority {{ $labels.authority }}"
        
        # Controller errors
        - alert: EnvoyAuthzControllerErrors
          expr: |
            rate(envoy_authz_controller_duration_seconds_count{result="error"}[5m]) by (authority, controller_name, controller_kind) > 1
          for: 5m
          labels:
            severity: warning
          annotations:
            summary: "Envoy Authz Controller for {{ $labels.authority }} experiencing errors"
            description: "{{ $labels.controller_name }} ({{ $labels.controller_kind }}) error rate: {{ $value }}"
        
        # Match Database Query errors
        - alert: EnvoyAuthzMatchDatabaseQueryErrors
          expr: |
            rate(envoy_authz_match_database_queries_total{result="ERROR"}[5m]) by (authority, controller_name, controller_kind, db_type) > 10
          for: 2m
          labels:
            severity: warning
          annotations:
            summary: "Database controller errors for {{ $labels.authority }}"
            description: "{{ $labels.controller_name }} ({{ $labels.controller_kind }}) on {{ $labels.db_type }} (authority {{ $labels.authority }}): {{ $value }} errors/s"

        # Match Database unavailable
        - alert: EnvoyAuthzMatchDatabaseUnavailable
          expr: |
            rate(envoy_authz_match_database_unavailable_total[1m]) by (authority, controller_name, controller_kind, db_type) > 0
          for: 1m
          labels:
            severity: critical
          annotations:
            summary: "Database unavailable for {{ $labels.authority }}"
            description: "{{ $labels.db_type }} unavailable for {{ $labels.controller_name }} (authority {{ $labels.authority }})"

        # Low cache hit rate
        - alert: LowCacheHitRate
          expr: |
            sum by (authority) (rate(envoy_authz_match_database_cache_requests_total{cache_result="HIT"}[5m]))
            /
            sum by (authority) (rate(envoy_authz_match_database_cache_requests_total[5m]))
            < 0.7
          for: 10m
          labels:
            severity: info
          annotations:
            summary: "Cache hit rate below 70% for {{ $labels.authority }}"
            description: "Current hit rate: {{ $value | humanizePercentage }} for authority {{ $labels.authority }}"
```

## Grafana Dashboard Examples

### Request Rate Panel

```promql
sum(rate(envoy_authz_requests_total[5m])) by (authority, verdict)
```

### Authorization Latency (p50, p95, p99)

```promql
histogram_quantile(0.50, rate(envoy_authz_request_duration_seconds_bucket[5m])) by (authority)
histogram_quantile(0.95, rate(envoy_authz_request_duration_seconds_bucket[5m])) by (authority)
histogram_quantile(0.99, rate(envoy_authz_request_duration_seconds_bucket[5m])) by (authority)
```

### Controller Performance

```promql
histogram_quantile(0.99,
  rate(envoy_authz_controller_duration_seconds_bucket[5m])
) by (controller_name, phase)
```

### Database Query Performance

```promql
histogram_quantile(0.99,
  rate(envoy_authz_match_database_query_duration_seconds_bucket[5m])
) by (authority, db_type)
```

### Cache Hit Rate

```promql
100 * sum(rate(envoy_authz_match_database_cache_requests_total{cache_result="HIT"}[5m])) by (authority)
/
sum(rate(envoy_authz_match_database_cache_requests_total[5m])) by (authority)
```

## Go Runtime Metrics

By default, the service excludes standard Go runtime metrics from `prometheus.DefaultGatherer`.

You can control this through prefixes specified in `metrics.dropPrefixes`.

**Filtered by default**:
- `go_*` - Go runtime metrics (goroutines, memory, GC)
- `process_*` - Process metrics (CPU, memory, file descriptors)
- `promhttp_*` - Prometheus HTTP handler metrics

To re-include all these metrics, just set `dropPrefixes: []` in your configuration.
