# Metrics Reference

Complete reference of Prometheus metrics exposed by the Envoy Authorization Service.

## Endpoint

Metrics are exposed at:
```
http://<service>:9090/metrics
```

## Core Metrics

These metrics track overall authorization service performance.

### envoy_authz_requests_total `Counter`

Total number of authorization requests processed by the service.

| Label Name | Example Value | Description |
|------------|---------------|-------------|
| `authority` | `api.service.com` | HTTP host/:authority value of the downstream request (or `-` when absent) |
| `verdict` | `ALLOW` | Authorization decision. Possible values: `ALLOW` (request was allowed), `DENY` (request was denied) |

**Example queries:**
```promql
# Total requests per second
sum by (authority) (rate(envoy_authz_requests_total[5m]))

# Allow rate
rate(envoy_authz_requests_total{verdict="ALLOW"}[5m]) by (authority)

# Deny rate
rate(envoy_authz_requests_total{verdict="DENY"}[5m]) by (authority)

# Denial percentage
100 *
sum by (authority) (rate(envoy_authz_requests_total{verdict="DENY"}[5m]))
/
sum by (authority) (rate(envoy_authz_requests_total[5m]))

# Top authorities by deny rate
topk(5,
  rate(envoy_authz_requests_total{verdict="DENY"}[5m])
) by (authority)
```

---

### envoy_authz_request_duration_seconds `Histogram`

End-to-end authorization request latency in seconds.

| Label Name | Example Value | Description |
|------------|---------------|-------------|
| `authority` | `api.service.com` | HTTP host/:authority value of the downstream request (or `-` when absent) |
| `verdict` | `ALLOW` | Authorization decision. Possible values: `ALLOW` (request was allowed), `DENY` (request was denied) |

**Buckets**: `[.00005, .0001, .0005, .001, .002, .005, .01, .025, .05, .1, .25, .5]`

**Example queries:**
```promql
# p99 latency for all requests
histogram_quantile(0.99, 
  rate(envoy_authz_request_duration_seconds_bucket[5m])
) by (authority)

# p99 latency by verdict
histogram_quantile(0.99,
  rate(envoy_authz_request_duration_seconds_bucket[5m])
) by (authority, verdict)

# Average latency
sum(rate(envoy_authz_request_duration_seconds_sum[5m])) by (authority)
/
sum(rate(envoy_authz_request_duration_seconds_count[5m])) by (authority)

# p95 latency by authority
histogram_quantile(0.95,
  rate(envoy_authz_request_duration_seconds_bucket[5m])
) by (authority)
```

---

### envoy_authz_controller_phase_duration_seconds `Histogram`

Controller phase execution time in seconds.

| Label Name | Example Value | Description |
|------------|---------------|-------------|
| `authority` | `api.service.com` | HTTP host/:authority value of the downstream request (or `-` when absent) |
| `controller_name` | `maxmind-asn-lookup` | Unique name of the controller instance (from configuration) |
| `controller_kind` | `maxmind-asn` | Type of controller. Possible values: `maxmind-asn`, `maxmind-geoip`, `ua-detect` (analysis controllers), `ip-match`, `asn-match`, `ip-match-database` (match controllers) |
| `phase` | `analysis` | Execution phase. Possible values: `analysis` (analysis controller execution), `match` (match controller execution) |
| `result` | `ok` | Execution outcome. Possible values: `ok` (successful execution), `error` (execution failed) |

**Buckets**: `[.00005, .0001, .0005, .001, .002, .005, .01, .025, .05, .1, .25, .5]`

**Example queries:**
```promql
# p95 latency for a specific controller
histogram_quantile(0.95,
  rate(envoy_authz_controller_phase_duration_seconds_bucket{
    controller_name="ip-whitelist"
  }[5m])
)

# Average analysis phase latency by controller kind
rate(envoy_authz_controller_phase_duration_seconds_sum{phase="analysis"}[5m])
/
rate(envoy_authz_controller_phase_duration_seconds_count{phase="analysis"}[5m])
by (controller_kind)

# Error rate by controller
rate(envoy_authz_controller_phase_duration_seconds_count{result="error"}[5m])
by (controller_name, controller_kind)

# Slowest controllers (p99)
topk(5,
  histogram_quantile(0.99,
    rate(envoy_authz_controller_phase_duration_seconds_bucket[5m])
  ) by (controller_name)
)
```

---

### envoy_authz_inflight_requests `Gauge`

Current number of authorization requests being processed.

| Label Name | Example Value | Description |
|------------|---------------|-------------|
| `authority` | `api.service.com` | HTTP host/:authority value of the downstream request (or `-` when absent) |

**Example queries:**
```promql
# Current in-flight requests
envoy_authz_inflight_requests

# Maximum in-flight requests over 1 hour
max_over_time(envoy_authz_inflight_requests[1h])

# Average in-flight requests
avg_over_time(envoy_authz_inflight_requests[5m])
```

---

## IP Match Database Metrics

These metrics are specific to the `ip-match-database` match controller.

### envoy_authz_ip_match_database_requests_total `Counter`

Total requests processed by the ip-match-database controller.

| Label Name | Example Value | Description |
|------------|---------------|-------------|
| `authority` | `api.service.com` | HTTP host/:authority value of the downstream request (or `-` when absent) |
| `controller_name` | `scraper-blocker` | Name of the controller instance (from configuration) |
| `database` | `redis` | Database type. Possible values: `redis`, `postgres` |
| `result` | `allow` | Authorization result. Possible values: `allow` (request was allowed), `deny` (request was denied), `error` (processing error occurred) |

**Example queries:**
```promql
# Request rate by result
rate(envoy_authz_ip_match_database_requests_total[5m])
by (authority, controller_name, result)

# Denial rate for a specific controller
rate(envoy_authz_ip_match_database_requests_total{
  authority="api.service.com",
  controller_name="scraper-blocker",
  result="deny"
}[5m])

# Error rate
rate(envoy_authz_ip_match_database_requests_total{result="error"}[5m]) by (authority)
```

---

### envoy_authz_ip_match_database_queries_total `Counter`

Total database queries executed by the ip-match-database controller.

| Label Name | Example Value | Description |
|------------|---------------|-------------|
| `authority` | `api.service.com` | HTTP host/:authority value of the downstream request (or `-` when absent) |
| `controller_name` | `scraper-blocker` | Name of the controller instance (from configuration) |
| `database` | `redis` | Database type. Possible values: `redis`, `postgres` |
| `result` | `found` | Query outcome. Possible values: `found` (IP address was found in database), `not_found` (IP address was not found), `error` (query failed) |

**Example queries:**
```promql
# Database query rate
rate(envoy_authz_ip_match_database_queries_total[5m])
by (authority, database)

# Query error rate
rate(envoy_authz_ip_match_database_queries_total{result="error"}[5m]) by (authority, database)

# Hit rate (found vs total queries)
sum(rate(envoy_authz_ip_match_database_queries_total{result="found"}[5m]))
/
sum(rate(envoy_authz_ip_match_database_queries_total{result!="error"}[5m]))
```

---

### envoy_authz_ip_match_database_query_duration_seconds `Histogram`

Database query duration in seconds.

| Label Name | Example Value | Description |
|------------|---------------|-------------|
| `authority` | `api.service.com` | HTTP host/:authority value of the downstream request (or `-` when absent) |
| `controller_name` | `scraper-blocker` | Name of the controller instance (from configuration) |
| `database` | `redis` | Database type. Possible values: `redis`, `postgres` |

**Buckets**: `[.001, .002, .005, .01, .025, .05, .1, .25, .5, 1]`

**Example queries:**
```promql
# p99 query latency
histogram_quantile(0.99,
  rate(envoy_authz_ip_match_database_query_duration_seconds_bucket[5m])
) by (authority, database)

# Redis vs PostgreSQL latency comparison (p50)
histogram_quantile(0.50,
  rate(envoy_authz_ip_match_database_query_duration_seconds_bucket[5m])
) by (authority, database)

# Average query duration
sum(rate(envoy_authz_ip_match_database_query_duration_seconds_sum[5m])) by (authority, database)
/
sum(rate(envoy_authz_ip_match_database_query_duration_seconds_count[5m])) by (authority, database)
```

---

### envoy_authz_ip_match_database_cache_requests_total `Counter`

Total cache lookup requests.

| Label Name | Example Value | Description |
|------------|---------------|-------------|
| `authority` | `api.service.com` | HTTP host/:authority value of the downstream request (or `-` when absent) |
| `controller_name` | `scraper-blocker` | Name of the controller instance (from configuration) |
| `result` | `hit` | Cache outcome. Possible values: `hit` (entry found in cache), `miss` (entry not found, database query required) |

**Example queries:**
```promql
# Cache hit rate by authority
sum(rate(envoy_authz_ip_match_database_cache_requests_total{result="hit"}[5m])) by (authority)
/
sum(rate(envoy_authz_ip_match_database_cache_requests_total[5m])) by (authority)

# Cache hit rate by controller
sum(rate(envoy_authz_ip_match_database_cache_requests_total{result="hit"}[5m]))
by (authority, controller_name)
/
sum(rate(envoy_authz_ip_match_database_cache_requests_total[5m]))
by (authority, controller_name)

# Cache miss rate
rate(envoy_authz_ip_match_database_cache_requests_total{result="miss"}[5m]) by (authority, controller_name)
```

---

### envoy_authz_ip_match_database_cache_entries `Gauge`

Current number of entries in the cache.

| Label Name | Example Value | Description |
|------------|---------------|-------------|
| `authority` | `api.service.com` | HTTP host/:authority value of the downstream request (or `-` when absent) |
| `controller_name` | `scraper-blocker` | Name of the controller instance (from configuration) |

**Example queries:**
```promql
# Current cache size by controller
envoy_authz_ip_match_database_cache_entries
by (authority, controller_name)

# Total cache entries across all controllers
sum by (authority) (envoy_authz_ip_match_database_cache_entries)

# Cache growth rate over 1 hour
delta(envoy_authz_ip_match_database_cache_entries[1h])
```

---

### envoy_authz_ip_match_database_unavailable_total `Counter`

Total database unavailability events (connection failures, timeouts, etc.).

| Label Name | Example Value | Description |
|------------|---------------|-------------|
| `authority` | `api.service.com` | HTTP host/:authority value of the downstream request (or `-` when absent) |
| `controller_name` | `scraper-blocker` | Name of the controller instance (from configuration) |
| `database` | `redis` | Database type. Possible values: `redis`, `postgres` |

**Example queries:****
```promql
# Database unavailability rate
rate(envoy_authz_ip_match_database_unavailable_total[5m])
by (authority, database)

# Total unavailability events in last 24 hours
increase(envoy_authz_ip_match_database_unavailable_total[24h])
by (authority, controller_name, database)

# Alert on any unavailability event
rate(envoy_authz_ip_match_database_unavailable_total[1m]) > 0
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
            rate(envoy_authz_controller_phase_duration_seconds_count{result="error"}[5m]) by (authority, controller_name, controller_kind) > 1
          for: 5m
          labels:
            severity: warning
          annotations:
            summary: "Envoy Authz Controller for {{ $labels.authority }} experiencing errors"
            description: "{{ $labels.controller_name }} ({{ $labels.controller_kind }}) error rate: {{ $value }}"
        
        # Ip Match Database Query errors
        - alert: EnvoyAuthzIpMatchDatabaseQueryErrors
          expr: |
            rate(envoy_authz_ip_match_database_queries_total{result="error"}[5m]) by (authority, controller_name, database) > 10
          for: 2m
          labels:
            severity: warning
          annotations:
            summary: "Database controller errors for {{ $labels.authority }}"
            description: "{{ $labels.controller_name }} on {{ $labels.database }} (authority {{ $labels.authority }}): {{ $value }} errors/s"
        
        # Ip Match Database unavailable
        - alert: EnvoyAuthzIpMatchDatabaseUnavailable
          expr: |
            rate(envoy_authz_ip_match_database_unavailable_total[1m]) by (authority, controller_name, database) > 0
          for: 1m
          labels:
            severity: critical
          annotations:
            summary: "Database unavailable for {{ $labels.authority }}"
            description: "{{ $labels.database }} unavailable for {{ $labels.controller_name }} (authority {{ $labels.authority }})"
        
        # Low cache hit rate
        - alert: LowCacheHitRate
          expr: |
            sum by (authority) (rate(envoy_authz_ip_match_database_cache_requests_total{result="hit"}[5m]))
            /
            sum by (authority) (rate(envoy_authz_ip_match_database_cache_requests_total[5m]))
            < 0.7
          for: 10m
          labels:
            severity: info
          annotations:
            summary: "Cache hit rate below 70% for {{ $labels.authority }}"
            description: "Current hit rate: {{ $value | humanizePercentage }} for authority {{ $labels.authority }}"
```

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
              rate(envoy_authz_controller_phase_duration_seconds_bucket[5m])
            ) by (authority, controller_name)
        
        # Cache hit rate
        - record: job:envoy_authz:cache_hit_rate
          expr: |
            sum by (authority) (rate(envoy_authz_ip_match_database_cache_requests_total{result="hit"}[5m]))
            /
            sum by (authority) (rate(envoy_authz_ip_match_database_cache_requests_total[5m]))
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
  rate(envoy_authz_controller_phase_duration_seconds_bucket[5m])
) by (controller_name, phase)
```

### Database Query Performance

```promql
histogram_quantile(0.99,
  rate(envoy_authz_ip_match_database_query_duration_seconds_bucket[5m])
) by (authority, database)
```

### Cache Hit Rate

```promql
100 * sum(rate(envoy_authz_ip_match_database_cache_requests_total{result="hit"}[5m])) by (authority)
/
sum(rate(envoy_authz_ip_match_database_cache_requests_total[5m])) by (authority)
```

## Go Runtime Metrics

By default, the service excludes standard Go runtime metrics from `prometheus.DefaultGatherer`.

You can control this through prefixes specified in `metrics.dropPrefixes`.

**Filtered by default**:
- `go_*` - Go runtime metrics (goroutines, memory, GC)
- `process_*` - Process metrics (CPU, memory, file descriptors)
- `promhttp_*` - Prometheus HTTP handler metrics

To re-include all these metrics, just set `dropPrefixes: []` in your configuration.
