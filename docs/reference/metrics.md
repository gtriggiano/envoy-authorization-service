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
| `verdict` | `ALLOW` | Authorization decision. Possible values: `ALLOW` (request was allowed), `DENY` (request was denied) |

**Example queries:**
```promql
# Total requests per second
rate(envoy_authz_requests_total[5m])

# Allow rate
rate(envoy_authz_requests_total{verdict="ALLOW"}[5m])

# Deny rate
rate(envoy_authz_requests_total{verdict="DENY"}[5m])

# Denial percentage
100 * rate(envoy_authz_requests_total{verdict="DENY"}[5m])
/
rate(envoy_authz_requests_total[5m])
```

---

### envoy_authz_request_duration_seconds `Histogram`

End-to-end authorization request latency in seconds.

| Label Name | Example Value | Description |
|------------|---------------|-------------|
| `verdict` | `ALLOW` | Authorization decision. Possible values: `ALLOW` (request was allowed), `DENY` (request was denied) |

**Buckets**: `[.00005, .0001, .0005, .001, .002, .005, .01, .025, .05, .1, .25, .5]`

**Example queries:**
```promql
# p99 latency for all requests
histogram_quantile(0.99, 
  rate(envoy_authz_request_duration_seconds_bucket[5m])
)

# p99 latency by verdict
histogram_quantile(0.99,
  rate(envoy_authz_request_duration_seconds_bucket[5m])
) by (verdict)

# Average latency
rate(envoy_authz_request_duration_seconds_sum[5m])
/
rate(envoy_authz_request_duration_seconds_count[5m])
```

---

### envoy_authz_controller_phase_duration_seconds `Histogram`

Controller phase execution time in seconds.

| Label Name | Example Value | Description |
|------------|---------------|-------------|
| `controller_name` | `maxmind-asn-lookup` | Unique name of the controller instance (from configuration) |
| `controller_kind` | `maxmind-asn` | Type of controller. Possible values: `maxmind-asn`, `maxmind-geoip`, `ua-detect` (analysis controllers), `ip-match`, `asn-match`, `ip-match-database` (authorization controllers) |
| `phase` | `analysis` | Execution phase. Possible values: `analysis` (analysis controller execution), `authorization` (authorization controller execution) |
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

**Labels**: None

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

These metrics are specific to the `ip-match-database` authorization controller.

### envoy_authz_ip_match_database_requests_total `Counter`

Total authorization requests processed by the ip-match-database controller.

| Label Name | Example Value | Description |
|------------|---------------|-------------|
| `controller_name` | `scraper-blocker` | Name of the controller instance (from configuration) |
| `database` | `redis` | Database type. Possible values: `redis`, `postgres` |
| `result` | `allow` | Authorization result. Possible values: `allow` (request was allowed), `deny` (request was denied), `error` (processing error occurred) |

**Example queries:**
```promql
# Request rate by result
rate(envoy_authz_ip_match_database_requests_total[5m])
by (controller_name, result)

# Denial rate for a specific controller
rate(envoy_authz_ip_match_database_requests_total{
  controller_name="scraper-blocker",
  result="deny"
}[5m])

# Error rate
rate(envoy_authz_ip_match_database_requests_total{result="error"}[5m])
```

---

### envoy_authz_ip_match_database_queries_total `Counter`

Total database queries executed by the ip-match-database controller.

| Label Name | Example Value | Description |
|------------|---------------|-------------|
| `controller_name` | `scraper-blocker` | Name of the controller instance (from configuration) |
| `database` | `redis` | Database type. Possible values: `redis`, `postgres` |
| `result` | `found` | Query outcome. Possible values: `found` (IP address was found in database), `not_found` (IP address was not found), `error` (query failed) |

**Example queries:**
```promql
# Database query rate
rate(envoy_authz_ip_match_database_queries_total[5m])
by (database)

# Query error rate
rate(envoy_authz_ip_match_database_queries_total{result="error"}[5m])

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
| `controller_name` | `scraper-blocker` | Name of the controller instance (from configuration) |
| `database` | `redis` | Database type. Possible values: `redis`, `postgres` |

**Buckets**: `[.001, .002, .005, .01, .025, .05, .1, .25, .5, 1]`

**Example queries:**
```promql
# p99 query latency
histogram_quantile(0.99,
  rate(envoy_authz_ip_match_database_query_duration_seconds_bucket[5m])
) by (database)

# Redis vs PostgreSQL latency comparison (p50)
histogram_quantile(0.50,
  rate(envoy_authz_ip_match_database_query_duration_seconds_bucket[5m])
) by (database)

# Average query duration
rate(envoy_authz_ip_match_database_query_duration_seconds_sum[5m])
/
rate(envoy_authz_ip_match_database_query_duration_seconds_count[5m])
```

---

### envoy_authz_ip_match_database_cache_requests_total `Counter`

Total cache lookup requests.

| Label Name | Example Value | Description |
|------------|---------------|-------------|
| `controller_name` | `scraper-blocker` | Name of the controller instance (from configuration) |
| `result` | `hit` | Cache outcome. Possible values: `hit` (entry found in cache), `miss` (entry not found, database query required) |

**Example queries:**
```promql
# Cache hit rate
sum(rate(envoy_authz_ip_match_database_cache_requests_total{result="hit"}[5m]))
/
sum(rate(envoy_authz_ip_match_database_cache_requests_total[5m]))

# Cache hit rate by controller
sum(rate(envoy_authz_ip_match_database_cache_requests_total{result="hit"}[5m]))
by (controller_name)
/
sum(rate(envoy_authz_ip_match_database_cache_requests_total[5m]))
by (controller_name)

# Cache miss rate
rate(envoy_authz_ip_match_database_cache_requests_total{result="miss"}[5m])
```

---

### envoy_authz_ip_match_database_cache_entries `Gauge`

Current number of entries in the cache.

| Label Name | Example Value | Description |
|------------|---------------|-------------|
| `controller_name` | `scraper-blocker` | Name of the controller instance (from configuration) |

**Example queries:**
```promql
# Current cache size by controller
envoy_authz_ip_match_database_cache_entries
by (controller_name)

# Total cache entries across all controllers
sum(envoy_authz_ip_match_database_cache_entries)

# Cache growth rate over 1 hour
delta(envoy_authz_ip_match_database_cache_entries[1h])
```

---

### envoy_authz_ip_match_database_unavailable_total `Counter`

Total database unavailability events (connection failures, timeouts, etc.).

| Label Name | Example Value | Description |
|------------|---------------|-------------|
| `controller_name` | `scraper-blocker` | Name of the controller instance (from configuration) |
| `database` | `redis` | Database type. Possible values: `redis`, `postgres` |

**Example queries:****
```promql
# Database unavailability rate
rate(envoy_authz_ip_match_database_unavailable_total[5m])
by (database)

# Total unavailability events in last 24 hours
increase(envoy_authz_ip_match_database_unavailable_total[24h])
by (controller_name, database)

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
        - alert: HighAuthorizationDenialRate
          expr: rate(envoy_authz_requests_total{verdict="DENY"}[5m]) > 100
          for: 5m
          labels:
            severity: warning
          annotations:
            summary: "High authorization denial rate"
            description: "Denial rate is {{ $value }} req/s"
        
        # Service down
        - alert: AuthorizationServiceDown
          expr: up{job="envoy-authorization-service"} == 0
          for: 2m
          labels:
            severity: critical
          annotations:
            summary: "Authorization service is down"
        
        # High latency
        - alert: HighAuthorizationLatency
          expr: |
            histogram_quantile(0.99,
              rate(envoy_authz_request_duration_seconds_bucket[5m])
            ) > 0.5
          for: 10m
          labels:
            severity: warning
          annotations:
            summary: "High authorization latency"
            description: "p99 latency is {{ $value }}s"
        
        # Controller errors
        - alert: ControllerErrors
          expr: |
            rate(envoy_authz_controller_phase_duration_seconds_count{result="error"}[5m]) > 1
          for: 5m
          labels:
            severity: warning
          annotations:
            summary: "Controller experiencing errors"
            description: "{{ $labels.controller_name }} ({{ $labels.controller_kind }}) error rate: {{ $value }}"
        
        # Database errors
        - alert: DatabaseControllerErrors
          expr: |
            rate(envoy_authz_ip_match_database_queries_total{result="error"}[5m]) > 10
          for: 2m
          labels:
            severity: warning
          annotations:
            summary: "Database controller experiencing errors"
            description: "{{ $labels.controller_name }} on {{ $labels.database }}: {{ $value }} errors/s"
        
        # Database unavailable
        - alert: DatabaseUnavailable
          expr: |
            rate(envoy_authz_ip_match_database_unavailable_total[1m]) > 0
          for: 1m
          labels:
            severity: critical
          annotations:
            summary: "Database unavailable"
            description: "{{ $labels.database }} unavailable for {{ $labels.controller_name }}"
        
        # Low cache hit rate
        - alert: LowCacheHitRate
          expr: |
            sum(rate(envoy_authz_ip_match_database_cache_requests_total{result="hit"}[5m]))
            /
            sum(rate(envoy_authz_ip_match_database_cache_requests_total[5m]))
            < 0.7
          for: 10m
          labels:
            severity: info
          annotations:
            summary: "Cache hit rate below 70%"
            description: "Current hit rate: {{ $value | humanizePercentage }}"
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
          expr: sum(rate(envoy_authz_requests_total[5m]))
        
        # Denial rate
        - record: job:envoy_authz:denial_rate
          expr: sum(rate(envoy_authz_requests_total{verdict="DENY"}[5m]))
        
        # p99 latency
        - record: job:envoy_authz:latency_p99
          expr: |
            histogram_quantile(0.99,
              rate(envoy_authz_request_duration_seconds_bucket[5m])
            )
        
        # Controller p99 latency by name
        - record: job:envoy_authz:controller_latency_p99:by_name
          expr: |
            histogram_quantile(0.99,
              rate(envoy_authz_controller_phase_duration_seconds_bucket[5m])
            ) by (controller_name)
        
        # Cache hit rate
        - record: job:envoy_authz:cache_hit_rate
          expr: |
            sum(rate(envoy_authz_ip_match_database_cache_requests_total{result="hit"}[5m]))
            /
            sum(rate(envoy_authz_ip_match_database_cache_requests_total[5m]))
```

## Grafana Dashboard Examples

### Request Rate Panel

```promql
sum(rate(envoy_authz_requests_total[5m])) by (verdict)
```

### Authorization Latency (p50, p95, p99)

```promql
histogram_quantile(0.50, rate(envoy_authz_request_duration_seconds_bucket[5m]))
histogram_quantile(0.95, rate(envoy_authz_request_duration_seconds_bucket[5m]))
histogram_quantile(0.99, rate(envoy_authz_request_duration_seconds_bucket[5m]))
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
) by (database)
```

### Cache Hit Rate

```promql
100 * sum(rate(envoy_authz_ip_match_database_cache_requests_total{result="hit"}[5m]))
/
sum(rate(envoy_authz_ip_match_database_cache_requests_total[5m]))
```

## Go Runtime Metrics

By default, the service excludes standard Go runtime metrics from `prometheus.DefaultGatherer`.

You can control this through prefixes specified in `metrics.dropPrefixes`.

**Filtered by default**:
- `go_*` - Go runtime metrics (goroutines, memory, GC)
- `process_*` - Process metrics (CPU, memory, file descriptors)
- `promhttp_*` - Prometheus HTTP handler metrics

To re-include all these metrics, just set `dropPrefixes: []` in your configuration.
