# Metrics

The authorization service exposes comprehensive Prometheus metrics for monitoring performance, authorization decisions, and controller behavior.

## Configuration

Metrics are exposed via an HTTP server configured in the `metrics` section of the YAML configuration:

```yaml
metrics:
  address: ":9090"           # HTTP server bind address
  healthPath: /healthz       # Liveness probe endpoint
  readinessPath: /readyz     # Readiness probe endpoint
  dropPrefixes:              # Metric name prefixes to exclude from Go runtime metrics
    - go_
    - process_
    - promhttp_
```

### Configuration Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `address` | string | Yes | `:9090` | HTTP server bind address for metrics and health endpoints |
| `healthPath` | string | No | `/healthz` | URL path for liveness probe (always returns 200 OK) |
| `readinessPath` | string | No | `/readyz` | URL path for readiness probe (checks controller health) |
| `dropPrefixes` | []string | No | `["go_", "process_", "promhttp_"]` | Metric name prefixes to filter from Go runtime metrics |

### Endpoints

- **`/metrics`** - Prometheus metrics endpoint in text exposition format
- **`/healthz`** - Liveness probe (returns `200 OK` with body `ok`)
- **`/readyz`** - Readiness probe (returns `200 OK` when service and all controllers are healthy, `503 Service Unavailable` otherwise)

The readiness probe runs health checks against all configured analysis and authorization controllers in parallel with a 5-second timeout.

## Standard Service Metrics

These metrics track overall authorization service performance and are produced by the core service.

### `envoy_authz_requests_total`

**Type**: Counter  
**Labels**: `verdict`

Total number of authorization requests processed.

**Labels:**
- `verdict`: Authorization decision
  - `ALLOW` - Request was allowed by policy
  - `DENY` - Request was denied by policy

**Example:**
```promql
# Total allow decisions
envoy_authz_requests_total{verdict="ALLOW"}

# Total deny decisions  
envoy_authz_requests_total{verdict="DENY"}

# Request rate over 5 minutes
rate(envoy_authz_requests_total[5m])
```

---

### `envoy_authz_request_duration_seconds`

**Type**: Histogram  
**Labels**: `verdict`

End-to-end authorization request latency in seconds.

**Buckets**: `[.00005, .0001, .0005, .001, .002, .005, .01, .025, .05, .1, .25, .5]`

**Labels:**
- `verdict`: Authorization decision (`ALLOW` or `DENY`)

**Example:**
```promql
# 99th percentile latency for all requests
histogram_quantile(0.99, rate(envoy_authz_request_duration_seconds_bucket[5m]))

# Average latency for denied requests
rate(envoy_authz_request_duration_seconds_sum{verdict="DENY"}[5m]) /
rate(envoy_authz_request_duration_seconds_count{verdict="DENY"}[5m])
```

---

### `envoy_authz_controller_phase_duration_seconds`

**Type**: Histogram  
**Labels**: `controller_name`, `controller_kind`, `phase`, `result`

Individual controller execution time in seconds.

**Buckets**: `[.00005, .0001, .0005, .001, .002, .005, .01, .025, .05, .1, .25, .5]`

**Labels:**
- `controller_name`: Unique controller instance name (from configuration)
- `controller_kind`: Controller type (e.g., `maxmind-asn`, `ip-match`, `asn-match`)
- `phase`: Execution phase
  - `analysis` - Analysis controller execution
  - `authorization` - Authorization controller execution
- `result`: Execution outcome
  - `ok` - Successful execution
  - `error` - Execution failed

**Example:**
```promql
# 95th percentile latency for IP match controller
histogram_quantile(0.95, 
  rate(envoy_authz_controller_phase_duration_seconds_bucket{
    controller_name="ip-whitelist"
  }[5m])
)

# Average authorization phase latency across all controllers
rate(envoy_authz_controller_phase_duration_seconds_sum{phase="authorization"}[5m]) /
rate(envoy_authz_controller_phase_duration_seconds_count{phase="authorization"}[5m])
```

---

### `envoy_authz_inflight_requests`

**Type**: Gauge

Current number of authorization requests being processed.

**Example:**
```promql
# Current in-flight requests
envoy_authz_inflight_requests

# Maximum in-flight requests over 1 hour
max_over_time(envoy_authz_inflight_requests[1h])
```

---

## Controller-Specific Metrics

### IP Match Database Controller

The `ip-match-database` controller produces additional metrics for database operations and caching.

#### `envoy_authz_ip_match_database_requests_total`

**Type**: Counter  
**Labels**: `controller_name`, `database`, `result`

Total authorization requests processed by this controller.

**Labels:**
- `controller_name`: Controller instance name
- `database`: Database type (`redis` or `postgres`)
- `result`: Authorization result
  - `allow` - Request was allowed
  - `deny` - Request was denied
  - `error` - Processing error occurred

**Example:**
```promql
# Allow rate for scraper blocker
rate(envoy_authz_ip_match_database_requests_total{
  controller="scraper-blocker",
  result="deny"
}[5m])
```

---

#### `envoy_authz_ip_match_database_queries_total`

**Type**: Counter  
**Labels**: `controller_name`, `database`, `result`

Total database queries executed.

**Labels:**
- `controller_name`: Controller instance name
- `database`: Database type (`redis` or `postgres`)
- `result`: Query outcome
  - `found` - IP address matched in database
  - `not_found` - IP address not found in database
  - `error` - Query failed

**Example:**
```promql
# Database query error rate
rate(envoy_authz_ip_match_database_queries_total{result="error"}[5m])

# Redis hit rate
rate(envoy_authz_ip_match_database_queries_total{
  database="redis",
  result="found"
}[5m]) /
rate(envoy_authz_ip_match_database_queries_total{
  database="redis"
}[5m])
```

---

#### `envoy_authz_ip_match_database_query_duration_seconds`

**Type**: Histogram  
**Labels**: `controller_name`, `database`

Database query duration in seconds.

**Buckets**: `[.001, .002, .005, .01, .025, .05, .1, .25, .5, 1]`

**Labels:**
- `controller_name`: Controller instance name
- `database`: Database type (`redis` or `postgres`)

**Example:**
```promql
# 99th percentile database query latency
histogram_quantile(0.99,
  rate(envoy_authz_ip_match_database_query_duration_seconds_bucket[5m])
)

# PostgreSQL vs Redis latency comparison
histogram_quantile(0.50,
  rate(envoy_authz_ip_match_database_query_duration_seconds_bucket{
    database="postgres"
  }[5m])
) 
/
histogram_quantile(0.50,
  rate(envoy_authz_ip_match_database_query_duration_seconds_bucket{
    database="redis"
  }[5m])
)
```

---

#### `envoy_authz_ip_match_database_cache_requests_total`

**Type**: Counter  
**Labels**: `controller_name`, `result`

Total cache lookup requests.

**Labels:**
- `controller_name`: Controller instance name
- `result`: Cache outcome
  - `hit` - Entry found in cache
  - `miss` - Entry not in cache, database query required

**Example:**
```promql
# Cache hit rate
rate(envoy_authz_ip_match_database_cache_requests_total{
  result="hit"
}[5m]) /
rate(envoy_authz_ip_match_database_cache_requests_total[5m])

# Cache miss rate by controller
rate(envoy_authz_ip_match_database_cache_requests_total{
  result="miss"
}[5m])
```

---

#### `envoy_authz_ip_match_database_cache_entries`

**Type**: Gauge  
**Labels**: `controller_name`

Current number of entries in the cache.

**Labels:**
- `controller_name`: Controller instance name

**Example:**
```promql
# Current cache size
envoy_authz_ip_match_database_cache_entries

# Cache growth rate over 1 hour
delta(envoy_authz_ip_match_database_cache_entries[1h])
```

---

#### `envoy_authz_ip_match_database_unavailable_total`

**Type**: Counter  
**Labels**: `controller_name`, `database`

Total database unavailability events (connection failures, timeouts, etc.).

**Labels:**
- `controller_name`: Controller instance name
- `database`: Database type (`redis` or `postgres`)

**Example:**
```promql
# Database unavailability rate
rate(envoy_authz_ip_match_database_unavailable_total[5m])

# Total unavailability events in last hour
increase(envoy_authz_ip_match_database_unavailable_total[1h])
```

---

## Go Runtime Metrics

By default, the service exposes standard Go runtime metrics from `prometheus.DefaultGatherer`, excluding prefixes specified in `metrics.dropPrefixes`:

**Filtered by default** (via `dropPrefixes`):
- `go_*` - Go runtime metrics (goroutines, memory, GC)
- `process_*` - Process metrics (CPU, memory, file descriptors)
- `promhttp_*` - HTTP handler metrics

To include these metrics, set `dropPrefixes: []` in your configuration.

**Example Go metrics** (when not filtered):
```
go_goroutines                    # Current number of goroutines
go_memstats_alloc_bytes          # Bytes allocated and still in use
go_memstats_gc_cpu_fraction      # Fraction of CPU time used by GC
process_cpu_seconds_total        # Total user and system CPU time
process_resident_memory_bytes    # Resident memory size
```

---

## Example Queries

### Service Health

```promql
# Request rate (requests per second)
rate(envoy_authz_requests_total[1m])

# Denial rate percentage
100 * rate(envoy_authz_requests_total{verdict="DENY"}[5m]) /
rate(envoy_authz_requests_total[5m])

# P99 latency
histogram_quantile(0.99, rate(envoy_authz_request_duration_seconds_bucket[5m]))

# Error rate from controller failures
rate(envoy_authz_controller_phase_duration_seconds_count{result="error"}[5m])
```

### Database Controller Performance

```promql
# Cache effectiveness
100 * rate(envoy_authz_ip_match_database_cache_requests_total{result="hit"}[5m]) /
rate(envoy_authz_ip_match_database_cache_requests_total[5m])

# Database query load (queries per second)
rate(envoy_authz_ip_match_database_queries_total[1m])

# Database unavailability incidents in last 24 hours
increase(envoy_authz_ip_match_database_unavailable_total[24h])
```


