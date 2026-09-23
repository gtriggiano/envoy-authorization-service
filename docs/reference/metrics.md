# Metrics Reference

Complete reference of Prometheus metrics exposed by the Envoy Authorization Service.

## Endpoint

Metrics are exposed at:
```
http://<service>:9090/metrics
```

## Build Metrics

### `envoy_authz_build_info` `Gauge`

Always `1`. Identifies the running build so behaviour can be correlated with deployments (`envoy_authz_requests_total * on (instance) group_left (version) envoy_authz_build_info`). The same values are printed by `envoy-authorization-service version` and logged at startup.

| Label Name | Example Value | Description |
|------------|---------------|-------------|
| `version` | `1.5.0` | Release version; `dev` for unreleased builds |
| `commit` | `9f3c2d1e4b7a` | VCS revision the binary was built from; `-dirty` suffix when built from an uncommitted tree, `unknown` when not available |
| `go_version` | `go1.27.0` | Go toolchain that compiled the binary |

## Core Metrics

These metrics track overall authorization service performance.

### `envoy_authz_inflight_requests` `Gauge`

Current number of authorization requests being processed.

| Label Name | Example Value | Description |
|------------|---------------|-------------|
| `authority` | `api.service.com` | HTTP host/:authority value of the downstream request (or `-` when absent) |


### `envoy_authz_policy_configured` `Gauge`

`1` when an `authorizationPolicy` is configured, `0` when it is empty and every request is allowed. No labels.

### `envoy_authz_policy_bypass_enabled` `Gauge`

`1` when `authorizationPolicyBypass` is enabled and requests denied by the policy are allowed anyway, `0` otherwise. No labels. Alert on either gauge being in the fail-open state in production.

### `envoy_authz_requests_total` `Counter`

Total number of authorization requests processed by the service.

| Label Name | Example Value | Description |
|------------|---------------|-------------|
| `authority` | `api.service.com` | HTTP host/:authority value of the downstream request (or `-` when absent) |
| `verdict` | `ALLOW` | Final response sent to Envoy (`ALLOW`/`DENY`). Can be `ALLOW` even when policy wanted `DENY` if `policyBypass` is enabled. |
| `policy_verdict` | `DENY` | Result of policy evaluation before bypass. |
| `country_iso` | `US` | 2-letter ISO from GeoIP analysis, or `-` if unavailable. Populated only when `metrics.trackCountry` is true. |
| `country_name` | `United States` | Country name from GeoIP analysis, or `-` if unavailable. Populated only when `metrics.trackCountry` is true. |
| `continent` | `North America` | Continent from GeoIP analysis, or `-` if unavailable. Populated only when `metrics.trackCountry` is true. |
| `culprit_controller_name` | `partner-ip` | Match controller name that policy used to deny (`-` when policy allowed). |
| `culprit_controller_kind` | `ip-match-database` | Match controller kind for the culprit (`-` when policy allowed). |
| `culprit_controller_verdict` | `MATCH` | Controller verdict (`MATCH`/`NO_MATCH` or `-` when policy allowed). |
| `culprit_controller_result` | `OK` | Execution result of the culprit controller (`OK`/`ERROR` or `-` when policy allowed). |

**Denials without a culprit controller:** when `clientIp.requireValid` is `true` and no configured source yields an address, the request is denied before any controller runs and recorded with `culprit_controller_name="client-ip"`, `culprit_controller_kind="client-ip"`, `culprit_controller_verdict="-"`, `culprit_controller_result="ERROR"` (see [Client IP Resolution](/guides/client-ip)).

**Verdict vs policy_verdict:** `verdict` is what Envoy sees; `policy_verdict` is the raw policy evaluation result. They differ when `policyBypass` lets a denied request pass, letting you distinguish “should have been denied” from “actually denied.” Geo labels default to `-` when GeoIP analysis is not configured or did not return data.

### `envoy_authz_request_duration_seconds` `Histogram`

End-to-end authorization request latency in seconds.

| Label Name | Example Value | Description |
|------------|---------------|-------------|
| `authority` | `api.service.com` | HTTP host/:authority value of the downstream request (or `-` when absent) |
| `verdict` | `DENY` | Final response sent to Envoy (`ALLOW`/`DENY`). |
| `policy_verdict` | `DENY` | Policy evaluation result prior to bypass. |
| `country_iso` | `US` | 2-letter ISO from GeoIP analysis, or `-` if unavailable. Populated only when `metrics.trackCountry` is true. |
| `country_name` | `United States` | Country name from GeoIP analysis, or `-` if unavailable. Populated only when `metrics.trackCountry` is true. |
| `continent` | `North America` | Continent from GeoIP analysis, or `-` if unavailable. Populated only when `metrics.trackCountry` is true. |
| `culprit_controller_name` | `scraper-ip` | Match controller name that caused the denial (`-` when policy allowed). |
| `culprit_controller_kind` | `ip-match` | Match controller kind that caused the denial (`-` when policy allowed). |
| `culprit_controller_verdict` | `MATCH` | Verdict from the culprit match controller (`MATCH`, `NO_MATCH`, or `-` when policy allowed/not available) |
| `culprit_controller_result` | `OK` | Execution result of the culprit match controller (`OK`, `ERROR`, or `-` when policy allowed/not available) |

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
Emitted only when `metrics.trackGeofence` is `true` (default `false`, because the `feature` label grows with the number of geofence features).

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

## Go Runtime Metrics

By default, the service excludes standard Go runtime metrics from `prometheus.DefaultGatherer`.

You can control this through prefixes specified in `metrics.dropPrefixes`.

**Filtered by default**:
- `go_*` - Go runtime metrics (goroutines, memory, GC)
- `process_*` - Process metrics (CPU, memory, file descriptors)
- `promhttp_*` - Prometheus HTTP handler metrics

To re-include all these metrics, just set `dropPrefixes: []` in your configuration.
