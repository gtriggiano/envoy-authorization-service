package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	ALLOW            = "ALLOW"
	DENY             = "DENY"
	ANALISYS         = "ANALISYS"
	MATCH            = "MATCH"
	OK               = "OK"
	ERROR            = "ERROR"
	NotAvailable     = "-"
	POSTGRES         = "POSTGRES"
	REDIS            = "REDIS"
	FOUND            = "FOUND"
	NOTFOUND         = "NOT_FOUND"
	HIT              = "HIT"
	MISS             = "MISS"
	MATCH_VERDICT    = "MATCH"
	NO_MATCH_VERDICT = "NO_MATCH"
)

// Instrumentation publishes Prometheus metrics for the authorization flow.
type Instrumentation struct {
	requestTotals        *prometheus.CounterVec
	requestDuration      *prometheus.HistogramVec
	controllerDuration   *prometheus.HistogramVec
	controllerRequests   *prometheus.CounterVec
	inFlight             *prometheus.GaugeVec
	matchVerdicts        *prometheus.CounterVec
	matchDbRequests      *prometheus.CounterVec
	matchDbQueries       *prometheus.CounterVec
	matchDbQueryDur      *prometheus.HistogramVec
	matchDbCacheReq      *prometheus.CounterVec
	matchDbCacheSize     *prometheus.GaugeVec
	matchDbUnavailable   *prometheus.CounterVec
	geofenceMatchTotals  *prometheus.CounterVec
}

// NewInstrumentation registers all metric vectors.
func NewInstrumentation(reg prometheus.Registerer) *Instrumentation {
	inst := &Instrumentation{
		requestTotals: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "envoy_authz",
			Name:      "requests_total",
			Help:      "Total authorization decisions by result",
		}, []string{"authority", "verdict", "culprit_controller_name", "culprit_controller_kind", "culprit_controller_verdict", "culprit_controller_result"}),
		requestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "envoy_authz",
			Name:      "request_duration_seconds",
			Help:      "End-to-end authorization latency",
			Buckets:   []float64{.00005, .0001, .0005, .001, .002, .005, .01, .025, .05, .1, .25, .5},
		}, []string{"authority", "verdict", "culprit_controller_name", "culprit_controller_kind", "culprit_controller_verdict", "culprit_controller_result"}),
		controllerDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "envoy_authz",
			Name:      "controller_duration_seconds",
			Help:      "Controller execution time",
			Buckets:   []float64{.00005, .0001, .0005, .001, .002, .005, .01, .025, .05, .1, .25, .5},
		}, []string{"authority", "controller_name", "controller_kind", "phase", "result"}),
		controllerRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "envoy_authz",
			Name:      "controller_requests_total",
			Help:      "Total controller invocations by phase and result",
		}, []string{"authority", "controller_name", "controller_kind", "phase", "result"}),
		inFlight: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "envoy_authz",
			Name:      "inflight_requests",
			Help:      "Active authorization requests",
		}, []string{"authority"}),
		matchVerdicts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "envoy_authz",
			Name:      "match_verdicts_total",
			Help:      "Match controller verdicts",
		}, []string{"authority", "controller_name", "controller_kind", "verdict"}),
		matchDbRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "envoy_authz",
			Subsystem: "match_database",
			Name:      "requests_total",
			Help:      "Total match controller database-backed decisions",
		}, []string{"authority", "controller_name", "controller_kind", "db_type", "verdict", "result"}),
		matchDbQueries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "envoy_authz",
			Subsystem: "match_database",
			Name:      "queries_total",
			Help:      "Total database queries issued by match controllers",
		}, []string{"authority", "controller_name", "controller_kind", "db_type", "verdict", "result"}),
		matchDbQueryDur: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "envoy_authz",
			Subsystem: "match_database",
			Name:      "query_duration_seconds",
			Help:      "Database query duration in seconds for match controllers",
			Buckets:   []float64{.001, .002, .005, .01, .025, .05, .1, .25, .5, 1},
		}, []string{"authority", "controller_name", "controller_kind", "db_type", "verdict", "result"}),
		matchDbCacheReq: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "envoy_authz",
			Subsystem: "match_database",
			Name:      "cache_requests_total",
			Help:      "Cache lookups performed by match controllers",
		}, []string{"authority", "controller_name", "controller_kind", "db_type", "cache_result"}),
		matchDbCacheSize: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "envoy_authz",
			Subsystem: "match_database",
			Name:      "cache_entries",
			Help:      "Current cache entries for match controllers",
		}, []string{"authority", "controller_name", "controller_kind", "db_type"}),
		matchDbUnavailable: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "envoy_authz",
			Subsystem: "match_database",
			Name:      "unavailable_total",
			Help:      "Database unavailability events for match controllers",
		}, []string{"authority", "controller_name", "controller_kind", "db_type"}),
		geofenceMatchTotals: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "envoy_authz",
			Name:      "geofence_match_totals",
			Help:      "Geofence match controller feature matches",
		}, []string{"authority", "controller_name", "feature"}),
	}

	reg.MustRegister(
		inst.requestTotals,
		inst.requestDuration,
		inst.controllerDuration,
		inst.controllerRequests,
		inst.inFlight,
		inst.matchVerdicts,
		inst.matchDbRequests,
		inst.matchDbQueries,
		inst.matchDbQueryDur,
		inst.matchDbCacheReq,
		inst.matchDbCacheSize,
		inst.matchDbUnavailable,
		inst.geofenceMatchTotals,
	)
	return inst
}

// InFlight increments or decrements the in-flight gauge.
func (i *Instrumentation) InFlight(authority string, delta float64) {
	if i == nil {
		return
	}

	if delta == 0 {
		return
	}
	if delta > 0 {
		i.inFlight.WithLabelValues(authority).Add(delta)
		return
	}
	i.inFlight.WithLabelValues(authority).Sub(-delta)
}

// ObserveDenyDecision records a deny decision and duration with culprit labels.
func (i *Instrumentation) ObserveDenyDecision(authority, controllerName, controllerKind, controllerVerdict, controllerResult string, duration time.Duration) {
	if i == nil {
		return
	}

	i.requestTotals.WithLabelValues(authority, DENY, controllerName, controllerKind, controllerVerdict, controllerResult).Inc()
	i.requestDuration.WithLabelValues(authority, DENY, controllerName, controllerKind, controllerVerdict, controllerResult).Observe(duration.Seconds())
}

// ObserveAllowDecision records an allow decision and duration with culprit labels set to not applicable.
func (i *Instrumentation) ObserveAllowDecision(authority string, duration time.Duration) {
	if i == nil {
		return
	}

	i.requestTotals.WithLabelValues(authority, ALLOW, NotAvailable, NotAvailable, NotAvailable, NotAvailable).Inc()
	i.requestDuration.WithLabelValues(authority, ALLOW, NotAvailable, NotAvailable, NotAvailable, NotAvailable).Observe(duration.Seconds())
}

// ObserveAnalysisControllerRequest records analysis controller invocation and latency.
func (i *Instrumentation) ObserveAnalysisControllerRequest(authority, controllerName, controllerKind string, success bool, duration time.Duration) {
	if i == nil {
		return
	}

	result := ERROR
	if success {
		result = OK
	}
	i.controllerRequests.WithLabelValues(authority, controllerName, controllerKind, ANALISYS, result).Inc()
	i.controllerDuration.WithLabelValues(authority, controllerName, controllerKind, ANALISYS, result).Observe(duration.Seconds())
}

// ObserveMatchControllerRequest records match controller invocation and latency.
func (i *Instrumentation) ObserveMatchControllerRequest(authority, controllerName, controllerKind string, success bool, duration time.Duration) {
	if i == nil {
		return
	}

	result := ERROR
	if success {
		result = OK
	}
	i.controllerRequests.WithLabelValues(authority, controllerName, controllerKind, MATCH, result).Inc()
	i.controllerDuration.WithLabelValues(authority, controllerName, controllerKind, MATCH, result).Observe(duration.Seconds())
}

// ObserveMatchVerdict counts match controller verdicts.
func (i *Instrumentation) ObserveMatchVerdict(authority, controllerName, controllerKind string, matched bool) {
	if i == nil {
		return
	}
	verdict := NO_MATCH_VERDICT
	if matched {
		verdict = MATCH_VERDICT
	}
	i.matchVerdicts.WithLabelValues(authority, controllerName, controllerKind, verdict).Inc()
}

// ObserveMatchDatabaseRequest records a database-backed match controller decision.
func (i *Instrumentation) ObserveMatchDatabaseRequest(authority, controllerName, controllerKind string, dbType string, matched bool, success bool) {
	if i == nil {
		return
	}
	verdict := NO_MATCH_VERDICT
	if matched {
		verdict = MATCH_VERDICT
	}
	result := ERROR
	if success {
		result = OK
	}
	i.matchDbRequests.WithLabelValues(authority, controllerName, controllerKind, dbType, verdict, result).Inc()
}

// ObserveMatchDatabaseQuery records database query outcome and duration.
func (i *Instrumentation) ObserveMatchDatabaseQuery(authority, controllerName, controllerKind string, dbType string, matched bool, err error, duration time.Duration) {
	if i == nil {
		return
	}
	verdict := NO_MATCH_VERDICT
	if matched {
		verdict = MATCH_VERDICT
	}
	result := OK
	if err != nil {
		result = ERROR
	}
	i.matchDbQueries.WithLabelValues(authority, controllerName, controllerKind, dbType, verdict, result).Inc()
	i.matchDbQueryDur.WithLabelValues(authority, controllerName, controllerKind, dbType, verdict, result).Observe(duration.Seconds())
}

// ObserveMatchDatabaseCacheHit records a cache lookup that returned an entry.
func (i *Instrumentation) ObserveMatchDatabaseCacheHit(authority, controllerName, controllerKind string, dbType string) {
	if i == nil {
		return
	}
	i.matchDbCacheReq.WithLabelValues(authority, controllerName, controllerKind, dbType, HIT).Inc()
}

// ObserveMatchDatabaseCacheMiss records a cache lookup that missed.
func (i *Instrumentation) ObserveMatchDatabaseCacheMiss(authority, controllerName, controllerKind string, dbType string) {
	if i == nil {
		return
	}
	i.matchDbCacheReq.WithLabelValues(authority, controllerName, controllerKind, dbType, MISS).Inc()
}

// ObserveMatchDatabaseCacheSize sets the current cache size gauge.
func (i *Instrumentation) ObserveMatchDatabaseCacheSize(authority, controllerName, controllerKind string, dbType string, size int) {
	if i == nil {
		return
	}
	i.matchDbCacheSize.WithLabelValues(authority, controllerName, controllerKind, dbType).Set(float64(size))
}

// ObserveMatchDatabaseUnavailable records database unavailability.
func (i *Instrumentation) ObserveMatchDatabaseUnavailable(authority, controllerName, controllerKind string, dbType string) {
	if i == nil {
		return
	}
	i.matchDbUnavailable.WithLabelValues(authority, controllerName, controllerKind, dbType).Inc()
}

// ObserveGeofenceMatch records a geofence feature match.
func (i *Instrumentation) ObserveGeofenceMatch(authority, controllerName, feature string) {
	if i == nil {
		return
	}
	i.geofenceMatchTotals.WithLabelValues(authority, controllerName, feature).Inc()
}
