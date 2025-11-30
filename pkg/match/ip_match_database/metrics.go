package ip_match_database

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// Metrics are registered using promauto which uses the default registry
	requestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "envoy_authz",
		Subsystem: "ip_match_database",
		Name:      "requests_total",
		Help:      "Total authorization requests processed by controller",
	}, []string{"authority", "controller_name", "database", "result"})

	queriesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "envoy_authz",
		Subsystem: "ip_match_database",
		Name:      "queries_total",
		Help:      "Total database queries executed",
	}, []string{"authority", "controller_name", "database", "result"})

	queryDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "envoy_authz",
		Subsystem: "ip_match_database",
		Name:      "query_duration_seconds",
		Help:      "Database query duration in seconds",
		Buckets:   []float64{.001, .002, .005, .01, .025, .05, .1, .25, .5, 1},
	}, []string{"authority", "controller_name", "database"})

	cacheRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "envoy_authz",
		Subsystem: "ip_match_database",
		Name:      "cache_requests_total",
		Help:      "Total cache lookup requests",
	}, []string{"authority", "controller_name", "result"})

	cacheEntries = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "envoy_authz",
		Subsystem: "ip_match_database",
		Name:      "cache_entries",
		Help:      "Current number of entries in cache",
	}, []string{"authority", "controller_name"})

	unavailableTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "envoy_authz",
		Subsystem: "ip_match_database",
		Name:      "unavailable_total",
		Help:      "Total database unavailability events",
	}, []string{"authority", "controller_name", "database"})
)

// observeRequest records a match request result
func (c *ipMatchDatabaseController) observeRequest(authority, result string) {
	requestsTotal.WithLabelValues(authority, c.name, c.dbType, result).Inc()
}

// observeQuery records a database query
func (c *ipMatchDatabaseController) observeQuery(authority, dbType, result string, duration time.Duration) {
	queriesTotal.WithLabelValues(authority, c.name, dbType, result).Inc()
	queryDuration.WithLabelValues(authority, c.name, dbType).Observe(duration.Seconds())
}

// observeCacheHit records a cache hit
func (c *ipMatchDatabaseController) observeCacheHit(authority string) {
	cacheRequestsTotal.WithLabelValues(authority, c.name, "hit").Inc()
}

// observeCacheMiss records a cache miss
func (c *ipMatchDatabaseController) observeCacheMiss(authority string) {
	cacheRequestsTotal.WithLabelValues(authority, c.name, "miss").Inc()
}

// observeCacheSize updates the cache size gauge
func (c *ipMatchDatabaseController) observeCacheSize(authority string) {
	if c.cache != nil {
		cacheEntries.WithLabelValues(authority, c.name).Set(float64(c.cache.Size()))
	}
}

// observeUnavailable records a database unavailability event
func (c *ipMatchDatabaseController) observeUnavailable(authority, dbType string) {
	unavailableTotal.WithLabelValues(authority, c.name, dbType).Inc()
}
