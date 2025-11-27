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
	}, []string{"controller", "result"})

	queriesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "envoy_authz",
		Subsystem: "ip_match_database",
		Name:      "queries_total",
		Help:      "Total database queries executed",
	}, []string{"controller", "database", "result"})

	queryDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "envoy_authz",
		Subsystem: "ip_match_database",
		Name:      "query_duration_seconds",
		Help:      "Database query duration in seconds",
		Buckets:   []float64{.001, .002, .005, .01, .025, .05, .1, .25, .5, 1},
	}, []string{"controller", "database"})

	cacheRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "envoy_authz",
		Subsystem: "ip_match_database",
		Name:      "cache_requests_total",
		Help:      "Total cache lookup requests",
	}, []string{"controller", "result"})

	cacheEntries = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "envoy_authz",
		Subsystem: "ip_match_database",
		Name:      "cache_entries",
		Help:      "Current number of entries in cache",
	}, []string{"controller"})

	unavailableTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "envoy_authz",
		Subsystem: "ip_match_database",
		Name:      "unavailable_total",
		Help:      "Total database unavailability events",
	}, []string{"controller", "database"})
)

// observeRequest records an authorization request result
func (c *ipMatchDatabaseAuthorizationController) observeRequest(result string) {
	requestsTotal.WithLabelValues(c.name, result).Inc()
}

// observeQuery records a database query
func (c *ipMatchDatabaseAuthorizationController) observeQuery(dbType string, result string, duration time.Duration) {
	queriesTotal.WithLabelValues(c.name, dbType, result).Inc()
	queryDuration.WithLabelValues(c.name, dbType).Observe(duration.Seconds())
}

// observeCacheHit records a cache hit
func (c *ipMatchDatabaseAuthorizationController) observeCacheHit() {
	cacheRequestsTotal.WithLabelValues(c.name, "hit").Inc()
}

// observeCacheMiss records a cache miss
func (c *ipMatchDatabaseAuthorizationController) observeCacheMiss() {
	cacheRequestsTotal.WithLabelValues(c.name, "miss").Inc()
}

// updateCacheSize updates the cache size gauge
func (c *ipMatchDatabaseAuthorizationController) updateCacheSize() {
	if c.cache != nil {
		cacheEntries.WithLabelValues(c.name).Set(float64(c.cache.Size()))
	}
}

// observeUnavailable records a database unavailability event
func (c *ipMatchDatabaseAuthorizationController) observeUnavailable(dbType string) {
	unavailableTotal.WithLabelValues(c.name, dbType).Inc()
}
