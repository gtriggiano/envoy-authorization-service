package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	ALLOW_DECISION = "ALLOW"
	DENY_DECISION  = "DENY"
)

// Instrumentation publishes Prometheus metrics for the authorization flow.
type Instrumentation struct {
	requestTotals    *prometheus.CounterVec
	requestDuration  *prometheus.HistogramVec
	controllerTiming *prometheus.HistogramVec
	inFlight         prometheus.Gauge
}

// NewInstrumentation registers all metric vectors.
func NewInstrumentation(reg prometheus.Registerer) *Instrumentation {
	inst := &Instrumentation{
		requestTotals: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "envoy_authz",
			Name:      "requests_total",
			Help:      "Total authorization decisions by result",
		}, []string{"verdict"}),
		requestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "envoy_authz",
			Name:      "request_duration_seconds",
			Help:      "End-to-end authorization latency",
			Buckets:   []float64{.00005, .0001, .0005, .001, .002, .005, .01, .025, .05, .1, .25, .5},
		}, []string{"verdict"}),
		controllerTiming: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "envoy_authz",
			Name:      "controller_phase_duration_seconds",
			Help:      "Controller phase execution time",
			Buckets:   []float64{.00005, .0001, .0005, .001, .002, .005, .01, .025, .05, .1, .25, .5},
		}, []string{"controller_name", "controller_kind", "phase", "result"}),
		inFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "envoy_authz",
			Name:      "inflight_requests",
			Help:      "Active authorization requests",
		}),
	}

	reg.MustRegister(inst.requestTotals, inst.requestDuration, inst.controllerTiming, inst.inFlight)
	return inst
}

// ObserveDenyDecision records a deny decision and duration.
func (i *Instrumentation) ObserveDenyDecision(duration time.Duration) {
	i.requestTotals.WithLabelValues(DENY_DECISION).Inc()
	i.requestDuration.WithLabelValues(DENY_DECISION).Observe(duration.Seconds())
}

// ObserveAllowDecision records an allow decision and duration.
func (i *Instrumentation) ObserveAllowDecision(duration time.Duration) {
	i.requestTotals.WithLabelValues(ALLOW_DECISION).Inc()
	i.requestDuration.WithLabelValues(ALLOW_DECISION).Observe(duration.Seconds())
}

// ObservePhase records controller phase latencies.
func (i *Instrumentation) ObservePhase(controllerName, controllerKind, phase, result string, duration time.Duration) {
	i.controllerTiming.WithLabelValues(controllerName, controllerKind, phase, result).Observe(duration.Seconds())
}

// InFlight increments or decrements the in-flight gauge.
func (i *Instrumentation) InFlight(delta float64) {
	if delta == 0 {
		return
	}
	if delta > 0 {
		i.inFlight.Add(delta)
		return
	}
	i.inFlight.Sub(-delta)
}
