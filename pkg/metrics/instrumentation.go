package metrics

import (
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Instrumentation publishes Prometheus metrics for the authorization flow.
type Instrumentation struct {
	requestTotals    *prometheus.CounterVec
	requestDuration  *prometheus.HistogramVec
	controllerTiming *prometheus.HistogramVec
	inFlight         prometheus.Gauge
	ready            atomic.Bool
}

// NewInstrumentation registers all metric vectors.
func NewInstrumentation(reg prometheus.Registerer) *Instrumentation {
	inst := &Instrumentation{
		requestTotals: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "envoy_authorization_service",
			Name:      "requests_total",
			Help:      "Total authorization decisions by result",
		}, []string{"decision"}),
		requestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "envoy_authorization_service",
			Name:      "request_duration_seconds",
			Help:      "End-to-end authorization latency",
			Buckets:   []float64{.001, .002, .005, .01, .025, .05, .1, .25, .5, 1, 2.5},
		}, []string{"decision"}),
		controllerTiming: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "envoy_authorization_service",
			Name:      "controller_phase_duration_seconds",
			Help:      "Controller phase execution time",
			Buckets:   []float64{.001, .002, .005, .01, .025, .05, .1, .25, .5, 1, 2.5},
		}, []string{"controller", "controller_kind", "phase", "result"}),
		inFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "envoy_authorization_service",
			Name:      "inflight_requests",
			Help:      "Active authorization requests",
		}),
	}

	reg.MustRegister(inst.requestTotals, inst.requestDuration, inst.controllerTiming, inst.inFlight)
	return inst
}

// ObserveDecision records the overall decision and duration.
func (i *Instrumentation) ObserveDecision(decision string, duration time.Duration) {
	i.requestTotals.WithLabelValues(decision).Inc()
	i.requestDuration.WithLabelValues(decision).Observe(duration.Seconds())
}

// ObservePhase records controller phase latencies.
func (i *Instrumentation) ObservePhase(controller, controllerKind, phase, result string, duration time.Duration) {
	i.controllerTiming.WithLabelValues(controller, controllerKind, phase, result).Observe(duration.Seconds())
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

// Ready reports readiness to health probes.
func (i *Instrumentation) Ready() bool {
	return i.ready.Load()
}

// SetReady flips readiness status.
func (i *Instrumentation) SetReady(ready bool) {
	i.ready.Store(ready)
}
