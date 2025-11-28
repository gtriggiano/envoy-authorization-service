package metrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestObserveDecisionCounters(t *testing.T) {
	reg := prometheus.NewRegistry()
	inst := NewInstrumentation(reg)

	inst.ObserveAllowDecision(10 * time.Millisecond)
	inst.ObserveDenyDecision(20 * time.Millisecond)

	if v := testutil.ToFloat64(inst.requestTotals.WithLabelValues(ALLOW_DECISION)); v != 1 {
		t.Fatalf("expected 1 allow decision, got %v", v)
	}
	if v := testutil.ToFloat64(inst.requestTotals.WithLabelValues(DENY_DECISION)); v != 1 {
		t.Fatalf("expected 1 deny decision, got %v", v)
	}

	// histograms are keyed by verdict; ensure both label values were observed.
	if c := testutil.CollectAndCount(inst.requestDuration); c != 2 {
		t.Fatalf("expected requestDuration to contain two label combinations, got %d", c)
	}
}

func TestObservePhaseAndInFlight(t *testing.T) {
	reg := prometheus.NewRegistry()
	inst := NewInstrumentation(reg)

	inst.InFlight(1)
	inst.InFlight(-1)

	if v := testutil.ToFloat64(inst.inFlight); v != 0 {
		t.Fatalf("expected inFlight gauge back to zero, got %v", v)
	}

	inst.ObservePhase("c1", "kind", "analysis", "ok", 5*time.Millisecond)
	if c := testutil.CollectAndCount(inst.controllerTiming); c != 1 {
		t.Fatalf("expected controllerTiming to have one metric family, got %d", c)
	}
}
