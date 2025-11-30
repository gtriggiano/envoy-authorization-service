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

	inst.ObserveAllowDecision("allow.example", 10*time.Millisecond)
	inst.ObserveDenyDecision("deny.example", "c1", "kind", MATCH_VERDICT, OK, 20*time.Millisecond)

	if v := testutil.ToFloat64(inst.requestTotals.WithLabelValues("allow.example", ALLOW, NotAvailable, NotAvailable, NotAvailable, NotAvailable)); v != 1 {
		t.Fatalf("expected 1 allow decision, got %v", v)
	}
	if v := testutil.ToFloat64(inst.requestTotals.WithLabelValues("deny.example", DENY, "c1", "kind", MATCH_VERDICT, OK)); v != 1 {
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

	inst.InFlight("allow.example", 1)
	inst.InFlight("allow.example", -1)

	if v := testutil.ToFloat64(inst.inFlight); v != 0 {
		t.Fatalf("expected inFlight gauge back to zero, got %v", v)
	}

	inst.ObserveAnalysisControllerRequest("allow.example", "c1", "kind", true, 5*time.Millisecond)
	inst.ObserveMatchControllerRequest("allow.example", "c1", "kind", false, 6*time.Millisecond)
	if c := testutil.CollectAndCount(inst.controllerDuration); c != 2 {
		t.Fatalf("expected controllerTiming to have two label sets, got %d", c)
	}
	if v := testutil.ToFloat64(inst.controllerRequests.WithLabelValues("allow.example", "c1", "kind", ANALISYS, OK)); v != 1 {
		t.Fatalf("expected analysis OK count, got %v", v)
	}
	if v := testutil.ToFloat64(inst.controllerRequests.WithLabelValues("allow.example", "c1", "kind", MATCH, ERROR)); v != 1 {
		t.Fatalf("expected match ERROR count, got %v", v)
	}
}

func TestObserveMatchDatabase(t *testing.T) {
	reg := prometheus.NewRegistry()
	inst := NewInstrumentation(reg)

	inst.ObserveMatchDatabaseRequest("auth", "c1", "kind", POSTGRES, true, true)
	inst.ObserveMatchDatabaseRequest("auth", "c1", "kind", POSTGRES, false, false)
	inst.ObserveMatchDatabaseQuery("auth", "c1", "kind", POSTGRES, true, nil, 5*time.Millisecond)
	inst.ObserveMatchDatabaseCacheHit("auth", "c1", "kind", POSTGRES)
	inst.ObserveMatchDatabaseCacheMiss("auth", "c1", "kind", POSTGRES)
	inst.ObserveMatchDatabaseCacheSize("auth", "c1", "kind", POSTGRES, 3)
	inst.ObserveMatchDatabaseUnavailable("auth", "c1", "kind", POSTGRES)
	inst.ObserveMatchVerdict("auth", "c1", "kind", true)
	inst.ObserveMatchVerdict("auth", "c1", "kind", false)

	if v := testutil.ToFloat64(inst.matchDbRequests.WithLabelValues("auth", "c1", "kind", POSTGRES, MATCH_VERDICT, OK)); v != 1 {
		t.Fatalf("expected 1 match request, got %v", v)
	}
	if v := testutil.ToFloat64(inst.matchDbRequests.WithLabelValues("auth", "c1", "kind", POSTGRES, NO_MATCH_VERDICT, ERROR)); v != 1 {
		t.Fatalf("expected 1 error request, got %v", v)
	}
	if v := testutil.ToFloat64(inst.matchDbQueries.WithLabelValues("auth", "c1", "kind", POSTGRES, MATCH_VERDICT, OK)); v != 1 {
		t.Fatalf("expected 1 successful query, got %v", v)
	}
	if v := testutil.ToFloat64(inst.matchDbCacheReq.WithLabelValues("auth", "c1", "kind", POSTGRES, HIT)); v != 1 {
		t.Fatalf("expected 1 cache hit, got %v", v)
	}
	if v := testutil.ToFloat64(inst.matchDbCacheReq.WithLabelValues("auth", "c1", "kind", POSTGRES, MISS)); v != 1 {
		t.Fatalf("expected 1 cache miss, got %v", v)
	}
	if v := testutil.ToFloat64(inst.matchDbUnavailable.WithLabelValues("auth", "c1", "kind", POSTGRES)); v != 1 {
		t.Fatalf("expected 1 unavailable event, got %v", v)
	}
	if v := testutil.ToFloat64(inst.matchVerdicts.WithLabelValues("auth", "c1", "kind", MATCH_VERDICT)); v != 1 {
		t.Fatalf("expected 1 match verdict, got %v", v)
	}
	if v := testutil.ToFloat64(inst.matchVerdicts.WithLabelValues("auth", "c1", "kind", NO_MATCH_VERDICT)); v != 1 {
		t.Fatalf("expected 1 no-match verdict, got %v", v)
	}
}
