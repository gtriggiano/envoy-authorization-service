package asn_match_database

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/gtriggiano/envoy-authorization-service/pkg/analysis/maxmind_asn"
	"github.com/gtriggiano/envoy-authorization-service/pkg/controller"
	"github.com/gtriggiano/envoy-authorization-service/pkg/runtime"
)

func TestMatchWithoutASNReportRespectsMatchesOnFailure(t *testing.T) {
	ctrl := &asnMatchDatabaseController{
		name:             "asn-db",
		matchesOnFailure: false,
		dataSource:       &stubDataSource{},
		cache:            NewCache(time.Minute),
		dbType:           "redis",
		logger:           zap.NewNop(),
	}

	req := runtime.NewRequestContext(nil)
	verdict, err := ctrl.Match(context.Background(), req, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.IsMatch {
		t.Fatalf("expected no match when ASN data missing")
	}
}

func TestMatchDatabaseErrorUsesMatchesOnFailure(t *testing.T) {
	ctrl := &asnMatchDatabaseController{
		name:             "asn-db",
		matchesOnFailure: true,
		dataSource:       &stubDataSource{err: errors.New("boom")},
		cache:            nil,
		dbType:           "postgres",
		logger:           zap.NewNop(),
	}

	reports := controller.AnalysisReports{
		"asn": {
			ControllerKind: maxmind_asn.ControllerKind,
			Data: map[string]any{
				"result": &maxmind_asn.IpLookupResult{AutonomousSystemNumber: 64500},
			},
		},
	}

	req := runtime.NewRequestContext(nil)
	verdict, err := ctrl.Match(context.Background(), req, reports)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !verdict.IsMatch {
		t.Fatalf("expected match on failure, got %v", verdict.IsMatch)
	}
	if verdict.Description == "" {
		t.Fatalf("expected description to mention database failure")
	}
}

func TestCachePreventsRepeatedQueries(t *testing.T) {
	dataSource := &stubDataSource{matches: true}
	ctrl := &asnMatchDatabaseController{
		name:             "asn-db",
		matchesOnFailure: false,
		dataSource:       dataSource,
		cache:            NewCache(time.Minute),
		dbType:           "redis",
		logger:           zap.NewNop(),
	}

	reports := asnReports(64500)

	req := runtime.NewRequestContext(nil)
	if _, err := ctrl.Match(context.Background(), req, reports); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dataSource.containsCalls != 1 {
		t.Fatalf("expected single database query, got %d", dataSource.containsCalls)
	}

	if _, err := ctrl.Match(context.Background(), req, reports); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dataSource.containsCalls != 1 {
		t.Fatalf("expected cached result to be used")
	}
}

func asnReports(asn uint) controller.AnalysisReports {
	return controller.AnalysisReports{
		"asn": {
			ControllerKind: maxmind_asn.ControllerKind,
			Data: map[string]any{
				"result": &maxmind_asn.IpLookupResult{
					AutonomousSystemNumber:       asn,
					AutonomousSystemOrganization: "test",
				},
			},
		},
	}
}

type stubDataSource struct {
	matches       bool
	err           error
	containsCalls int
}

func (s *stubDataSource) Contains(ctx context.Context, asn uint) (bool, error) {
	s.containsCalls++
	return s.matches, s.err
}

func (s *stubDataSource) Close() error { return nil }

func (s *stubDataSource) HealthCheck(ctx context.Context) error { return nil }
