package asn_match

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"

	"github.com/gtriggiano/envoy-authorization-service/pkg/analysis/maxmind_asn"
	"github.com/gtriggiano/envoy-authorization-service/pkg/config"
	"github.com/gtriggiano/envoy-authorization-service/pkg/controller"
	"github.com/gtriggiano/envoy-authorization-service/pkg/runtime"
)

func TestASNMatchController_Match(t *testing.T) {
	ctrl := createTestController(t, "# ExampleNet\n64500\n# AnotherNet\n64501")

	tests := []struct {
		name      string
		reportASN uint
		wantMatch bool
	}{
		{"match first", 64500, true},
		{"match second", 64501, true},
		{"no match", 64510, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verdict := matchASN(t, ctrl, tt.reportASN)
			if verdict.IsMatch != tt.wantMatch {
				t.Fatalf("expected IsMatch=%v, got %v", tt.wantMatch, verdict.IsMatch)
			}
			if verdict.DenyCode != codes.PermissionDenied {
				t.Fatalf("expected DenyCode PermissionDenied, got %v", verdict.DenyCode)
			}
			if verdict.Description == "" {
				t.Fatal("expected description")
			}
		})
	}
}

func TestASNMatchController_NoReport(t *testing.T) {
	ctrl := createTestController(t, "64500 ExampleNet")
	req := runtime.NewRequestContext(minimalCheckRequest("198.51.100.1"))
	verdict, err := ctrl.Match(context.Background(), req, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.IsMatch {
		t.Fatalf("expected no match without analysis report")
	}
}

func TestNewASNMatchController_InvalidPath(t *testing.T) {
	cfg := config.ControllerConfig{
		Name: "asn-test",
		Type: ControllerKind,
		Settings: map[string]any{
			"asnList": "/missing/file",
		},
	}
	if _, err := newASNMatchController(context.Background(), zap.NewNop(), cfg); err == nil {
		t.Fatalf("expected error for missing list file")
	}
}

// helpers
func createTestController(t *testing.T, asnList string) controller.MatchController {
	t.Helper()
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "asn.txt")
	if err := os.WriteFile(path, []byte(asnList), 0o644); err != nil {
		t.Fatalf("write asn list: %v", err)
	}
	cfg := config.ControllerConfig{
		Name: "asn-controller",
		Type: ControllerKind,
		Settings: map[string]any{
			"asnList": path,
		},
	}
	ctrl, err := newASNMatchController(context.Background(), zap.NewNop(), cfg)
	if err != nil {
		t.Fatalf("create controller: %v", err)
	}
	return ctrl
}

func matchASN(t *testing.T, ctrl controller.MatchController, asn uint) *controller.MatchVerdict {
	t.Helper()
	req := runtime.NewRequestContext(minimalCheckRequest("198.51.100.1"))
	reports := controller.AnalysisReports{
		"asn": {
			ControllerKind: maxmind_asn.ControllerKind,
			Data: map[string]any{
				"result": &maxmind_asn.IpLookupResult{
					AutonomousSystemNumber:       asn,
					AutonomousSystemOrganization: "Org",
				},
			},
		},
	}
	verdict, err := ctrl.Match(context.Background(), req, reports)
	if err != nil {
		t.Fatalf("match returned error: %v", err)
	}
	return verdict
}

func minimalCheckRequest(ip string) *authv3.CheckRequest {
	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Source: &authv3.AttributeContext_Peer{
				Address: &corev3.Address{
					Address: &corev3.Address_SocketAddress{
						SocketAddress: &corev3.SocketAddress{
							Address:       ip,
							PortSpecifier: &corev3.SocketAddress_PortValue{PortValue: 80},
						},
					},
				},
			},
		},
	}
}
