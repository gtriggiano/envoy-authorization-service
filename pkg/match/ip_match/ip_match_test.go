package ip_match

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"

	"github.com/gtriggiano/envoy-authorization-service/pkg/config"
	"github.com/gtriggiano/envoy-authorization-service/pkg/controller"
	"github.com/gtriggiano/envoy-authorization-service/pkg/runtime"
)

func TestMatchController_MatchResults(t *testing.T) {
	ctrl := createTestController(t, "192.168.1.0/24\n10.0.0.1")

	tests := []struct {
		name        string
		ip          string
		wantMatch   bool
		wantCode    codes.Code
		description string
	}{
		{"exact match", "10.0.0.1", true, codes.PermissionDenied, "matched"},
		{"range match", "192.168.1.42", true, codes.PermissionDenied, "matched"},
		{"no match", "203.0.113.1", false, codes.PermissionDenied, "did not match"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verdict := matchIP(t, ctrl, tt.ip)
			if verdict.IsMatch != tt.wantMatch {
				t.Fatalf("expected IsMatch=%v, got %v", tt.wantMatch, verdict.IsMatch)
			}
			if verdict.DenyCode != tt.wantCode {
				t.Fatalf("expected DenyCode=%v, got %v", tt.wantCode, verdict.DenyCode)
			}
			if verdict.Description == "" {
				t.Fatal("expected non-empty description")
			}
			if verdict.Controller != "test-controller" || verdict.ControllerType != ControllerKind {
				t.Fatalf("unexpected controller metadata: %+v", verdict)
			}
		})
	}
}

func TestMatchController_InvalidIP(t *testing.T) {
	ctrl := createTestController(t, "192.168.1.0/24")

	req := runtime.NewRequestContext(&authv3.CheckRequest{})

	verdict, err := ctrl.Match(context.Background(), req, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.IsMatch {
		t.Fatalf("expected no match for invalid IP")
	}
	if verdict.DenyCode != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", verdict.DenyCode)
	}
}

func TestMatchController_Cache(t *testing.T) {
	ctrl := createTestController(t, "192.168.1.0/24")
	ip := "192.168.1.10"

	verdict1 := matchIP(t, ctrl, ip)
	if !verdict1.IsMatch {
		t.Fatalf("expected match on first call")
	}

	c := ctrl.(*ipMatchController)
	c.cacheMu.RLock()
	if _, ok := c.cache[ip]; !ok {
		t.Fatalf("expected IP cached after first call")
	}
	c.cacheMu.RUnlock()

	verdict2 := matchIP(t, ctrl, ip)
	if verdict2.Description != verdict1.Description {
		t.Fatalf("cache hit produced different verdict")
	}
}

func TestNewMatchController_MissingCIDRList(t *testing.T) {
	cfg := config.ControllerConfig{
		Name: "test",
		Type: ControllerKind,
		Settings: map[string]any{
			"cidrList": "",
		},
	}
	_, err := newIpMatchController(context.Background(), zap.NewNop(), cfg)
	if err == nil {
		t.Fatalf("expected error for missing cidrList")
	}
}

func TestNewMatchController_InvalidPath(t *testing.T) {
	cfg := config.ControllerConfig{
		Name: "test",
		Type: ControllerKind,
		Settings: map[string]any{
			"cidrList": "/does/not/exist",
		},
	}
	_, err := newIpMatchController(context.Background(), zap.NewNop(), cfg)
	if err == nil {
		t.Fatalf("expected error for invalid cidrList path")
	}
}

// helpers
func createTestController(t *testing.T, cidrList string) controller.MatchController {
	t.Helper()
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "cidrs.txt")
	if err := os.WriteFile(path, []byte(cidrList), 0o644); err != nil {
		t.Fatalf("failed to write cidr list: %v", err)
	}
	cfg := config.ControllerConfig{
		Name: "test-controller",
		Type: ControllerKind,
		Settings: map[string]any{
			"cidrList": path,
		},
	}
	ctrl, err := newIpMatchController(context.Background(), zap.NewNop(), cfg)
	if err != nil {
		t.Fatalf("failed to create controller: %v", err)
	}
	return ctrl
}

func matchIP(t *testing.T, ctrl controller.MatchController, ip string) *controller.MatchVerdict {
	t.Helper()
	req := runtime.NewRequestContext(minimalCheckRequest(ip))
	verdict, err := ctrl.Match(context.Background(), req, nil)
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
						SocketAddress: &corev3.SocketAddress{Address: ip},
					},
				},
			},
		},
	}
}
