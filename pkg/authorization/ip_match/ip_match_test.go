package ip_match

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"

	"github.com/gtriggiano/envoy-authorization-service/pkg/config"
	"github.com/gtriggiano/envoy-authorization-service/pkg/controller"
	"github.com/gtriggiano/envoy-authorization-service/pkg/runtime"
)

// TestIpMatchAuthorizationController_Authorize_AllowAction validates allow-mode verdicts for various CIDR matches.
func TestIpMatchAuthorizationController_Authorize_AllowAction(t *testing.T) {
	tests := []struct {
		name         string
		cidrList     string
		ipAddress    string
		expectedCode codes.Code
		expectMatch  bool
	}{
		{
			name:         "IP in allowed list - exact match",
			cidrList:     "192.168.1.0/24\n10.0.0.1",
			ipAddress:    "10.0.0.1",
			expectedCode: codes.OK,
			expectMatch:  true,
		},
		{
			name:         "IP in allowed list - network range",
			cidrList:     "192.168.1.0/24\n10.0.0.0/8",
			ipAddress:    "10.5.3.2",
			expectedCode: codes.OK,
			expectMatch:  true,
		},
		{
			name:         "IP not in allowed list",
			cidrList:     "192.168.1.0/24\n10.0.0.0/8",
			ipAddress:    "172.16.0.1",
			expectedCode: codes.PermissionDenied,
			expectMatch:  false,
		},
		{
			name:         "IP with comment in allowed list",
			cidrList:     "# Office network\n192.168.1.0/24",
			ipAddress:    "192.168.1.50",
			expectedCode: codes.OK,
			expectMatch:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := createTestController(t, tt.cidrList, "allow")
			verdict := authorizeIP(t, ctrl, tt.ipAddress)

			if verdict.Code != tt.expectedCode {
				t.Errorf("expected code %v, got %v", tt.expectedCode, verdict.Code)
			}

			if verdict.Controller != "test-controller" {
				t.Errorf("expected controller name 'test-controller', got %q", verdict.Controller)
			}

			if verdict.ControllerKind != ControllerKind {
				t.Errorf("expected controller kind %q, got %q", ControllerKind, verdict.ControllerKind)
			}

			if verdict.Reason == "" {
				t.Error("expected non-empty reason")
			}
		})
	}
}

// TestIpMatchAuthorizationController_Authorize_DenyAction validates deny-mode verdicts and reasons.
func TestIpMatchAuthorizationController_Authorize_DenyAction(t *testing.T) {
	tests := []struct {
		name         string
		cidrList     string
		ipAddress    string
		expectedCode codes.Code
		expectMatch  bool
	}{
		{
			name:         "IP in denied list",
			cidrList:     "192.168.1.0/24\n10.0.0.1",
			ipAddress:    "192.168.1.100",
			expectedCode: codes.PermissionDenied,
			expectMatch:  true,
		},
		{
			name:         "IP not in denied list - allowed",
			cidrList:     "192.168.1.0/24\n10.0.0.0/8",
			ipAddress:    "172.16.0.1",
			expectedCode: codes.OK,
			expectMatch:  false,
		},
		{
			name:         "IP with comment in denied list",
			cidrList:     "# Malicious network\n192.168.1.0/24",
			ipAddress:    "192.168.1.50",
			expectedCode: codes.PermissionDenied,
			expectMatch:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := createTestController(t, tt.cidrList, "deny")
			verdict := authorizeIP(t, ctrl, tt.ipAddress)

			if verdict.Code != tt.expectedCode {
				t.Errorf("expected code %v, got %v", tt.expectedCode, verdict.Code)
			}

			if verdict.Reason == "" {
				t.Error("expected non-empty reason")
			}
		})
	}
}

// TestIpMatchAuthorizationController_Authorize_InvalidIP ensures invalid requests yield permission denied.
func TestIpMatchAuthorizationController_Authorize_InvalidIP(t *testing.T) {
	ctrl := createTestController(t, "192.168.1.0/24", "allow")

	req := &runtime.RequestContext{
		Request:    &authv3.CheckRequest{},
		ReceivedAt: time.Now(),
		IpAddress:  netip.Addr{}, // Invalid IP
	}

	verdict, err := ctrl.Authorize(context.Background(), req, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if verdict.Code != codes.PermissionDenied {
		t.Errorf("expected PermissionDenied for invalid IP, got %v", verdict.Code)
	}

	if verdict.Reason != "unable to determine source IP address" {
		t.Errorf("unexpected reason: %q", verdict.Reason)
	}
}

// TestIpMatchAuthorizationController_Cache verifies lookup results are cached between calls.
func TestIpMatchAuthorizationController_Cache(t *testing.T) {
	ctrl := createTestController(t, "192.168.1.0/24\n10.0.0.0/8", "allow")
	ipAddress := "192.168.1.50"

	// First call - cache miss
	verdict1 := authorizeIP(t, ctrl, ipAddress)
	if verdict1.Code != codes.OK {
		t.Errorf("first call: expected OK, got %v", verdict1.Code)
	}

	// Check cache was populated
	c := ctrl.(*ipMatchAuthorizationController)
	c.cacheMu.RLock()
	cached, exists := c.cache[ipAddress]
	c.cacheMu.RUnlock()

	if !exists {
		t.Fatal("expected IP to be cached after first call")
	}

	if cached == nil {
		t.Error("cached CIDR should not be nil for IP in allowed list")
	}

	// Second call - cache hit (should return same result)
	verdict2 := authorizeIP(t, ctrl, ipAddress)
	if verdict2.Code != verdict1.Code || verdict2.Reason != verdict1.Reason {
		t.Error("second call returned different verdict than first call")
	}
}

// TestIpMatchAuthorizationController_CacheDifferentIPs confirms caching logic handles multiple IPs.
func TestIpMatchAuthorizationController_CacheDifferentIPs(t *testing.T) {
	ctrl := createTestController(t, "192.168.1.0/24", "allow")

	// Authorize multiple different IPs
	ips := []string{"192.168.1.1", "192.168.1.2", "10.0.0.1", "172.16.0.1"}
	for _, ip := range ips {
		authorizeIP(t, ctrl, ip)
	}

	// Check all are cached
	c := ctrl.(*ipMatchAuthorizationController)
	c.cacheMu.RLock()
	cacheSize := len(c.cache)
	c.cacheMu.RUnlock()

	if cacheSize != len(ips) {
		t.Errorf("expected cache size %d, got %d", len(ips), cacheSize)
	}

	// Verify each IP has correct match result cached
	expectedMatches := map[string]bool{
		"192.168.1.1": true,  // in allowed list (CIDR not nil)
		"192.168.1.2": true,  // in allowed list (CIDR not nil)
		"10.0.0.1":    false, // not in allowed list (CIDR is nil)
		"172.16.0.1":  false, // not in allowed list (CIDR is nil)
	}

	c.cacheMu.RLock()
	for ip, shouldMatch := range expectedMatches {
		cached, exists := c.cache[ip]
		if !exists {
			t.Errorf("IP %s not found in cache", ip)
			continue
		}
		if shouldMatch && cached == nil {
			t.Errorf("IP %s: expected non-nil CIDR, got nil", ip)
		} else if !shouldMatch && cached != nil {
			t.Errorf("IP %s: expected nil CIDR, got %v", ip, cached)
		}
	}
	c.cacheMu.RUnlock()
}

// TestIpMatchAuthorizationController_Name asserts Name returns the configured controller identifier.
func TestIpMatchAuthorizationController_Name(t *testing.T) {
	ctrl := createTestController(t, "192.168.1.0/24", "allow")
	if ctrl.Name() != "test-controller" {
		t.Errorf("expected name 'test-controller', got %q", ctrl.Name())
	}
}

// TestIpMatchAuthorizationController_Kind ensures Kind matches the package constant.
func TestIpMatchAuthorizationController_Kind(t *testing.T) {
	ctrl := createTestController(t, "192.168.1.0/24", "allow")
	if ctrl.Kind() != ControllerKind {
		t.Errorf("expected kind %q, got %q", ControllerKind, ctrl.Kind())
	}
}

// TestNewIpMatchAuthorizationController_InvalidAction expects configuration errors when action is unknown.
func TestNewIpMatchAuthorizationController_InvalidAction(t *testing.T) {
	tmpFile := createTempCIDRFile(t, "192.168.1.0/24")
	defer os.Remove(tmpFile)

	cfg := config.ControllerConfig{
		Name: "test",
		Type: ControllerKind,
		Settings: map[string]any{
			"cidrList": tmpFile,
			"action":   "invalid",
		},
	}

	_, err := newIpMatchAuthorizationController(context.Background(), zap.NewNop(), cfg)
	if err == nil {
		t.Fatal("expected error for invalid action, got nil")
	}
}

// TestNewIpMatchAuthorizationController_MissingCIDRList ensures the CIDR file is required.
func TestNewIpMatchAuthorizationController_MissingCIDRList(t *testing.T) {
	cfg := config.ControllerConfig{
		Name: "test",
		Type: ControllerKind,
		Settings: map[string]any{
			"action": "allow",
		},
	}

	_, err := newIpMatchAuthorizationController(context.Background(), zap.NewNop(), cfg)
	if err == nil {
		t.Fatal("expected error for missing cidrList, got nil")
	}
}

// TestNewIpMatchAuthorizationController_InvalidFilePath validates that missing CIDR files error.
func TestNewIpMatchAuthorizationController_InvalidFilePath(t *testing.T) {
	cfg := config.ControllerConfig{
		Name: "test",
		Type: ControllerKind,
		Settings: map[string]any{
			"cidrList": "/nonexistent/path/to/file.txt",
			"action":   "allow",
		},
	}

	_, err := newIpMatchAuthorizationController(context.Background(), zap.NewNop(), cfg)
	if err == nil {
		t.Fatal("expected error for nonexistent file, got nil")
	}
}

// TestComputeVerdict_ReasonFormat checks the textual reasons for each action/match combination.
func TestComputeVerdict_ReasonFormat(t *testing.T) {
	tests := []struct {
		name           string
		cidrList       string
		ipAddress      string
		action         string
		expectedReason string
	}{
		{
			name:           "Allow with comment",
			cidrList:       "# Office\n192.168.1.0/24",
			ipAddress:      "192.168.1.50",
			action:         "allow",
			expectedReason: "IP 192.168.1.50 matched allowed CIDR 192.168.1.0/24 [Office]",
		},
		{
			name:           "Allow without comment",
			cidrList:       "192.168.1.0/24",
			ipAddress:      "192.168.1.50",
			action:         "allow",
			expectedReason: "IP 192.168.1.50 matched allowed CIDR 192.168.1.0/24",
		},
		{
			name:           "Deny with comment",
			cidrList:       "# Malicious\n192.168.1.0/24",
			ipAddress:      "192.168.1.50",
			action:         "deny",
			expectedReason: "IP 192.168.1.50 matched black-listed CIDR 192.168.1.0/24 [Malicious]",
		},
		{
			name:           "Deny without comment",
			cidrList:       "192.168.1.0/24",
			ipAddress:      "192.168.1.50",
			action:         "deny",
			expectedReason: "IP 192.168.1.50 matched black-listed CIDR 192.168.1.0/24",
		},
		{
			name:           "Not in allowed list",
			cidrList:       "192.168.1.0/24",
			ipAddress:      "10.0.0.1",
			action:         "allow",
			expectedReason: "IP 10.0.0.1 not allowed",
		},
		{
			name:           "Not in denied list",
			cidrList:       "192.168.1.0/24",
			ipAddress:      "10.0.0.1",
			action:         "deny",
			expectedReason: "IP 10.0.0.1 is not black-listed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := createTestController(t, tt.cidrList, tt.action)
			verdict := authorizeIP(t, ctrl, tt.ipAddress)

			if verdict.Reason != tt.expectedReason {
				t.Errorf("expected reason %q, got %q", tt.expectedReason, verdict.Reason)
			}
		})
	}
}

// Helper functions

// createTestController builds a controller backed by a temporary CIDR file.
func createTestController(t *testing.T, cidrList string, action string) controller.AuthorizationController {
	t.Helper()

	tmpFile := createTempCIDRFile(t, cidrList)
	t.Cleanup(func() { os.Remove(tmpFile) })

	cfg := config.ControllerConfig{
		Name: "test-controller",
		Type: ControllerKind,
		Settings: map[string]any{
			"cidrList": tmpFile,
			"action":   action,
		},
	}

	ctrl, err := newIpMatchAuthorizationController(context.Background(), zap.NewNop(), cfg)
	if err != nil {
		t.Fatalf("failed to create controller: %v", err)
	}

	return ctrl
}

// createTempCIDRFile writes CIDR contents to a temp file and returns its path.
func createTempCIDRFile(t *testing.T, content string) string {
	t.Helper()

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "cidrs.txt")

	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	return tmpFile
}

// authorizeIP performs a controller Authorize call for the supplied IP.
func authorizeIP(t *testing.T, ctrl controller.AuthorizationController, ipAddress string) *controller.AuthorizationVerdict {
	t.Helper()

	addr, err := netip.ParseAddr(ipAddress)
	if err != nil {
		t.Fatalf("invalid IP address %q: %v", ipAddress, err)
	}

	req := &runtime.RequestContext{
		Request:    &authv3.CheckRequest{},
		ReceivedAt: time.Now(),
		IpAddress:  addr,
	}

	verdict, err := ctrl.Authorize(context.Background(), req, nil)
	if err != nil {
		t.Fatalf("authorize failed: %v", err)
	}

	return verdict
}
