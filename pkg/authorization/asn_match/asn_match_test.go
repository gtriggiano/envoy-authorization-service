package asn_match

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"

	"github.com/gtriggiano/envoy-authorization-service/pkg/analysis/maxmind_asn"
	"github.com/gtriggiano/envoy-authorization-service/pkg/config"
	"github.com/gtriggiano/envoy-authorization-service/pkg/controller"
	"github.com/gtriggiano/envoy-authorization-service/pkg/runtime"
)

// TestASNMatchAuthorizationController_Authorize_AllowAction exercises allow-mode verdicts across scenarios.
func TestASNMatchAuthorizationController_Authorize_AllowAction(t *testing.T) {
	tests := []struct {
		name         string
		asnList      string
		asn          uint
		asnOrg       string
		expectedCode codes.Code
		expectMatch  bool
	}{
		{
			name:         "ASN in allowed list - exact match",
			asnList:      "13335\n15169",
			asn:          13335,
			asnOrg:       "Cloudflare, Inc.",
			expectedCode: codes.OK,
			expectMatch:  true,
		},
		{
			name:         "ASN in allowed list - second entry",
			asnList:      "13335\n15169",
			asn:          15169,
			asnOrg:       "Google LLC",
			expectedCode: codes.OK,
			expectMatch:  true,
		},
		{
			name:         "ASN not in allowed list",
			asnList:      "13335\n15169",
			asn:          16509,
			asnOrg:       "Amazon.com, Inc.",
			expectedCode: codes.PermissionDenied,
			expectMatch:  false,
		},
		{
			name:         "ASN with comment in allowed list",
			asnList:      "# Cloudflare CDN\n13335",
			asn:          13335,
			asnOrg:       "Cloudflare, Inc.",
			expectedCode: codes.OK,
			expectMatch:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := createTestController(t, tt.asnList, "allow")
			verdict := authorizeASN(t, ctrl, tt.asn, tt.asnOrg)

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

// TestASNMatchAuthorizationController_Authorize_DenyAction ensures deny-mode verdicts behave correctly.
func TestASNMatchAuthorizationController_Authorize_DenyAction(t *testing.T) {
	tests := []struct {
		name         string
		asnList      string
		asn          uint
		asnOrg       string
		expectedCode codes.Code
		expectMatch  bool
	}{
		{
			name:         "ASN in denied list",
			asnList:      "13335\n15169",
			asn:          13335,
			asnOrg:       "Cloudflare, Inc.",
			expectedCode: codes.PermissionDenied,
			expectMatch:  true,
		},
		{
			name:         "ASN not in denied list - allowed",
			asnList:      "13335\n15169",
			asn:          16509,
			asnOrg:       "Amazon.com, Inc.",
			expectedCode: codes.OK,
			expectMatch:  false,
		},
		{
			name:         "ASN with comment in denied list",
			asnList:      "# Blocked network\n13335",
			asn:          13335,
			asnOrg:       "Cloudflare, Inc.",
			expectedCode: codes.PermissionDenied,
			expectMatch:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := createTestController(t, tt.asnList, "deny")
			verdict := authorizeASN(t, ctrl, tt.asn, tt.asnOrg)

			if verdict.Code != tt.expectedCode {
				t.Errorf("expected code %v, got %v", tt.expectedCode, verdict.Code)
			}

			if verdict.Reason == "" {
				t.Error("expected non-empty reason")
			}
		})
	}
}

// TestASNMatchAuthorizationController_Authorize_NoASNInformation verifies fallback behavior without analysis data.
func TestASNMatchAuthorizationController_Authorize_NoASNInformation(t *testing.T) {
	tests := []struct {
		name         string
		action       string
		expectedCode codes.Code
	}{
		{
			name:         "Allow action with no ASN info",
			action:       "allow",
			expectedCode: codes.PermissionDenied,
		},
		{
			name:         "Deny action with no ASN info",
			action:       "deny",
			expectedCode: codes.OK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := createTestController(t, "13335", tt.action)

			req := &runtime.RequestContext{
				Request:    &authv3.CheckRequest{},
				ReceivedAt: time.Now(),
				IpAddress:  netip.MustParseAddr("192.168.1.1"),
			}

			// Pass empty reports - no ASN analysis available
			verdict, err := ctrl.Authorize(context.Background(), req, controller.AnalysisReports{})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if verdict.Code != tt.expectedCode {
				t.Errorf("expected code %v for action %q with no ASN info, got %v", tt.expectedCode, tt.action, verdict.Code)
			}

			if verdict.Reason != "no ASN information available" {
				t.Errorf("unexpected reason: %q", verdict.Reason)
			}
		})
	}
}

// TestASNMatchAuthorizationController_Authorize_WrongReportKind confirms unrelated reports are ignored.
func TestASNMatchAuthorizationController_Authorize_WrongReportKind(t *testing.T) {
	ctrl := createTestController(t, "13335", "allow")

	req := &runtime.RequestContext{
		Request:    &authv3.CheckRequest{},
		ReceivedAt: time.Now(),
		IpAddress:  netip.MustParseAddr("192.168.1.1"),
	}

	// Pass reports with wrong controller kind
	reports := controller.AnalysisReports{
		"other": {
			Controller:     "other",
			ControllerKind: "other-kind",
			Data:           map[string]any{},
		},
	}

	verdict, err := ctrl.Authorize(context.Background(), req, reports)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should be treated as no ASN info available
	if verdict.Code != codes.PermissionDenied {
		t.Errorf("expected PermissionDenied for allow action with no valid ASN report, got %v", verdict.Code)
	}

	if verdict.Reason != "no ASN information available" {
		t.Errorf("unexpected reason: %q", verdict.Reason)
	}
}

// TestASNMatchAuthorizationController_Authorize_NilReport ensures nil reports don't panic and deny appropriately.
func TestASNMatchAuthorizationController_Authorize_NilReport(t *testing.T) {
	ctrl := createTestController(t, "13335", "allow")

	req := &runtime.RequestContext{
		Request:    &authv3.CheckRequest{},
		ReceivedAt: time.Now(),
		IpAddress:  netip.MustParseAddr("192.168.1.1"),
	}

	// Pass reports with nil entry
	reports := controller.AnalysisReports{
		"maxmind": nil,
	}

	verdict, err := ctrl.Authorize(context.Background(), req, reports)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should be treated as no ASN info available
	if verdict.Code != codes.PermissionDenied {
		t.Errorf("expected PermissionDenied for allow action with nil report, got %v", verdict.Code)
	}
}

// TestASNMatchAuthorizationController_Name ensures Name returns the configured identifier.
func TestASNMatchAuthorizationController_Name(t *testing.T) {
	ctrl := createTestController(t, "13335", "allow")
	if ctrl.Name() != "test-controller" {
		t.Errorf("expected name 'test-controller', got %q", ctrl.Name())
	}
}

// TestASNMatchAuthorizationController_Kind ensures Kind matches the package constant.
func TestASNMatchAuthorizationController_Kind(t *testing.T) {
	ctrl := createTestController(t, "13335", "allow")
	if ctrl.Kind() != ControllerKind {
		t.Errorf("expected kind %q, got %q", ControllerKind, ctrl.Kind())
	}
}

// TestNewASNMatchAuthorizationController_InvalidAction validates configuration errors surface for unknown actions.
func TestNewASNMatchAuthorizationController_InvalidAction(t *testing.T) {
	tmpFile := createTempASNFile(t, "13335")
	defer os.Remove(tmpFile)

	cfg := config.ControllerConfig{
		Name: "test",
		Type: ControllerKind,
		Settings: map[string]any{
			"asnList": tmpFile,
			"action":  "invalid",
		},
	}

	_, err := newASNMatchAuthorizationController(context.Background(), zap.NewNop(), cfg)
	if err == nil {
		t.Fatal("expected error for invalid action, got nil")
	}

	expectedMsg := "action must be 'allow' or 'deny', check your configuration"
	if err.Error() != expectedMsg {
		t.Errorf("expected error message %q, got %q", expectedMsg, err.Error())
	}
}

// TestNewASNMatchAuthorizationController_MissingASNList verifies the ASN list path is required.
func TestNewASNMatchAuthorizationController_MissingASNList(t *testing.T) {
	cfg := config.ControllerConfig{
		Name: "test",
		Type: ControllerKind,
		Settings: map[string]any{
			"action": "allow",
		},
	}

	_, err := newASNMatchAuthorizationController(context.Background(), zap.NewNop(), cfg)
	if err == nil {
		t.Fatal("expected error for missing asnList, got nil")
	}

	expectedMsg := "asnList is required, check your configuration"
	if err.Error() != expectedMsg {
		t.Errorf("expected error message %q, got %q", expectedMsg, err.Error())
	}
}

// TestNewASNMatchAuthorizationController_InvalidFilePath expects missing files to trigger errors.
func TestNewASNMatchAuthorizationController_InvalidFilePath(t *testing.T) {
	cfg := config.ControllerConfig{
		Name: "test",
		Type: ControllerKind,
		Settings: map[string]any{
			"asnList": "/nonexistent/path/to/file.txt",
			"action":  "allow",
		},
	}

	_, err := newASNMatchAuthorizationController(context.Background(), zap.NewNop(), cfg)
	if err == nil {
		t.Fatal("expected error for nonexistent file, got nil")
	}
}

// TestDeriveVerdict_ReasonFormat checks the user-facing reason strings.
func TestDeriveVerdict_ReasonFormat(t *testing.T) {
	tests := []struct {
		name           string
		asnList        string
		asn            uint
		asnOrg         string
		action         string
		expectedReason string
	}{
		{
			name:           "Allow with comment",
			asnList:        "# Cloudflare CDN\n13335",
			asn:            13335,
			asnOrg:         "Cloudflare, Inc.",
			action:         "allow",
			expectedReason: "AS 13335 Cloudflare, Inc. (Cloudflare CDN) matched allow list",
		},
		{
			name:           "Allow without comment",
			asnList:        "13335",
			asn:            13335,
			asnOrg:         "Cloudflare, Inc.",
			action:         "allow",
			expectedReason: "AS 13335 Cloudflare, Inc. matched allow list",
		},
		{
			name:           "Deny with comment",
			asnList:        "# Blocked network\n13335",
			asn:            13335,
			asnOrg:         "Cloudflare, Inc.",
			action:         "deny",
			expectedReason: "AS 13335 Cloudflare, Inc. (Blocked network) matched deny list",
		},
		{
			name:           "Deny without comment",
			asnList:        "13335",
			asn:            13335,
			asnOrg:         "Cloudflare, Inc.",
			action:         "deny",
			expectedReason: "AS 13335 Cloudflare, Inc. matched deny list",
		},
		{
			name:           "Not in allowed list",
			asnList:        "13335",
			asn:            15169,
			asnOrg:         "Google LLC",
			action:         "allow",
			expectedReason: "AS 15169 Google LLC did not match allow list",
		},
		{
			name:           "Not in denied list",
			asnList:        "13335",
			asn:            15169,
			asnOrg:         "Google LLC",
			action:         "deny",
			expectedReason: "AS 15169 Google LLC did not match deny list",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := createTestController(t, tt.asnList, tt.action)
			verdict := authorizeASN(t, ctrl, tt.asn, tt.asnOrg)

			if verdict.Reason != tt.expectedReason {
				t.Errorf("expected reason %q, got %q", tt.expectedReason, verdict.Reason)
			}
		})
	}
}

// TestDeriveVerdict_MultipleASNs validates behavior when many ASNs are listed.
func TestDeriveVerdict_MultipleASNs(t *testing.T) {
	asnList := `# Cloudflare
13335
# Google
15169
# Amazon
16509`

	ctrl := createTestController(t, asnList, "allow")

	testCases := []struct {
		asn          uint
		asnOrg       string
		expectedCode codes.Code
		shouldMatch  bool
	}{
		{13335, "Cloudflare, Inc.", codes.OK, true},
		{15169, "Google LLC", codes.OK, true},
		{16509, "Amazon.com, Inc.", codes.OK, true},
		{8075, "Microsoft Corporation", codes.PermissionDenied, false},
	}

	for _, tc := range testCases {
		verdict := authorizeASN(t, ctrl, tc.asn, tc.asnOrg)
		if verdict.Code != tc.expectedCode {
			t.Errorf("ASN %d: expected code %v, got %v", tc.asn, tc.expectedCode, verdict.Code)
		}
	}
}

// TestDeriveVerdict_EmptyASNList ensures empty allow lists deny traffic.
func TestDeriveVerdict_EmptyASNList(t *testing.T) {
	ctrl := createTestController(t, "", "allow")
	verdict := authorizeASN(t, ctrl, 13335, "Cloudflare, Inc.")

	if verdict.Code != codes.PermissionDenied {
		t.Errorf("expected PermissionDenied for empty allow list, got %v", verdict.Code)
	}
}

// TestDeriveVerdict_ASNWithBlankLines confirms blank lines do not break parsing.
func TestDeriveVerdict_ASNWithBlankLines(t *testing.T) {
	asnList := `
13335

15169

`
	ctrl := createTestController(t, asnList, "allow")

	// Both ASNs should be recognized despite blank lines
	verdict1 := authorizeASN(t, ctrl, 13335, "Cloudflare, Inc.")
	if verdict1.Code != codes.OK {
		t.Errorf("expected OK for ASN 13335, got %v", verdict1.Code)
	}

	verdict2 := authorizeASN(t, ctrl, 15169, "Google LLC")
	if verdict2.Code != codes.OK {
		t.Errorf("expected OK for ASN 15169, got %v", verdict2.Code)
	}
}

// TestDeriveVerdict_AllowAndDenyLogic validates allow/deny matrix outcomes.
func TestDeriveVerdict_AllowAndDenyLogic(t *testing.T) {
	tests := []struct {
		name           string
		action         string
		asnInList      bool
		expectedCode   codes.Code
		asnNum         uint
		reasonContains string
	}{
		{
			name:           "Allow action, ASN in list",
			action:         "allow",
			asnInList:      true,
			expectedCode:   codes.OK,
			asnNum:         13335,
			reasonContains: "matched allow list",
		},
		{
			name:           "Allow action, ASN not in list",
			action:         "allow",
			asnInList:      false,
			expectedCode:   codes.PermissionDenied,
			asnNum:         99999,
			reasonContains: "did not match allow list",
		},
		{
			name:           "Deny action, ASN in list",
			action:         "deny",
			asnInList:      true,
			expectedCode:   codes.PermissionDenied,
			asnNum:         13335,
			reasonContains: "matched deny list",
		},
		{
			name:           "Deny action, ASN not in list",
			action:         "deny",
			asnInList:      false,
			expectedCode:   codes.OK,
			asnNum:         99999,
			reasonContains: "did not match deny list",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := createTestController(t, "13335\n15169", tt.action)
			verdict := authorizeASN(t, ctrl, tt.asnNum, "Test Organization")

			if verdict.Code != tt.expectedCode {
				t.Errorf("expected code %v, got %v", tt.expectedCode, verdict.Code)
			}

			if tt.reasonContains != "" && !strings.Contains(verdict.Reason, tt.reasonContains) {
				t.Errorf("expected reason to contain %q, got %q", tt.reasonContains, verdict.Reason)
			}
		})
	}
}

// TestASNMatchAuthorizationController_DecodeError ensures invalid settings shape returns an error.
func TestASNMatchAuthorizationController_DecodeError(t *testing.T) {
	cfg := config.ControllerConfig{
		Name: "test",
		Type: ControllerKind,
		Settings: map[string]any{
			"asnList": []int{1, 2, 3}, // Invalid type - should be string
			"action":  "allow",
		},
	}

	_, err := newASNMatchAuthorizationController(context.Background(), zap.NewNop(), cfg)
	if err == nil {
		t.Fatal("expected error for invalid settings decode, got nil")
	}
}

// TestASNMatchAuthorizationController_ASNListParsing ensures the list is parsed and deduplicated.
func TestASNMatchAuthorizationController_ASNListParsing(t *testing.T) {
	// Test that ASN list is properly parsed and deduplicated
	asnList := `13335
# Duplicate entry
13335
15169`

	ctrl := createTestController(t, asnList, "allow")
	c := ctrl.(*asnMatchAuthorizationController)

	// Should have both ASNs (deduplication is handled by asnlist.Synthesize)
	if len(c.asnMap) == 0 {
		t.Error("expected non-empty ASN map")
	}

	if _, exists := c.asnMap[13335]; !exists {
		t.Error("expected ASN 13335 to be in map")
	}

	if _, exists := c.asnMap[15169]; !exists {
		t.Error("expected ASN 15169 to be in map")
	}
}

// Helper functions

// createTestController builds an ASN controller backed by a temporary file.
func createTestController(t *testing.T, asnList string, action string) controller.AuthorizationController {
	t.Helper()

	tmpFile := createTempASNFile(t, asnList)
	t.Cleanup(func() { os.Remove(tmpFile) })

	cfg := config.ControllerConfig{
		Name: "test-controller",
		Type: ControllerKind,
		Settings: map[string]any{
			"asnList": tmpFile,
			"action":  action,
		},
	}

	ctrl, err := newASNMatchAuthorizationController(context.Background(), zap.NewNop(), cfg)
	if err != nil {
		t.Fatalf("failed to create controller: %v", err)
	}

	return ctrl
}

// createTempASNFile writes ASN data to a temporary file for tests.
func createTempASNFile(t *testing.T, content string) string {
	t.Helper()

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "asns.txt")

	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	return tmpFile
}

// authorizeASN performs the authorization call with fabricated MaxMind reports.
func authorizeASN(t *testing.T, ctrl controller.AuthorizationController, asn uint, asnOrg string) *controller.AuthorizationVerdict {
	t.Helper()

	req := &runtime.RequestContext{
		Request:    &authv3.CheckRequest{},
		ReceivedAt: time.Now(),
		IpAddress:  netip.MustParseAddr("192.168.1.1"),
	}

	// Create an analysis report with ASN information
	reports := controller.AnalysisReports{
		"maxmind-asn": {
			Controller:     "maxmind-asn",
			ControllerKind: maxmind_asn.ControllerKind,
			Data: map[string]any{
				"result": &maxmind_asn.IpLookupResult{
					AutonomousSystemNumber:       asn,
					AutonomousSystemOrganization: asnOrg,
				},
			},
		},
	}

	verdict, err := ctrl.Authorize(context.Background(), req, reports)
	if err != nil {
		t.Fatalf("authorize failed: %v", err)
	}

	return verdict
}
