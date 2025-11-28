package ip_match_database

import (
	"testing"

	"google.golang.org/grpc/codes"
)

// TestCodeToMetricsResult tests the codeToResult helper
func TestCodeToMetricsResult(t *testing.T) {
	tests := []struct {
		name     string
		code     codes.Code
		expected string
	}{
		{"OK returns allow", codes.OK, "allow"},
		{"PermissionDenied returns deny", codes.PermissionDenied, "deny"},
		{"Other code returns error", codes.Internal, "error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := codeToMetricsResult(tt.code)
			if result != tt.expected {
				t.Fatalf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestIpMatchDatabaseController_DeriveCodeForInvalidIP(t *testing.T) {
	tests := []struct {
		name         string
		action       string
		expectedCode codes.Code
	}{
		{"allow action denies invalid IP", "allow", codes.PermissionDenied},
		{"deny action allows invalid IP", "deny", codes.OK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := &ipMatchDatabaseAuthorizationController{
				action: tt.action,
			}
			code := ctrl.deriveCodeForInvalidIP()
			if code != tt.expectedCode {
				t.Errorf("expected %v, got %v", tt.expectedCode, code)
			}
		})
	}
}

func TestIpMatchDatabaseController_DeriveCodeForDatabaseError(t *testing.T) {
	tests := []struct {
		name                      string
		action                    string
		alwaysDenyOnDbUnavailable bool
		expectedCode              codes.Code
	}{
		{"always deny on db unavailable", "allow", true, codes.PermissionDenied},
		{"allow action denies on db error", "allow", false, codes.PermissionDenied},
		{"deny action allows on db error", "deny", false, codes.OK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := &ipMatchDatabaseAuthorizationController{
				action:                    tt.action,
				alwaysDenyOnDbUnavailable: tt.alwaysDenyOnDbUnavailable,
			}
			code := ctrl.deriveCodeForDatabaseError()
			if code != tt.expectedCode {
				t.Errorf("expected %v, got %v", tt.expectedCode, code)
			}
		})
	}
}

func TestIpMatchDatabaseController_DeriveVerdict(t *testing.T) {
	tests := []struct {
		name         string
		action       string
		matched      bool
		expectedCode codes.Code
		reasonMatch  string
	}{
		{"allow list matched", "allow", true, codes.OK, "found in"},
		{"allow list not matched", "allow", false, codes.PermissionDenied, "not found in"},
		{"deny list matched", "deny", true, codes.PermissionDenied, "found in"},
		{"deny list not matched", "deny", false, codes.OK, "not found in"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := &ipMatchDatabaseAuthorizationController{
				action: tt.action,
				dbType: "test",
			}
			code, reason := ctrl.deriveVerdict("192.168.1.1", tt.matched)
			if code != tt.expectedCode {
				t.Errorf("expected code %v, got %v", tt.expectedCode, code)
			}
			if reason == "" {
				t.Error("expected non-empty reason")
			}
		})
	}
}

func TestIpMatchDatabaseController_InPolicy(t *testing.T) {
	tests := []struct {
		name     string
		action   string
		code     codes.Code
		expected bool
	}{
		{"allow policy with OK", "allow", codes.OK, true},
		{"allow policy with deny", "allow", codes.PermissionDenied, false},
		{"deny policy with OK", "deny", codes.OK, true},
		{"deny policy with deny", "deny", codes.PermissionDenied, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := &ipMatchDatabaseAuthorizationController{
				action: tt.action,
			}
			result := ctrl.inPolicy(tt.code)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestIpMatchDatabaseController_CreateVerdict(t *testing.T) {
	ctrl := &ipMatchDatabaseAuthorizationController{
		name:   "test-controller",
		action: "allow",
	}

	verdict := ctrl.createVerdict(codes.OK, "test reason")

	if verdict.Controller != "test-controller" {
		t.Errorf("expected controller name 'test-controller', got '%s'", verdict.Controller)
	}
	if verdict.ControllerKind != ControllerKind {
		t.Errorf("expected controller kind '%s', got '%s'", ControllerKind, verdict.ControllerKind)
	}
	if verdict.Code != codes.OK {
		t.Errorf("expected code OK, got %v", verdict.Code)
	}
	if verdict.Reason != "test reason" {
		t.Errorf("expected reason 'test reason', got '%s'", verdict.Reason)
	}
	if !verdict.InPolicy {
		t.Error("expected InPolicy to be true for allow action with OK code")
	}
}

func TestIpMatchDatabaseController_Name(t *testing.T) {
	ctrl := &ipMatchDatabaseAuthorizationController{
		name: "test-name",
	}
	if ctrl.Name() != "test-name" {
		t.Errorf("expected 'test-name', got '%s'", ctrl.Name())
	}
}

func TestIpMatchDatabaseController_Kind(t *testing.T) {
	ctrl := &ipMatchDatabaseAuthorizationController{}
	if ctrl.Kind() != ControllerKind {
		t.Errorf("expected '%s', got '%s'", ControllerKind, ctrl.Kind())
	}
}
