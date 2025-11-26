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
