package controller

import (
	"context"
	"testing"

	"go.uber.org/zap"
	"google.golang.org/grpc/codes"

	"github.com/gtriggiano/envoy-authorization-service/pkg/config"
	"github.com/gtriggiano/envoy-authorization-service/pkg/runtime"
)

// Mock implementations for testing
type mockAnalysisController struct {
	name       string
	kind       string
	report     *AnalysisReport
	healthErr  error
	analyzeErr error
}

func (m *mockAnalysisController) Name() string { return m.name }
func (m *mockAnalysisController) Kind() string { return m.kind }
func (m *mockAnalysisController) Analyze(ctx context.Context, req *runtime.RequestContext) (*AnalysisReport, error) {
	return m.report, m.analyzeErr
}
func (m *mockAnalysisController) HealthCheck(ctx context.Context) error { return m.healthErr }

type mockAuthorizationController struct {
	name         string
	kind         string
	verdict      *AuthorizationVerdict
	healthErr    error
	authorizeErr error
}

func (m *mockAuthorizationController) Name() string { return m.name }
func (m *mockAuthorizationController) Kind() string { return m.kind }
func (m *mockAuthorizationController) Authorize(ctx context.Context, req *runtime.RequestContext, reports AnalysisReports) (*AuthorizationVerdict, error) {
	return m.verdict, m.authorizeErr
}
func (m *mockAuthorizationController) HealthCheck(ctx context.Context) error { return m.healthErr }

func TestAuthorizationVerdict_IsAllow(t *testing.T) {
	tests := []struct {
		name     string
		code     codes.Code
		expected bool
	}{
		{"OK is allow", codes.OK, true},
		{"PermissionDenied is not allow", codes.PermissionDenied, false},
		{"Internal is not allow", codes.Internal, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			av := &AuthorizationVerdict{Code: tt.code}
			if got := av.IsAllow(); got != tt.expected {
				t.Errorf("IsAllow() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestAuthorizationVerdict_IsDeny(t *testing.T) {
	tests := []struct {
		name     string
		code     codes.Code
		expected bool
	}{
		{"OK is not deny", codes.OK, false},
		{"PermissionDenied is deny", codes.PermissionDenied, true},
		{"Internal is deny", codes.Internal, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			av := &AuthorizationVerdict{Code: tt.code}
			if got := av.IsDeny(); got != tt.expected {
				t.Errorf("IsDeny() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestRegisterAnalysis(t *testing.T) {
	// Reset registry for test isolation
	oldReg := analysisRegistry
	t.Cleanup(func() {
		analysisRegistry = oldReg
	})
	analysisRegistry = newRegistry[AnalysisFactory]()

	factory := func(ctx context.Context, logger *zap.Logger, cfg config.ControllerConfig) (AnalysisController, error) {
		return &mockAnalysisController{name: cfg.Name, kind: "test"}, nil
	}

	t.Run("successful registration", func(t *testing.T) {
		RegisterAnalysis("test-type", factory)

		f, ok := getFactory(analysisRegistry, "test-type")
		if !ok {
			t.Error("factory not found after registration")
		}
		if f == nil {
			t.Error("factory is nil")
		}
	})

	t.Run("panic on duplicate registration", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic on duplicate registration")
			}
		}()
		RegisterAnalysis("test-type", factory)
	})

	t.Run("panic on empty kind", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic on empty kind")
			}
		}()
		RegisterAnalysis("", factory)
	})
}

func TestRegisterAuthorization(t *testing.T) {
	// Reset registry for test isolation
	oldReg := authorizationRegistry
	t.Cleanup(func() {
		authorizationRegistry = oldReg
	})
	authorizationRegistry = newRegistry[AuthorizationFactory]()

	factory := func(ctx context.Context, logger *zap.Logger, cfg config.ControllerConfig) (AuthorizationController, error) {
		return &mockAuthorizationController{name: cfg.Name, kind: "test"}, nil
	}

	t.Run("successful registration", func(t *testing.T) {
		RegisterAuthorization("test-type", factory)

		f, ok := getFactory(authorizationRegistry, "test-type")
		if !ok {
			t.Error("factory not found after registration")
		}
		if f == nil {
			t.Error("factory is nil")
		}
	})

	t.Run("panic on duplicate registration", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic on duplicate registration")
			}
		}()
		RegisterAuthorization("test-type", factory)
	})
}

func TestBuildAnalysisControllers(t *testing.T) {
	// Reset registry for test isolation
	oldReg := analysisRegistry
	t.Cleanup(func() {
		analysisRegistry = oldReg
	})
	analysisRegistry = newRegistry[AnalysisFactory]()

	factory := func(ctx context.Context, logger *zap.Logger, cfg config.ControllerConfig) (AnalysisController, error) {
		return &mockAnalysisController{name: cfg.Name, kind: cfg.Type}, nil
	}
	RegisterAnalysis("mock-type", factory)

	logger, _ := zap.NewDevelopment()
	ctx := context.Background()

	t.Run("builds enabled controllers", func(t *testing.T) {
		enabled := true
		configs := []config.ControllerConfig{
			{Name: "controller1", Type: "mock-type", Enabled: &enabled},
			{Name: "controller2", Type: "mock-type", Enabled: &enabled},
		}

		controllers, err := BuildAnalysisControllers(ctx, logger, configs)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(controllers) != 2 {
			t.Errorf("expected 2 controllers, got %d", len(controllers))
		}
	})

	t.Run("skips disabled controllers", func(t *testing.T) {
		enabled := true
		disabled := false
		configs := []config.ControllerConfig{
			{Name: "controller1", Type: "mock-type", Enabled: &enabled},
			{Name: "controller2", Type: "mock-type", Enabled: &disabled},
		}

		controllers, err := BuildAnalysisControllers(ctx, logger, configs)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(controllers) != 1 {
			t.Errorf("expected 1 controller, got %d", len(controllers))
		}
	})

	t.Run("returns error for unknown type", func(t *testing.T) {
		enabled := true
		configs := []config.ControllerConfig{
			{Name: "controller1", Type: "unknown-type", Enabled: &enabled},
		}

		_, err := BuildAnalysisControllers(ctx, logger, configs)
		if err == nil {
			t.Error("expected error for unknown type")
		}
	})
}

func TestBuildAuthorizationControllers(t *testing.T) {
	// Reset registry for test isolation
	oldReg := authorizationRegistry
	t.Cleanup(func() {
		authorizationRegistry = oldReg
	})
	authorizationRegistry = newRegistry[AuthorizationFactory]()

	factory := func(ctx context.Context, logger *zap.Logger, cfg config.ControllerConfig) (AuthorizationController, error) {
		return &mockAuthorizationController{name: cfg.Name, kind: cfg.Type}, nil
	}
	RegisterAuthorization("mock-type", factory)

	logger, _ := zap.NewDevelopment()
	ctx := context.Background()

	t.Run("builds enabled controllers", func(t *testing.T) {
		enabled := true
		configs := []config.ControllerConfig{
			{Name: "controller1", Type: "mock-type", Enabled: &enabled},
			{Name: "controller2", Type: "mock-type", Enabled: &enabled},
		}

		controllers, err := BuildAuthorizationControllers(ctx, logger, configs)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(controllers) != 2 {
			t.Errorf("expected 2 controllers, got %d", len(controllers))
		}
	})

	t.Run("skips disabled controllers", func(t *testing.T) {
		enabled := true
		disabled := false
		configs := []config.ControllerConfig{
			{Name: "controller1", Type: "mock-type", Enabled: &enabled},
			{Name: "controller2", Type: "mock-type", Enabled: &disabled},
		}

		controllers, err := BuildAuthorizationControllers(ctx, logger, configs)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(controllers) != 1 {
			t.Errorf("expected 1 controller, got %d", len(controllers))
		}
	})

	t.Run("returns error for unknown type", func(t *testing.T) {
		enabled := true
		configs := []config.ControllerConfig{
			{Name: "controller1", Type: "unknown-type", Enabled: &enabled},
		}

		_, err := BuildAuthorizationControllers(ctx, logger, configs)
		if err == nil {
			t.Error("expected error for unknown type")
		}
	})
}

func TestDecodeControllerSettings(t *testing.T) {
	type TestSettings struct {
		Field1 string `yaml:"field1"`
		Field2 int    `yaml:"field2"`
	}

	t.Run("decodes valid settings", func(t *testing.T) {
		settings := map[string]any{
			"field1": "value1",
			"field2": 42,
		}

		var decoded TestSettings
		err := DecodeControllerSettings(settings, &decoded)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if decoded.Field1 != "value1" {
			t.Errorf("expected field1 to be 'value1', got '%s'", decoded.Field1)
		}
		if decoded.Field2 != 42 {
			t.Errorf("expected field2 to be 42, got %d", decoded.Field2)
		}
	})

	t.Run("handles nil settings", func(t *testing.T) {
		var decoded TestSettings
		err := DecodeControllerSettings(nil, &decoded)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("handles empty settings", func(t *testing.T) {
		settings := map[string]any{}

		var decoded TestSettings
		err := DecodeControllerSettings(settings, &decoded)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}
