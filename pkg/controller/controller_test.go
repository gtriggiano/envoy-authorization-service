package controller

import (
	"context"
	"testing"

	"go.uber.org/zap"

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

type mockMatchController struct {
	name      string
	kind      string
	verdict   *MatchVerdict
	healthErr error
	matchErr  error
}

func (m *mockMatchController) Name() string { return m.name }
func (m *mockMatchController) Kind() string { return m.kind }
func (m *mockMatchController) Match(ctx context.Context, req *runtime.RequestContext, reports AnalysisReports) (*MatchVerdict, error) {
	return m.verdict, m.matchErr
}
func (m *mockMatchController) HealthCheck(ctx context.Context) error { return m.healthErr }

func TestRegisterAnalysisContollerFactory(t *testing.T) {
	// Reset registry for test isolation
	oldReg := analysisContollersRegistry
	t.Cleanup(func() {
		analysisContollersRegistry = oldReg
	})
	analysisContollersRegistry = newRegistry[AnalysisContollerFactory]()

	factory := func(ctx context.Context, logger *zap.Logger, cfg config.ControllerConfig) (AnalysisController, error) {
		return &mockAnalysisController{name: cfg.Name, kind: "test"}, nil
	}

	t.Run("successful registration", func(t *testing.T) {
		RegisterAnalysisContollerFactory("test-type", factory)

		f, ok := getFactory(analysisContollersRegistry, "test-type")
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
		RegisterAnalysisContollerFactory("test-type", factory)
	})

	t.Run("panic on empty kind", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic on empty kind")
			}
		}()
		RegisterAnalysisContollerFactory("", factory)
	})
}

func TestRegisterMatchContollerFactory(t *testing.T) {
	// Reset registry for test isolation
	oldReg := matchContollersRegistry
	t.Cleanup(func() {
		matchContollersRegistry = oldReg
	})
	matchContollersRegistry = newRegistry[MatchContollerFactory]()

	factory := func(ctx context.Context, logger *zap.Logger, cfg config.ControllerConfig) (MatchController, error) {
		return &mockMatchController{name: cfg.Name, kind: "test"}, nil
	}

	t.Run("successful registration", func(t *testing.T) {
		RegisterMatchContollerFactory("test-type", factory)

		f, ok := getFactory(matchContollersRegistry, "test-type")
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
		RegisterMatchContollerFactory("test-type", factory)
	})
}

func TestBuildAnalysisControllers(t *testing.T) {
	// Reset registry for test isolation
	oldReg := analysisContollersRegistry
	t.Cleanup(func() {
		analysisContollersRegistry = oldReg
	})
	analysisContollersRegistry = newRegistry[AnalysisContollerFactory]()

	factory := func(ctx context.Context, logger *zap.Logger, cfg config.ControllerConfig) (AnalysisController, error) {
		return &mockAnalysisController{name: cfg.Name, kind: cfg.Type}, nil
	}
	RegisterAnalysisContollerFactory("mock-type", factory)

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

func TestBuildMatchControllers(t *testing.T) {
	// Reset registry for test isolation
	oldReg := matchContollersRegistry
	t.Cleanup(func() {
		matchContollersRegistry = oldReg
	})
	matchContollersRegistry = newRegistry[MatchContollerFactory]()

	factory := func(ctx context.Context, logger *zap.Logger, cfg config.ControllerConfig) (MatchController, error) {
		return &mockMatchController{name: cfg.Name, kind: cfg.Type}, nil
	}
	RegisterMatchContollerFactory("mock-type", factory)

	logger, _ := zap.NewDevelopment()
	ctx := context.Background()

	t.Run("builds enabled controllers", func(t *testing.T) {
		enabled := true
		configs := []config.ControllerConfig{
			{Name: "controller1", Type: "mock-type", Enabled: &enabled},
			{Name: "controller2", Type: "mock-type", Enabled: &enabled},
		}

		controllers, err := BuildMatchControllers(ctx, logger, configs)
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

		controllers, err := BuildMatchControllers(ctx, logger, configs)
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

		_, err := BuildMatchControllers(ctx, logger, configs)
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
