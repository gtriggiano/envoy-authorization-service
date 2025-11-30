package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestLoad verifies configuration files are parsed, defaulted, and validated.
func TestLoad(t *testing.T) {
	t.Run("empty path returns error", func(t *testing.T) {
		_, err := Load("")
		if err == nil || !strings.Contains(err.Error(), "path to a configuration file is required") {
			t.Fatalf("expected path required error, got %v", err)
		}
	})

	t.Run("non-existent file returns error", func(t *testing.T) {
		_, err := Load("/nonexistent/path/to/config.yaml")
		if err == nil || !strings.Contains(err.Error(), "could not read the configuration file") {
			t.Fatalf("expected read error, got %v", err)
		}
	})

	t.Run("invalid YAML returns error", func(t *testing.T) {
		tmpFile := createTempFile(t, "invalid:\n  - yaml: [unclosed")
		defer os.Remove(tmpFile)

		_, err := Load(tmpFile)
		if err == nil || !strings.Contains(err.Error(), "could not parse the configuration file") {
			t.Fatalf("expected parse error, got %v", err)
		}
	})

	t.Run("minimal valid configuration with defaults", func(t *testing.T) {
		yaml := `
server:
  address: ":9001"
metrics:
  address: ":9090"
`
		tmpFile := createTempFile(t, yaml)
		defer os.Remove(tmpFile)

		cfg, err := Load(tmpFile)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Server.Address != ":9001" {
			t.Errorf("expected server address ':9001', got %q", cfg.Server.Address)
		}
		if cfg.Metrics.HealthPath != "/healthz" {
			t.Errorf("expected default health path '/healthz', got %q", cfg.Metrics.HealthPath)
		}
		if cfg.Metrics.ReadinessPath != "/readyz" {
			t.Errorf("expected default readiness path '/readyz', got %q", cfg.Metrics.ReadinessPath)
		}
		if cfg.Shutdown.Timeout != "20s" {
			t.Errorf("expected default shutdown timeout '20s', got %q", cfg.Shutdown.Timeout)
		}
	})

	t.Run("full configuration with all fields", func(t *testing.T) {
		yaml := `
logging:
  level: debug
server:
  address: ":8080"
metrics:
  address: ":8090"
  healthPath: /health
  readinessPath: /ready
analysisControllers:
  - name: test-analysis
    type: maxmind-asn
    enabled: true
    settings:
      databasePath: /path/to/db
matchControllers:
  - name: test-auth
    type: ip-match
    enabled: false
    settings:
      cidrList: /tmp/cidrs
authorizationPolicy: "test-auth"
authorizationPolicyBypass: true
shutdown:
  timeout: 30s
`
		tmpFile := createTempFile(t, yaml)
		defer os.Remove(tmpFile)

		cfg, err := Load(tmpFile)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cfg.Logging.Level != "debug" {
			t.Errorf("expected logging level 'debug', got %q", cfg.Logging.Level)
		}
		if cfg.Server.Address != ":8080" {
			t.Errorf("expected server address ':8080', got %q", cfg.Server.Address)
		}
		if cfg.Metrics.Address != ":8090" {
			t.Errorf("expected metrics address ':8090', got %q", cfg.Metrics.Address)
		}
		if cfg.Metrics.HealthPath != "/health" {
			t.Errorf("expected health path '/health', got %q", cfg.Metrics.HealthPath)
		}
		if cfg.AuthorizationPolicy != "test-auth" {
			t.Errorf("expected authorization policy 'test-auth', got %q", cfg.AuthorizationPolicy)
		}
		if !cfg.AuthorizationPolicyBypass {
			t.Error("expected authorization policy bypass to be true")
		}
		if len(cfg.AnalysisControllers) != 1 {
			t.Fatalf("expected 1 analysis controller, got %d", len(cfg.AnalysisControllers))
		}
		if len(cfg.MatchControllers) != 1 {
			t.Fatalf("expected 1 match controller, got %d", len(cfg.MatchControllers))
		}
	})
}

// TestConfigValidate covers the validation behavior for different config shapes.
func TestConfigValidate(t *testing.T) {
	t.Run("nil config returns error", func(t *testing.T) {
		var cfg *Config
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "config is nil") {
			t.Fatalf("expected nil config error, got %v", err)
		}
	})

	t.Run("missing server address returns error", func(t *testing.T) {
		cfg := &Config{
			Metrics: MetricsConfig{Address: ":9090"},
		}
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "server.address") {
			t.Fatalf("expected server address error, got %v", err)
		}
	})

	t.Run("missing metrics address returns error", func(t *testing.T) {
		cfg := &Config{
			Server: ServerConfig{Address: ":9001"},
		}
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "metrics.address") {
			t.Fatalf("expected metrics address error, got %v", err)
		}
	})

	t.Run("valid minimal config passes validation", func(t *testing.T) {
		cfg := &Config{
			Server:  ServerConfig{Address: ":9001"},
			Metrics: MetricsConfig{Address: ":9090"},
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("unexpected validation error: %v", err)
		}
	})

	t.Run("duplicate analysis controller names return error", func(t *testing.T) {
		cfg := &Config{
			Server:  ServerConfig{Address: ":9001"},
			Metrics: MetricsConfig{Address: ":9090"},
			AnalysisControllers: []ControllerConfig{
				{Name: "duplicate", Type: "type1"},
				{Name: "duplicate", Type: "type2"},
			},
		}
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "duplicate analysis controller name") {
			t.Fatalf("expected duplicate name error, got %v", err)
		}
	})

	t.Run("duplicate match controller names return error", func(t *testing.T) {
		cfg := &Config{
			Server:  ServerConfig{Address: ":9001"},
			Metrics: MetricsConfig{Address: ":9090"},
			MatchControllers: []ControllerConfig{
				{Name: "duplicate", Type: "type1"},
				{Name: "duplicate", Type: "type2"},
			},
		}
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "duplicate match controller name") {
			t.Fatalf("expected duplicate name error, got %v", err)
		}
	})

	t.Run("missing controller name returns error", func(t *testing.T) {
		cfg := &Config{
			Server:  ServerConfig{Address: ":9001"},
			Metrics: MetricsConfig{Address: ":9090"},
			AnalysisControllers: []ControllerConfig{
				{Type: "some-type"},
			},
		}
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "controller name is required") {
			t.Fatalf("expected name required error, got %v", err)
		}
	})

	t.Run("missing controller type returns error", func(t *testing.T) {
		cfg := &Config{
			Server:  ServerConfig{Address: ":9001"},
			Metrics: MetricsConfig{Address: ":9090"},
			MatchControllers: []ControllerConfig{
				{Name: "test"},
			},
		}
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "controller type is required") {
			t.Fatalf("expected type required error, got %v", err)
		}
	})
}

// TestTLSConfigValidation exercises TLS-specific validation logic.
func TestTLSConfigValidation(t *testing.T) {
	t.Run("TLS with missing cert file returns error", func(t *testing.T) {
		cfg := &Config{
			Server: ServerConfig{
				Address: ":9001",
				TLS: &TLSConfig{
					KeyFile: "/path/to/key.pem",
				},
			},
			Metrics: MetricsConfig{Address: ":9090"},
		}
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "certFile") {
			t.Fatalf("expected cert file error, got %v", err)
		}
	})

	t.Run("TLS with missing key file returns error", func(t *testing.T) {
		cfg := &Config{
			Server: ServerConfig{
				Address: ":9001",
				TLS: &TLSConfig{
					CertFile: "/path/to/cert.pem",
				},
			},
			Metrics: MetricsConfig{Address: ":9090"},
		}
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "keyFile") {
			t.Fatalf("expected key file error, got %v", err)
		}
	})

	t.Run("TLS with requireClientCert but no CA file returns error", func(t *testing.T) {
		// Create temporary cert and key files
		certFile := createTempFile(t, "cert content")
		keyFile := createTempFile(t, "key content")
		defer os.Remove(certFile)
		defer os.Remove(keyFile)

		cfg := &Config{
			Server: ServerConfig{
				Address: ":9001",
				TLS: &TLSConfig{
					CertFile:          certFile,
					KeyFile:           keyFile,
					RequireClientCert: true,
				},
			},
			Metrics: MetricsConfig{Address: ":9090"},
		}
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "caFile") {
			t.Fatalf("expected CA file error, got %v", err)
		}
	})

	t.Run("TLS with non-existent cert file returns error", func(t *testing.T) {
		cfg := &Config{
			Server: ServerConfig{
				Address: ":9001",
				TLS: &TLSConfig{
					CertFile: "/nonexistent/cert.pem",
					KeyFile:  "/nonexistent/key.pem",
				},
			},
			Metrics: MetricsConfig{Address: ":9090"},
		}
		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected file existence error")
		}
	})

	t.Run("TLS with valid file paths passes validation", func(t *testing.T) {
		certFile := createTempFile(t, "cert content")
		keyFile := createTempFile(t, "key content")
		defer os.Remove(certFile)
		defer os.Remove(keyFile)

		cfg := &Config{
			Server: ServerConfig{
				Address: ":9001",
				TLS: &TLSConfig{
					CertFile: certFile,
					KeyFile:  keyFile,
				},
			},
			Metrics: MetricsConfig{Address: ":9090"},
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("unexpected validation error: %v", err)
		}
	})
}

// TestControllerConfigIsEnabled checks enablement defaults and overrides.
func TestControllerConfigIsEnabled(t *testing.T) {
	t.Run("nil enabled defaults to true", func(t *testing.T) {
		ctrl := ControllerConfig{
			Name: "test",
			Type: "test-type",
		}
		if !ctrl.IsEnabled() {
			t.Error("expected controller to be enabled by default")
		}
	})

	t.Run("explicitly enabled returns true", func(t *testing.T) {
		enabled := true
		ctrl := ControllerConfig{
			Name:    "test",
			Type:    "test-type",
			Enabled: &enabled,
		}
		if !ctrl.IsEnabled() {
			t.Error("expected controller to be enabled")
		}
	})

	t.Run("explicitly disabled returns false", func(t *testing.T) {
		enabled := false
		ctrl := ControllerConfig{
			Name:    "test",
			Type:    "test-type",
			Enabled: &enabled,
		}
		if ctrl.IsEnabled() {
			t.Error("expected controller to be disabled")
		}
	})
}

// TestShutdownTimeout ensures the string duration parsing and defaults function correctly.
func TestShutdownTimeout(t *testing.T) {
	t.Run("empty timeout returns default", func(t *testing.T) {
		cfg := ShutdownConfig{}
		timeout := cfg.ShutdownTimeout()
		if timeout != 20*time.Second {
			t.Errorf("expected default timeout 20s, got %v", timeout)
		}
	})

	t.Run("valid duration string is parsed", func(t *testing.T) {
		cfg := ShutdownConfig{Timeout: "30s"}
		timeout := cfg.ShutdownTimeout()
		if timeout != 30*time.Second {
			t.Errorf("expected timeout 30s, got %v", timeout)
		}
	})

	t.Run("complex duration string is parsed", func(t *testing.T) {
		cfg := ShutdownConfig{Timeout: "1m30s"}
		timeout := cfg.ShutdownTimeout()
		if timeout != 90*time.Second {
			t.Errorf("expected timeout 90s, got %v", timeout)
		}
	})

	t.Run("invalid duration returns default", func(t *testing.T) {
		cfg := ShutdownConfig{Timeout: "invalid"}
		timeout := cfg.ShutdownTimeout()
		if timeout != 20*time.Second {
			t.Errorf("expected default timeout 20s, got %v", timeout)
		}
	})
}

// TestApplyDefaults ensures missing configuration values are populated.
func TestApplyDefaults(t *testing.T) {
	t.Run("applies all defaults to empty config", func(t *testing.T) {
		cfg := &Config{}
		cfg.applyDefaults()

		if cfg.Server.Address != ":9001" {
			t.Errorf("expected default server address ':9001', got %q", cfg.Server.Address)
		}
		if cfg.Metrics.Address != ":9090" {
			t.Errorf("expected default metrics address ':9090', got %q", cfg.Metrics.Address)
		}
		if cfg.Metrics.HealthPath != "/healthz" {
			t.Errorf("expected default health path '/healthz', got %q", cfg.Metrics.HealthPath)
		}
		if cfg.Metrics.ReadinessPath != "/readyz" {
			t.Errorf("expected default readiness path '/readyz', got %q", cfg.Metrics.ReadinessPath)
		}
		if cfg.Shutdown.Timeout != "20s" {
			t.Errorf("expected default shutdown timeout '20s', got %q", cfg.Shutdown.Timeout)
		}
	})

	t.Run("does not override existing values", func(t *testing.T) {
		cfg := &Config{
			Server: ServerConfig{Address: ":8080"},
			Metrics: MetricsConfig{
				Address:       ":8090",
				HealthPath:    "/custom-health",
				ReadinessPath: "/custom-ready",
			},
			Shutdown: ShutdownConfig{Timeout: "30s"},
		}
		cfg.applyDefaults()

		if cfg.Server.Address != ":8080" {
			t.Errorf("expected server address ':8080', got %q", cfg.Server.Address)
		}
		if cfg.Metrics.Address != ":8090" {
			t.Errorf("expected metrics address ':8090', got %q", cfg.Metrics.Address)
		}
		if cfg.Metrics.HealthPath != "/custom-health" {
			t.Errorf("expected health path '/custom-health', got %q", cfg.Metrics.HealthPath)
		}
		if cfg.Metrics.ReadinessPath != "/custom-ready" {
			t.Errorf("expected readiness path '/custom-ready', got %q", cfg.Metrics.ReadinessPath)
		}
		if cfg.Shutdown.Timeout != "30s" {
			t.Errorf("expected shutdown timeout '30s', got %q", cfg.Shutdown.Timeout)
		}
	})
}

// TestResolveTLSPaths ensures TLS file paths become absolute relative to the cwd.
func TestResolveTLSPaths(t *testing.T) {
	t.Run("no TLS config does nothing", func(t *testing.T) {
		cfg := &Config{}
		cfg.resolveTLSPaths()
		// Should not panic
	})

	t.Run("absolute paths remain unchanged", func(t *testing.T) {
		cfg := &Config{
			Server: ServerConfig{
				TLS: &TLSConfig{
					CertFile: "/absolute/path/cert.pem",
					KeyFile:  "/absolute/path/key.pem",
					CAFile:   "/absolute/path/ca.pem",
				},
			},
		}
		cfg.resolveTLSPaths()

		if cfg.Server.TLS.CertFile != "/absolute/path/cert.pem" {
			t.Errorf("absolute cert path changed: %s", cfg.Server.TLS.CertFile)
		}
		if cfg.Server.TLS.KeyFile != "/absolute/path/key.pem" {
			t.Errorf("absolute key path changed: %s", cfg.Server.TLS.KeyFile)
		}
		if cfg.Server.TLS.CAFile != "/absolute/path/ca.pem" {
			t.Errorf("absolute CA path changed: %s", cfg.Server.TLS.CAFile)
		}
	})

	t.Run("relative paths are resolved", func(t *testing.T) {
		cfg := &Config{
			Server: ServerConfig{
				TLS: &TLSConfig{
					CertFile: "certs/cert.pem",
					KeyFile:  "certs/key.pem",
					CAFile:   "certs/ca.pem",
				},
			},
		}
		cfg.resolveTLSPaths()

		if !filepath.IsAbs(cfg.Server.TLS.CertFile) {
			t.Error("cert file path should be absolute after resolution")
		}
		if !filepath.IsAbs(cfg.Server.TLS.KeyFile) {
			t.Error("key file path should be absolute after resolution")
		}
		if !filepath.IsAbs(cfg.Server.TLS.CAFile) {
			t.Error("CA file path should be absolute after resolution")
		}
	})
}

// TestEnabledMatchControllerNames returns only enabled controller names.
func TestEnabledMatchControllerNames(t *testing.T) {
	t.Run("returns empty list for no controllers", func(t *testing.T) {
		cfg := &Config{}
		names := cfg.EnabledMatchControllerNames()
		if len(names) != 0 {
			t.Errorf("expected empty list, got %v", names)
		}
	})

	t.Run("returns only enabled controllers", func(t *testing.T) {
		enabled := true
		disabled := false
		cfg := &Config{
			MatchControllers: []ControllerConfig{
				{Name: "enabled1", Type: "type1", Enabled: &enabled},
				{Name: "disabled", Type: "type2", Enabled: &disabled},
				{Name: "enabled2", Type: "type3"}, // defaults to enabled
			},
		}
		names := cfg.EnabledMatchControllerNames()
		if len(names) != 2 {
			t.Fatalf("expected 2 enabled controllers, got %d: %v", len(names), names)
		}
		if names[0] != "enabled1" {
			t.Errorf("expected first name 'enabled1', got %q", names[0])
		}
		if names[1] != "enabled2" {
			t.Errorf("expected second name 'enabled2', got %q", names[1])
		}
	})

	t.Run("skips controllers with empty names", func(t *testing.T) {
		cfg := &Config{
			MatchControllers: []ControllerConfig{
				{Name: "", Type: "type1"},
				{Name: "valid", Type: "type2"},
			},
		}
		names := cfg.EnabledMatchControllerNames()
		if len(names) != 1 {
			t.Fatalf("expected 1 controller, got %d: %v", len(names), names)
		}
		if names[0] != "valid" {
			t.Errorf("expected name 'valid', got %q", names[0])
		}
	})
}

// TestValidateControllerSet validates controller set invariants (name/type uniqueness).
func TestValidateControllerSet(t *testing.T) {
	t.Run("empty controller set is valid", func(t *testing.T) {
		err := validateControllerSet([]ControllerConfig{}, "test")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("valid controller set passes", func(t *testing.T) {
		ctrls := []ControllerConfig{
			{Name: "ctrl1", Type: "type1"},
			{Name: "ctrl2", Type: "type2"},
		}
		err := validateControllerSet(ctrls, "test")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("controller without name fails", func(t *testing.T) {
		ctrls := []ControllerConfig{
			{Name: "", Type: "type1"},
		}
		err := validateControllerSet(ctrls, "test")
		if err == nil || !strings.Contains(err.Error(), "name is required") {
			t.Fatalf("expected name required error, got %v", err)
		}
	})

	t.Run("controller without type fails", func(t *testing.T) {
		ctrls := []ControllerConfig{
			{Name: "ctrl1", Type: ""},
		}
		err := validateControllerSet(ctrls, "test")
		if err == nil || !strings.Contains(err.Error(), "type is required") {
			t.Fatalf("expected type required error, got %v", err)
		}
	})

	t.Run("duplicate controller names fail", func(t *testing.T) {
		ctrls := []ControllerConfig{
			{Name: "duplicate", Type: "type1"},
			{Name: "duplicate", Type: "type2"},
		}
		err := validateControllerSet(ctrls, "test")
		if err == nil || !strings.Contains(err.Error(), "duplicate") {
			t.Fatalf("expected duplicate error, got %v", err)
		}
	})
}

// createTempFile creates a temporary file with the given content for testing.
func createTempFile(t *testing.T, content string) string {
	t.Helper()
	tmpFile, err := os.CreateTemp("", "config-test-*.yaml")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatalf("failed to close temp file: %v", err)
	}
	return tmpFile.Name()
}
