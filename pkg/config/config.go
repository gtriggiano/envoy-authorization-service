// Package config provides configuration loading, validation, and management for the
// Envoy Authorization Service. It supports YAML-based configuration files with
// validation and default value application.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/gtriggiano/envoy-authorization-service/pkg/logging"
	"gopkg.in/yaml.v3"
)

const (
	// Server timeouts
	defaultShutdownTimeout = 20 * time.Second
)

// Config models the complete application configuration, including server settings,
// controller definitions, authorization policies, and operational parameters.
type Config struct {
	// Server configures the gRPC authorization service listener.
	Server ServerConfig `yaml:"server"`
	// ClientIP controls how the downstream client address is resolved from a CheckRequest.
	ClientIP ClientIPConfig `yaml:"clientIp"`
	// Metrics configures the HTTP server for Prometheus metrics and health endpoints.
	Metrics MetricsConfig `yaml:"metrics"`
	// Logging configures structured logging output and levels.
	Logging logging.Config `yaml:"logging"`
	// AnalysisControllers defines controllers that inspect requests and emit metadata.
	AnalysisControllers []ControllerConfig `yaml:"analysisControllers"`
	// MatchControllers defines controllers that match requests for policy evaluation.
	MatchControllers []ControllerConfig `yaml:"matchControllers"`
	// AuthorizationPolicy is a boolean expression evaluated against match verdicts.
	AuthorizationPolicy string `yaml:"authorizationPolicy"`
	// AuthorizationPolicyBypass allows requests even when the policy evaluates to false (for testing/metrics).
	AuthorizationPolicyBypass bool `yaml:"authorizationPolicyBypass"`
	// Shutdown controls graceful shutdown behavior.
	Shutdown ShutdownConfig `yaml:"shutdown"`
}

// ServerConfig controls the gRPC listener and optional TLS settings.
type ServerConfig struct {
	// Address is the bind address for the gRPC server (e.g., ":9001").
	Address string `yaml:"address"`
	// TLS configures optional mutual TLS for the gRPC server.
	TLS *TLSConfig `yaml:"tls"`
}

// TLSConfig wraps TLS material locations for server certificates and client verification.
type TLSConfig struct {
	// CertFile is the path to the server certificate PEM file.
	CertFile string `yaml:"certFile"`
	// KeyFile is the path to the server private key PEM file.
	KeyFile string `yaml:"keyFile"`
	// CAFile is the optional path to a CA certificate for client cert verification.
	CAFile string `yaml:"caFile"`
	// RequireClientCert enables mutual TLS by requiring and verifying client certificates.
	RequireClientCert bool `yaml:"requireClientCert"`
}

// MetricsConfig controls the metrics/health HTTP server.
type MetricsConfig struct {
	// Address is the bind address for the metrics HTTP server (e.g., ":9090").
	Address string `yaml:"address"`
	// HealthPath is the liveness probe endpoint path.
	HealthPath string `yaml:"healthPath"`
	// ReadinessPath is the readiness probe endpoint path.
	ReadinessPath string `yaml:"readinessPath"`
	// DropPrefixes specifies metric name prefixes to filter out from the default Go runtime registry.
	DropPrefixes []string `yaml:"dropPrefixes"`
	// TrackCountry enables country/continent labels on request-level metrics (off by default to limit cardinality).
	TrackCountry bool `yaml:"trackCountry"`
	// TrackGeofence toggles emission of geofence match counters (default true).
	TrackGeofence *bool `yaml:"trackGeofence"`
}

// ControllerConfig defines one controller instance with its type and settings.
type ControllerConfig struct {
	// Name is the unique identifier for this controller instance.
	Name string `yaml:"name"`
	// Type specifies the controller kind (e.g., "maxmind-asn", "ip-match").
	Type string `yaml:"type"`
	// Enabled allows conditional activation; defaults to true if omitted.
	Enabled *bool `yaml:"enabled"`
	// Settings contains controller-specific configuration as a map.
	Settings map[string]any `yaml:"settings"`
}

// ShutdownConfig holds graceful shutdown parameters.
type ShutdownConfig struct {
	// Timeout is the maximum duration to wait for graceful shutdown (e.g., "25s").
	Timeout string `yaml:"timeout"`
}

// ClientIPConfig controls how the client IP address is resolved from an Envoy CheckRequest.
//
// Only the sources listed here are consulted, in order; the first one that yields a valid
// address wins. When no source is configured the service falls back to Envoy's
// AttributeContext.source.address, which is the address of the peer that opened the
// connection to Envoy and cannot be forged by the client.
type ClientIPConfig struct {
	// Sources is the ordered list of places to read the client address from.
	// Defaults to a single envoySource entry when empty.
	Sources []ClientIPSource `yaml:"sources"`
	// RequireValid denies the request when no source yields a valid address instead of
	// running the controllers with an unset IP. Defaults to false.
	RequireValid bool `yaml:"requireValid"`
}

// ClientIPSource describes one place the client IP address can be read from.
// Exactly one of the fields is set. In YAML a source is either the scalar
// `envoySource`, a mapping `header: <name>` or a mapping `xff: {trustedHops: N}`.
type ClientIPSource struct {
	// EnvoySource reads AttributeContext.source.address (the peer connected to Envoy).
	EnvoySource bool
	// Header reads a single IP address from the named request header (lower-cased).
	Header string
	// XFF parses the X-Forwarded-For header right-to-left, skipping TrustedHops entries.
	XFF *XFFSource
}

// XFFSource configures X-Forwarded-For parsing.
type XFFSource struct {
	// TrustedHops is the number of right-most X-Forwarded-For entries that belong to
	// trusted proxies. The entry immediately to their left is taken as the client
	// address; 0 selects the right-most entry.
	TrustedHops int `yaml:"trustedHops"`
}

// Source identifiers used in YAML and in logs.
const (
	ClientIPSourceEnvoy  = "envoySource"
	ClientIPSourceHeader = "header"
	ClientIPSourceXFF    = "xff"
)

// DefaultClientIPSources returns the source list used when none is configured.
func DefaultClientIPSources() []ClientIPSource {
	return []ClientIPSource{{EnvoySource: true}}
}

// UnmarshalYAML accepts the three supported source notations.
func (s *ClientIPSource) UnmarshalYAML(node *yaml.Node) error {
	*s = ClientIPSource{}

	switch node.Kind {
	case yaml.ScalarNode:
		if node.Value == ClientIPSourceEnvoy {
			s.EnvoySource = true
			return nil
		}
		return fmt.Errorf("unknown clientIp source %q (expected %q, or a mapping with a %q or %q key)", node.Value, ClientIPSourceEnvoy, ClientIPSourceHeader, ClientIPSourceXFF)

	case yaml.MappingNode:
		if len(node.Content) != 2 {
			return fmt.Errorf("a clientIp source mapping must have exactly one key (%q or %q)", ClientIPSourceHeader, ClientIPSourceXFF)
		}
		key, value := node.Content[0], node.Content[1]
		switch key.Value {
		case ClientIPSourceHeader:
			var name string
			if err := value.Decode(&name); err != nil {
				return fmt.Errorf("clientIp source %q must be a header name: %w", ClientIPSourceHeader, err)
			}
			s.Header = strings.ToLower(strings.TrimSpace(name))
			return nil
		case ClientIPSourceXFF:
			xff := &XFFSource{}
			if value.Kind != yaml.ScalarNode || value.Tag != "!!null" {
				if err := value.Decode(xff); err != nil {
					return fmt.Errorf("clientIp source %q settings are invalid: %w", ClientIPSourceXFF, err)
				}
			}
			s.XFF = xff
			return nil
		default:
			return fmt.Errorf("unknown clientIp source %q (expected %q, or a mapping with a %q or %q key)", key.Value, ClientIPSourceEnvoy, ClientIPSourceHeader, ClientIPSourceXFF)
		}

	default:
		return fmt.Errorf("a clientIp source must be the scalar %q or a mapping with a %q or %q key", ClientIPSourceEnvoy, ClientIPSourceHeader, ClientIPSourceXFF)
	}
}

// String renders the source the way it is written in the configuration file.
func (s ClientIPSource) String() string {
	switch {
	case s.EnvoySource:
		return ClientIPSourceEnvoy
	case s.Header != "":
		return ClientIPSourceHeader + ":" + s.Header
	case s.XFF != nil:
		return fmt.Sprintf("%s:trustedHops=%d", ClientIPSourceXFF, s.XFF.TrustedHops)
	default:
		return "invalid"
	}
}

// validate ensures every configured source is well-formed.
func (c ClientIPConfig) validate() error {
	seen := make(map[string]struct{}, len(c.Sources))
	for i, src := range c.Sources {
		set := 0
		if src.EnvoySource {
			set++
		}
		if src.Header != "" {
			set++
		}
		if src.XFF != nil {
			set++
		}
		if set != 1 {
			return fmt.Errorf("configuration 'clientIp.sources[%d]' must define exactly one source", i)
		}
		if src.Header != "" && !headerNamePattern.MatchString(src.Header) {
			return fmt.Errorf("configuration 'clientIp.sources[%d]': %q is not a valid header name", i, src.Header)
		}
		if src.Header == "x-forwarded-for" {
			return fmt.Errorf("configuration 'clientIp.sources[%d]': use the 'xff' source to read x-forwarded-for", i)
		}
		if src.XFF != nil && src.XFF.TrustedHops < 0 {
			return fmt.Errorf("configuration 'clientIp.sources[%d].xff.trustedHops' must be >= 0", i)
		}
		key := src.String()
		if _, dup := seen[key]; dup {
			return fmt.Errorf("configuration 'clientIp.sources[%d]': duplicate source %s", i, key)
		}
		seen[key] = struct{}{}
	}
	return nil
}

// headerNamePattern matches RFC 7230 header field names (tokens).
var headerNamePattern = regexp.MustCompile(`^[!#$%&'*+\-.^_` + "`" + `|~0-9A-Za-z]+$`)

// Load reads, normalizes, and validates a configuration file from the specified path.
// It returns a fully validated Config instance or an error if loading or validation fails.
func Load(path string) (*Config, error) {
	if path == "" {
		return nil, errors.New("a path to a configuration file is required")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read the configuration file: %w", err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("could not parse the configuration file: %w", err)
	}

	cfg.applyDefaults()

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Validate ensures the configuration is ready for use by checking all required fields
// and validating nested configurations for servers, metrics, and controllers.
func (c *Config) Validate() error {
	if c == nil {
		return errors.New("config is nil")
	}

	if err := c.Server.validate(); err != nil {
		return err
	}

	if err := c.Metrics.validate(); err != nil {
		return err
	}

	if err := c.ClientIP.validate(); err != nil {
		return err
	}

	if err := validateControllerSet(c.AnalysisControllers, "analysis"); err != nil {
		return err
	}
	if err := validateControllerSet(c.MatchControllers, "match"); err != nil {
		return err
	}

	return nil
}

// validateControllerSet ensures all controllers in the set have unique names and required fields.
// It returns an error if any controller is missing a name or type, or if duplicate names exist.
func validateControllerSet(ctrls []ControllerConfig, phaseLabel string) error {
	names := make(map[string]struct{})
	for _, ctrl := range ctrls {
		if ctrl.Name == "" {
			return fmt.Errorf("%s controller name is required", phaseLabel)
		}
		if ctrl.Type == "" {
			return fmt.Errorf("%s controller type is required", phaseLabel)
		}
		if _, exists := names[ctrl.Name]; exists {
			return fmt.Errorf("duplicate %s controller name %s", phaseLabel, ctrl.Name)
		}
		names[ctrl.Name] = struct{}{}
	}
	return nil
}

// applyDefaults populates configuration fields with sensible default values when they
// are not explicitly specified in the configuration file.
func (c *Config) applyDefaults() {
	if c.Server.Address == "" {
		c.Server.Address = ":9001"
	}

	if c.Metrics.Address == "" {
		c.Metrics.Address = ":9090"
	}
	if c.Metrics.HealthPath == "" {
		c.Metrics.HealthPath = "/healthz"
	}
	if c.Metrics.ReadinessPath == "" {
		c.Metrics.ReadinessPath = "/readyz"
	}
	if c.Metrics.DropPrefixes == nil {
		c.Metrics.DropPrefixes = []string{"go_", "process_", "promhttp_"}
	}
	// Default geofence metric emission to true unless explicitly disabled.
	if c.Metrics.TrackGeofence == nil {
		val := true
		c.Metrics.TrackGeofence = &val
	}

	if c.Shutdown.Timeout == "" {
		c.Shutdown.Timeout = "20s"
	}

	if len(c.ClientIP.Sources) == 0 {
		c.ClientIP.Sources = DefaultClientIPSources()
	}

	c.resolveTLSPaths()
}

// validate ensures the server address is configured and TLS configuration is complete when TLS is enabled.
func (s ServerConfig) validate() error {
	if s.Address == "" {
		return errors.New("configuration 'server.address' is required")
	}

	if s.TLS == nil {
		return nil
	}

	return s.TLS.validate()
}

// validate ensures TLS certificate and key files exist and are accessible.
func (t TLSConfig) validate() error {
	if t.CertFile == "" || t.KeyFile == "" {
		return errors.New("configuration 'server.tls.certFile' and 'server.tls.keyFile' are required when TLS is enabled")
	}

	if t.RequireClientCert && t.CAFile == "" {
		return errors.New("configuration 'server.tls.caFile' is required when 'server.tls.requireClientCert' is true")
	}

	for _, filePath := range []string{t.CertFile, t.KeyFile, t.CAFile} {
		if filePath == "" {
			continue
		}
		if err := fileExists(filePath); err != nil {
			return err
		}
	}
	return nil
}

// validate ensures the metrics server address is configured.
func (m MetricsConfig) validate() error {
	if m.Address == "" {
		return errors.New("configuration 'metrics.address' is required")
	}
	return nil
}

// IsEnabled returns true if the controller should run. Controllers are enabled by default
// unless explicitly set to false in the configuration.
func (c ControllerConfig) IsEnabled() bool {
	if c.Enabled == nil {
		return true
	}
	return *c.Enabled
}

// ShutdownTimeout returns the parsed graceful shutdown deadline. It defaults to 20 seconds
// if the timeout string is empty or cannot be parsed.
func (c ShutdownConfig) ShutdownTimeout() time.Duration {
	if c.Timeout == "" {
		return defaultShutdownTimeout
	}
	d, err := time.ParseDuration(c.Timeout)
	if err != nil {
		return defaultShutdownTimeout
	}
	return d
}

// fileExists verifies that a file exists at the specified path.
// It returns an error if the path is empty or the file is not accessible.
func fileExists(path string) error {
	if path == "" {
		return errors.New("path is empty")
	}
	if _, err := os.Stat(path); err != nil {
		return err
	}
	return nil
}

// resolveTLSPaths converts relative TLS file paths to absolute paths based on the current
// working directory. This ensures consistent path resolution regardless of where the
// server binary is invoked from.
func (c *Config) resolveTLSPaths() {
	if c.Server.TLS == nil {
		return
	}

	cwd, err := os.Getwd()
	if err != nil {
		return
	}

	if c.Server.TLS.CertFile != "" && !filepath.IsAbs(c.Server.TLS.CertFile) {
		c.Server.TLS.CertFile = filepath.Join(cwd, c.Server.TLS.CertFile)
	}
	if c.Server.TLS.KeyFile != "" && !filepath.IsAbs(c.Server.TLS.KeyFile) {
		c.Server.TLS.KeyFile = filepath.Join(cwd, c.Server.TLS.KeyFile)
	}
	if c.Server.TLS.CAFile != "" && !filepath.IsAbs(c.Server.TLS.CAFile) {
		c.Server.TLS.CAFile = filepath.Join(cwd, c.Server.TLS.CAFile)
	}
}

// EnabledMatchControllerNames returns the list of enabled match controller names.
// This is used by the policy parser to validate that all referenced controllers exist.
func (c *Config) EnabledMatchControllerNames() []string {
	names := make([]string, 0, len(c.MatchControllers))
	for _, ctrl := range c.MatchControllers {
		if ctrl.Name != "" && ctrl.IsEnabled() {
			names = append(names, ctrl.Name)
		}
	}
	return names
}
