package asn_match_database

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/gtriggiano/envoy-authorization-service/pkg/config"
	"github.com/gtriggiano/envoy-authorization-service/pkg/controller"
)

const (
	DefaultDatabaseConnectionTimeout = 500 * time.Millisecond
	defaultPostgresPort              = 5432
	defaultRedisPort                 = 6379
)

// ASNMatchDatabaseConfig represents the complete configuration for the asn-match-database controller
type ASNMatchDatabaseConfig struct {
	MatchesOnFailure bool           `yaml:"matchesOnFailure"`
	Cache            *CacheConfig   `yaml:"cache"`
	Database         DatabaseConfig `yaml:"database"`
}

// CacheConfig represents the caching configuration
type CacheConfig struct {
	TTL config.Duration `yaml:"ttl"`
}

// DatabaseConfig represents the database configuration
type DatabaseConfig struct {
	Type              string           `yaml:"type"`
	ConnectionTimeout *config.Duration `yaml:"connectionTimeout"`
	Redis             *RedisConfig     `yaml:"redis"`
	Postgres          *PostgresConfig  `yaml:"postgres"`
}

// ApplyDefaults sets default values for the configuration
func (c *ASNMatchDatabaseConfig) ApplyDefaults() {
	c.Database.Redis.ApplyDefaults()
	c.Database.Postgres.ApplyDefaults()
}

// ResolvePaths turns every file path in the configuration (TLS material, credential files)
// into an absolute path using resolve, typically config.ControllerConfig.ResolvePath.
func (c *ASNMatchDatabaseConfig) ResolvePaths(resolve func(string) (string, error)) error {
	var fields []*string
	if pg := c.Database.Postgres; pg != nil {
		fields = append(fields, &pg.UsernameFile, &pg.PasswordFile)
		if pg.TLS != nil {
			fields = append(fields, &pg.TLS.CACert, &pg.TLS.ClientCert, &pg.TLS.ClientKey)
		}
	}
	if rd := c.Database.Redis; rd != nil {
		fields = append(fields, &rd.UsernameFile, &rd.PasswordFile)
		if rd.TLS != nil {
			fields = append(fields, &rd.TLS.CACert, &rd.TLS.ClientCert, &rd.TLS.ClientKey)
		}
	}
	for _, field := range fields {
		if *field == "" {
			continue
		}
		resolved, err := resolve(*field)
		if err != nil {
			return err
		}
		*field = resolved
	}
	return nil
}

// Validate checks the configuration for completeness and correctness, including that the
// credential sources and certificate files exist.
func (c *ASNMatchDatabaseConfig) Validate() error {
	return c.ValidateWith(controller.ValidationOptions{})
}

// ValidateWith is Validate with control over environment-dependent checks: when opts.Offline
// is set, missing credentials and certificate files are reported through opts.Warn instead
// of failing.
func (c *ASNMatchDatabaseConfig) ValidateWith(opts controller.ValidationOptions) error {
	// Validate cache configuration if present
	if c.Cache != nil && c.Cache.TTL <= 0 {
		return fmt.Errorf("cache.ttl is required and must be positive when cache is configured")
	}

	// Validate database connection timeout if present
	if c.Database.ConnectionTimeout != nil && c.Database.ConnectionTimeout.Std() <= 0 {
		return fmt.Errorf("database.connectionTimeout must be positive")
	}

	// Validate type-specific configuration
	switch c.Database.Type {
	case "redis":
		if err := c.validateRedisConfig(opts); err != nil {
			return err
		}
	case "postgres":
		if err := c.validatePostgresConfig(opts); err != nil {
			return err
		}
	default:
		return fmt.Errorf("database.type must be 'redis' or 'postgres', got '%s'", c.Database.Type)
	}

	return nil
}

// GetCacheTTL returns the cache TTL duration, or 0 if caching is disabled
func (c *ASNMatchDatabaseConfig) GetCacheTTL() time.Duration {
	if c.Cache == nil {
		return 0
	}
	return c.Cache.TTL.Std()
}

// GetDatabaseConnectionTimeout returns the database connection timeout duration, or default if not specified
func (c *ASNMatchDatabaseConfig) GetDatabaseConnectionTimeout() time.Duration {
	return c.Database.ConnectionTimeout.Or(DefaultDatabaseConnectionTimeout)
}

// checkCredential verifies a credential source exists. In offline validation a missing
// environment variable or file becomes a warning.
func checkCredential(source config.CredentialSource, name string, opts controller.ValidationOptions) error {
	if err := source.Validate(name); err != nil {
		return err
	}
	err := source.Check(name)
	if err != nil && opts.Offline && errors.Is(err, config.ErrCredentialUnavailable) {
		opts.Warnf("%v (not checked in offline validation)", err)
		return nil
	}
	return err
}

// readValidatedFile reads a certificate or key file. In offline validation a missing file is
// reported as a warning and (nil, false, nil) is returned.
func readValidatedFile(path, description string, opts controller.ValidationOptions) ([]byte, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if opts.Offline && errors.Is(err, os.ErrNotExist) {
			opts.Warnf("%s: file %s not found, its content was not checked", description, path)
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("could not read %s file: %w", description, err)
	}
	if len(data) == 0 {
		return nil, false, fmt.Errorf("%s file is empty", description)
	}
	return data, true, nil
}

// validateCertificateFile checks if a certificate file exists, is readable, and contains valid PEM data
func validateCertificateFile(path string, description string, opts controller.ValidationOptions) error {
	data, ok, err := readValidatedFile(path, description, opts)
	if err != nil || !ok {
		return err
	}

	// Validate it's a valid certificate by attempting to parse it
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(data) {
		return fmt.Errorf("%s file does not contain valid PEM-encoded certificate(s)", description)
	}

	return nil
}

// validateKeyFile checks if a private key file exists, is readable, and contains valid PEM data
func validateKeyFile(path string, description string, opts controller.ValidationOptions) error {
	data, ok, err := readValidatedFile(path, description, opts)
	if err != nil || !ok {
		return err
	}

	// Validate it contains PEM data
	block, _ := pem.Decode(data)
	if block == nil {
		return fmt.Errorf("%s file does not contain valid PEM-encoded data", description)
	}

	// Check if it's a private key type
	keyTypes := []string{"RSA PRIVATE KEY", "EC PRIVATE KEY", "PRIVATE KEY", "ENCRYPTED PRIVATE KEY"}
	validKeyType := slices.Contains(keyTypes, block.Type)
	if !validKeyType {
		return fmt.Errorf("%s file does not contain a valid private key (found PEM type: %s)", description, block.Type)
	}

	return nil
}
