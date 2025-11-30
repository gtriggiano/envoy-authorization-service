package asn_match_database

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"
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
	TTL string `yaml:"ttl"`
}

// DatabaseConfig represents the database configuration
type DatabaseConfig struct {
	Type              string          `yaml:"type"`
	ConnectionTimeout string          `yaml:"connectionTimeout"`
	Redis             *RedisConfig    `yaml:"redis"`
	Postgres          *PostgresConfig `yaml:"postgres"`
}

// ApplyDefaults sets default values for the configuration
func (c *ASNMatchDatabaseConfig) ApplyDefaults() {
	c.Database.Redis.ApplyDefaults()
	c.Database.Postgres.ApplyDefaults()
}

// Validate checks the configuration for completeness and correctness
func (c *ASNMatchDatabaseConfig) Validate() error {
	// Validate cache configuration if present
	if c.Cache != nil {
		if c.Cache.TTL == "" {
			return fmt.Errorf("cache.ttl is required when cache is configured")
		}
		cacheTTL, err := time.ParseDuration(c.Cache.TTL)
		if err != nil {
			return fmt.Errorf("invalid cache.ttl: %w", err)
		}
		if cacheTTL <= 0 {
			return fmt.Errorf("cache.ttl must be positive")
		}
	}

	// Validate database connection timeout if present
	if c.Database.ConnectionTimeout != "" {
		databaseTimeout, err := time.ParseDuration(c.Database.ConnectionTimeout)
		if err != nil {
			return fmt.Errorf("invalid database.connectionTimeout: %w", err)
		}
		if databaseTimeout <= 0 {
			return fmt.Errorf("database.connectionTimeout must be positive")
		}
	}

	// Validate type-specific configuration
	switch c.Database.Type {
	case "redis":
		if err := c.validateRedisConfig(); err != nil {
			return err
		}
	case "postgres":
		if err := c.validatePostgresConfig(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("database.type must be 'redis' or 'postgres', got '%s'", c.Database.Type)
	}

	return nil
}

// GetCacheTTL returns the parsed cache TTL duration, or 0 if caching is disabled
func (c *ASNMatchDatabaseConfig) GetCacheTTL() time.Duration {
	if c.Cache == nil || c.Cache.TTL == "" {
		return 0
	}
	ttl, _ := time.ParseDuration(c.Cache.TTL)
	return ttl
}

// GetDatabaseConnectionTimeout returns the parsed database connection timeout duration, or default if not specified
func (c *ASNMatchDatabaseConfig) GetDatabaseConnectionTimeout() time.Duration {
	if c.Database.ConnectionTimeout == "" {
		return DefaultDatabaseConnectionTimeout
	}
	timeout, _ := time.ParseDuration(c.Database.ConnectionTimeout)

	if timeout <= 0 {
		return DefaultDatabaseConnectionTimeout
	}

	return timeout
}

// validateCertificateFile checks if a certificate file exists, is readable, and contains valid PEM data
func validateCertificateFile(path string, description string) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("%s path is not valid: %w", description, err)
	}

	data, err := os.ReadFile(absPath)
	if err != nil {
		return fmt.Errorf("could not read %s file: %w", description, err)
	}

	if len(data) == 0 {
		return fmt.Errorf("%s file is empty", description)
	}

	// Validate it's a valid certificate by attempting to parse it
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(data) {
		return fmt.Errorf("%s file does not contain valid PEM-encoded certificate(s)", description)
	}

	return nil
}

// validateKeyFile checks if a private key file exists, is readable, and contains valid PEM data
func validateKeyFile(path string, description string) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("%s path is not valid: %w", description, err)
	}

	data, err := os.ReadFile(absPath)
	if err != nil {
		return fmt.Errorf("could not read %s file: %w", description, err)
	}

	if len(data) == 0 {
		return fmt.Errorf("%s file is empty", description)
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
