package ip_match_database

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

// PostgresConfig represents PostgreSQL-specific configuration
type PostgresConfig struct {
	Query        string              `yaml:"query"`
	Host         string              `yaml:"host"`
	Port         int                 `yaml:"port"`
	DatabaseName string              `yaml:"databaseName"`
	UsernameEnv  string              `yaml:"usernameEnv"`
	PasswordEnv  string              `yaml:"passwordEnv"`
	Pool         *PostgresPoolConfig `yaml:"pool"`
	TLS          *PostgresTLSConfig  `yaml:"tls"`
}

// PostgresPoolConfig represents connection pool configuration
type PostgresPoolConfig struct {
	MaxConnections    int    `yaml:"maxConnections"`
	MinConnections    int    `yaml:"minConnections"`
	MaxIdleTime       string `yaml:"maxIdleTime"`
	ConnectionTimeout string `yaml:"connectionTimeout"`
}

// PostgresTLSConfig represents TLS configuration for PostgreSQL
type PostgresTLSConfig struct {
	Mode       string `yaml:"mode"`
	CACert     string `yaml:"caCert"`
	ClientCert string `yaml:"clientCert"`
	ClientKey  string `yaml:"clientKey"`
}

// ApplyDefaults sets default values for the postgres configuration
func (c *PostgresConfig) ApplyDefaults() {
	if c != nil {
		if c.Port == 0 {
			c.Port = defaultPostgresPort
		}
	}
}

// validatePostgresConfig checks the PostgreSQL-specific configuration
func (c *IpMatchDatabaseConfig) validatePostgresConfig() error {
	if c.Database.Postgres == nil {
		return fmt.Errorf("database.postgres configuration is required when database.type is 'postgres'")
	}

	pg := c.Database.Postgres

	if pg.Query == "" {
		return fmt.Errorf("database.postgres.query is required")
	}

	// Validate query contains exactly one parameter placeholder
	placeholderRegex := regexp.MustCompile(`\$\d+`)
	matches := placeholderRegex.FindAllString(pg.Query, -1)
	if len(matches) != 1 {
		return fmt.Errorf("database.postgres.query must contain exactly one parameter placeholder ($1), found %d", len(matches))
	}
	if matches[0] != "$1" {
		return fmt.Errorf("database.postgres.query must use $1 as the parameter placeholder, found %s", matches[0])
	}

	// Validate host
	if pg.Host == "" {
		return fmt.Errorf("database.postgres.host is required")
	}

	// Validate port range
	if pg.Port < 1 || pg.Port > 65535 {
		return fmt.Errorf("database.postgres.port must be between 1 and 65535")
	}

	// Validate database name
	if pg.DatabaseName == "" {
		return fmt.Errorf("database.postgres.databaseName is required")
	}

	if pg.UsernameEnv == "" {
		return fmt.Errorf("database.postgres.usernameEnv is required")
	}

	if pg.PasswordEnv == "" {
		return fmt.Errorf("database.postgres.passwordEnv is required")
	}

	// Validate username env var exists
	if _, exists := os.LookupEnv(pg.UsernameEnv); !exists {
		return fmt.Errorf("environment variable '%s' not found", pg.UsernameEnv)
	}

	// Validate password env var exists
	if _, exists := os.LookupEnv(pg.PasswordEnv); !exists {
		return fmt.Errorf("environment variable '%s' not found", pg.PasswordEnv)
	}

	// Validate pool configuration if present
	if pg.Pool != nil {
		if err := validatePostgresPoolConfig(pg.Pool); err != nil {
			return fmt.Errorf("invalid pool configuration: %w", err)
		}
	}

	// Validate TLS configuration
	if pg.TLS != nil {
		if err := validatePostgresTLS(pg.TLS); err != nil {
			return fmt.Errorf("invalid postgres TLS configuration: %w", err)
		}
	}

	return nil
}

// validatePostgresPoolConfig checks pool sizing and timing values for correctness.
func validatePostgresPoolConfig(pool *PostgresPoolConfig) error {
	if pool.MaxConnections <= 0 {
		return fmt.Errorf("pool.maxConnections must be greater than 0")
	}

	if pool.MinConnections < 0 {
		return fmt.Errorf("pool.minConnections must be non-negative")
	}

	if pool.MinConnections > pool.MaxConnections {
		return fmt.Errorf("pool.minConnections (%d) must not exceed pool.maxConnections (%d)", pool.MinConnections, pool.MaxConnections)
	}

	if pool.MaxIdleTime != "" {
		poolMaxIdleTime, err := time.ParseDuration(pool.MaxIdleTime)
		if err != nil {
			return fmt.Errorf("invalid pool.maxIdleTime: %w", err)
		}
		if poolMaxIdleTime < 0 {
			return fmt.Errorf("pool.maxIdleTime must be non-negative")
		}
	}

	if pool.ConnectionTimeout != "" {
		timeout, err := time.ParseDuration(pool.ConnectionTimeout)
		if err != nil {
			return fmt.Errorf("invalid pool.connectionTimeout: %w", err)
		}
		if timeout <= 0 {
			return fmt.Errorf("pool.connectionTimeout must be positive")
		}
	}

	return nil
}

// validatePostgresTLS ensures SSL mode is valid and any certificate/key files are usable.
func validatePostgresTLS(tls *PostgresTLSConfig) error {
	// Validate SSL mode
	validModes := []string{"allow", "prefer", "require", "verify-ca", "verify-full"}
	if tls.Mode != "" {
		valid := false
		for _, mode := range validModes {
			if tls.Mode == mode {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("invalid ssl mode '%s', must be one of: %s", tls.Mode, strings.Join(validModes, ", "))
		}
	}

	// Validate certificate files exist and are readable if specified
	if tls.CACert != "" {
		if err := validateCertificateFile(tls.CACert, "CA certificate"); err != nil {
			return err
		}
	}

	if tls.ClientCert != "" {
		if err := validateCertificateFile(tls.ClientCert, "client certificate"); err != nil {
			return err
		}
	}

	if tls.ClientKey != "" {
		if err := validateKeyFile(tls.ClientKey, "client key"); err != nil {
			return err
		}
	}

	// Both client cert and key must be provided together
	if (tls.ClientCert != "" && tls.ClientKey == "") || (tls.ClientCert == "" && tls.ClientKey != "") {
		return fmt.Errorf("both clientCert and clientKey must be provided for mutual TLS")
	}

	return nil
}
