package ip_match_database

import (
	"fmt"
	"os"
)

// RedisConfig represents Redis-specific configuration
type RedisConfig struct {
	KeyPrefix   string          `yaml:"keyPrefix"`
	Host        string          `yaml:"host"`
	Port        int             `yaml:"port"`
	UsernameEnv string          `yaml:"usernameEnv"`
	PasswordEnv string          `yaml:"passwordEnv"`
	DB          int             `yaml:"db"`
	TLS         *RedisTLSConfig `yaml:"tls"`
}

// RedisTLSConfig represents TLS configuration for Redis
type RedisTLSConfig struct {
	InsecureSkipVerify bool   `yaml:"insecureSkipVerify"`
	CACert             string `yaml:"caCert"`
	ClientCert         string `yaml:"clientCert"`
	ClientKey          string `yaml:"clientKey"`
}

// ApplyDefaults sets default values for the redis configuration
func (c *RedisConfig) ApplyDefaults() {
	if c != nil {
		if c.Port == 0 {
			c.Port = defaultRedisPort
		}
	}
}

// validateRedisConfig checks the Redis-specific configuration
func (c *IpMatchDatabaseConfig) validateRedisConfig() error {
	if c.Database.Redis == nil {
		return fmt.Errorf("database.redis configuration is required when database.type is 'redis'")
	}

	redis := c.Database.Redis

	// Validate key prefix
	if redis.KeyPrefix == "" {
		return fmt.Errorf("database.redis.keyPrefix is required")
	}

	// Validate host
	if redis.Host == "" {
		return fmt.Errorf("database.redis.host is required")
	}

	// Validate port range
	if redis.Port < 1 || redis.Port > 65535 {
		return fmt.Errorf("database.redis.port must be between 1 and 65535")
	}

	// Validate DB number
	if redis.DB < 0 {
		return fmt.Errorf("database.redis.db must be non-negative")
	}

	// Validate username env var exists if specified
	if redis.UsernameEnv != "" {
		if _, exists := os.LookupEnv(redis.UsernameEnv); !exists {
			return fmt.Errorf("environment variable '%s' not found", redis.UsernameEnv)
		}
	}

	// Validate password env var exists if specified
	if redis.PasswordEnv != "" {
		if _, exists := os.LookupEnv(redis.PasswordEnv); !exists {
			return fmt.Errorf("environment variable '%s' not found", redis.PasswordEnv)
		}
	}

	// Validate TLS configuration
	if redis.TLS != nil {
		if err := validateRedisTLS(redis.TLS); err != nil {
			return fmt.Errorf("invalid redis TLS configuration: %w", err)
		}
	}

	return nil
}

// validateRedisTLS ensures optional Redis TLS settings point to valid certificates/keys and are consistent.
func validateRedisTLS(tls *RedisTLSConfig) error {
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
