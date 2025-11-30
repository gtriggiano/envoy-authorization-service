package asn_match_database

import (
	"os"
	"strings"
	"testing"
)

func TestValidateRedisConfig(t *testing.T) {
	t.Run("requires redis config when type is redis", func(t *testing.T) {
		config := &ASNMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "redis",
			},
		}

		if err := config.Validate(); err == nil {
			t.Fatal("expected validation error when redis config is missing")
		}
	})

	t.Run("valid redis config passes", func(t *testing.T) {
		fixtures := createTLSFixtures(t)

		config := &ASNMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "redis",
				Redis: &RedisConfig{
					KeyPrefix: "test:",
					Host:      "localhost",
					Port:      6379,
					DB:        0,
					TLS: &RedisTLSConfig{
						CACert: fixtures.caCertPath,
					},
				},
			},
		}

		if err := config.Validate(); err != nil {
			t.Fatalf("expected valid config, got error: %v", err)
		}
	})

	t.Run("missing keyPrefix fails", func(t *testing.T) {
		config := &ASNMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "redis",
				Redis: &RedisConfig{
					Host: "localhost",
					Port: 6379,
				},
			},
		}

		if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "database.redis.keyPrefix is required") {
			t.Fatalf("expected keyPrefix validation error, got: %v", err)
		}
	})

	t.Run("host is required", func(t *testing.T) {
		config := &ASNMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "redis",
				Redis: &RedisConfig{
					KeyPrefix: "test:",
					Port:      6379,
				},
			},
		}

		if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "database.redis.host is required") {
			t.Fatalf("expected host validation error, got: %v", err)
		}
	})

	t.Run("port must be in range", func(t *testing.T) {
		config := &ASNMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "redis",
				Redis: &RedisConfig{
					KeyPrefix: "test:",
					Host:      "localhost",
					Port:      70000,
				},
			},
		}

		if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "database.redis.port must be between 1 and 65535") {
			t.Fatalf("expected port validation error, got: %v", err)
		}
	})

	t.Run("db number must be non-negative", func(t *testing.T) {
		config := &ASNMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "redis",
				Redis: &RedisConfig{
					KeyPrefix: "test:",
					Host:      "localhost",
					Port:      6379,
					DB:        -1,
				},
			},
		}

		if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "database.redis.db must be non-negative") {
			t.Fatalf("expected db validation error, got: %v", err)
		}
	})

	t.Run("specified username env must exist", func(t *testing.T) {
		_ = os.Unsetenv("REDIS_MISSING_USER")

		config := &ASNMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "redis",
				Redis: &RedisConfig{
					KeyPrefix:   "test:",
					Host:        "localhost",
					Port:        6379,
					UsernameEnv: "REDIS_MISSING_USER",
				},
			},
		}

		if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "environment variable 'REDIS_MISSING_USER' not found") {
			t.Fatalf("expected username env validation error, got: %v", err)
		}
	})

	t.Run("specified password env must exist", func(t *testing.T) {
		setEnv(t, "REDIS_USER_PRESENT", "user")
		_ = os.Unsetenv("REDIS_MISSING_PASS")

		config := &ASNMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "redis",
				Redis: &RedisConfig{
					KeyPrefix:   "test:",
					Host:        "localhost",
					Port:        6379,
					UsernameEnv: "REDIS_USER_PRESENT",
					PasswordEnv: "REDIS_MISSING_PASS",
				},
			},
		}

		if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "environment variable 'REDIS_MISSING_PASS' not found") {
			t.Fatalf("expected password env validation error, got: %v", err)
		}
	})

	t.Run("client certificate without key fails", func(t *testing.T) {
		fixtures := createTLSFixtures(t)

		config := &ASNMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "redis",
				Redis: &RedisConfig{
					KeyPrefix: "test:",
					Host:      "localhost",
					Port:      6379,
					TLS: &RedisTLSConfig{
						ClientCert: fixtures.clientCertPath,
					},
				},
			},
		}

		if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "both clientCert and clientKey must be provided") {
			t.Fatalf("expected mutual TLS pairing error, got: %v", err)
		}
	})

	t.Run("invalid PEM ca cert fails", func(t *testing.T) {
		fixtures := createTLSFixtures(t)

		config := &ASNMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "redis",
				Redis: &RedisConfig{
					KeyPrefix: "test:",
					Host:      "localhost",
					Port:      6379,
					TLS: &RedisTLSConfig{
						CACert: fixtures.invalidPEMPath,
					},
				},
			},
		}

		if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "valid PEM-encoded certificate") {
			t.Fatalf("expected invalid PEM validation error, got: %v", err)
		}
	})
}
