package ip_match_database

import (
	"os"
	"strings"
	"testing"
)

func TestValidatePostgresConfig(t *testing.T) {
	t.Run("requires postgres config when type is postgres", func(t *testing.T) {
		config := &IpMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "postgres",
			},
		}

		if err := config.Validate(); err == nil {
			t.Fatal("expected validation error when postgres config is missing")
		}
	})

	t.Run("valid postgres config passes", func(t *testing.T) {
		fixtures := createTLSFixtures(t)
		setEnv(t, "PG_USER", "testuser")
		setEnv(t, "PG_PASS", "testpass")

		config := &IpMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "postgres",
				Postgres: &PostgresConfig{
					Query:        "SELECT 1 FROM test WHERE ip = $1",
					Host:         "localhost",
					Port:         5432,
					DatabaseName: "testdb",
					UsernameEnv:  "PG_USER",
					PasswordEnv:  "PG_PASS",
					Pool: &PostgresPoolConfig{
						MaxConnections:    10,
						MinConnections:    1,
						MaxIdleTime:       "5m",
						ConnectionTimeout: "1s",
					},
					TLS: &PostgresTLSConfig{
						Mode:       "require",
						CACert:     fixtures.caCertPath,
						ClientCert: fixtures.clientCertPath,
						ClientKey:  fixtures.clientKeyPath,
					},
				},
			},
		}

		if err := config.Validate(); err != nil {
			t.Fatalf("expected valid config, got error: %v", err)
		}
	})

	t.Run("query with zero placeholders fails", func(t *testing.T) {
		setEnv(t, "PG_USER", "user")
		setEnv(t, "PG_PASS", "pass")

		config := &IpMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "postgres",
				Postgres: &PostgresConfig{
					Query:        "SELECT 1 FROM table",
					Host:         "localhost",
					Port:         5432,
					DatabaseName: "testdb",
					UsernameEnv:  "PG_USER",
					PasswordEnv:  "PG_PASS",
				},
			},
		}

		if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "query must contain exactly one parameter placeholder") {
			t.Fatalf("expected placeholder validation error, got: %v", err)
		}
	})

	t.Run("query with more than one placeholder fails", func(t *testing.T) {
		setEnv(t, "PG_USER", "user")
		setEnv(t, "PG_PASS", "pass")

		config := &IpMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "postgres",
				Postgres: &PostgresConfig{
					Query:        "SELECT 1 FROM table WHERE ip = $1 AND port = $2",
					Host:         "localhost",
					Port:         5432,
					DatabaseName: "testdb",
					UsernameEnv:  "PG_USER",
					PasswordEnv:  "PG_PASS",
				},
			},
		}

		if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "query must contain exactly one parameter placeholder") {
			t.Fatalf("expected placeholder validation error, got: %v", err)
		}
	})

	t.Run("query with exactly one placeholder succeeds", func(t *testing.T) {
		setEnv(t, "PG_USER", "user")
		setEnv(t, "PG_PASS", "pass")

		config := &IpMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "postgres",
				Postgres: &PostgresConfig{
					Query:        "SELECT 1 FROM table WHERE ip = $1",
					Host:         "localhost",
					Port:         5432,
					DatabaseName: "testdb",
					UsernameEnv:  "PG_USER",
					PasswordEnv:  "PG_PASS",
				},
			},
		}

		if err := config.Validate(); err != nil {
			t.Fatalf("expected validation to succeed with exactly one placeholder, got: %v", err)
		}
	})

	t.Run("missing username env fails", func(t *testing.T) {
		_ = os.Unsetenv("PG_USER_MISSING")
		setEnv(t, "PG_PASS_PRESENT", "secret")

		config := &IpMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "postgres",
				Postgres: &PostgresConfig{
					Query:        "SELECT 1 FROM test WHERE ip = $1",
					Host:         "localhost",
					Port:         5432,
					DatabaseName: "testdb",
					UsernameEnv:  "PG_USER_MISSING",
					PasswordEnv:  "PG_PASS_PRESENT",
				},
			},
		}

		if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "environment variable 'PG_USER_MISSING' not found") {
			t.Fatalf("expected missing username env error, got: %v", err)
		}
	})

	t.Run("missing password env fails", func(t *testing.T) {
		setEnv(t, "PG_USER_PRESENT", "user")
		_ = os.Unsetenv("PG_PASS_MISSING")

		config := &IpMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "postgres",
				Postgres: &PostgresConfig{
					Query:        "SELECT 1 FROM test WHERE ip = $1",
					Host:         "localhost",
					Port:         5432,
					DatabaseName: "testdb",
					UsernameEnv:  "PG_USER_PRESENT",
					PasswordEnv:  "PG_PASS_MISSING",
				},
			},
		}

		if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "environment variable 'PG_PASS_MISSING' not found") {
			t.Fatalf("expected missing password env error, got: %v", err)
		}
	})

	t.Run("pool maxConnections must be positive", func(t *testing.T) {
		setEnv(t, "PG_USER", "user")
		setEnv(t, "PG_PASS", "pass")

		config := &IpMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "postgres",
				Postgres: &PostgresConfig{
					Query:        "SELECT 1 FROM test WHERE ip = $1",
					Host:         "localhost",
					Port:         5432,
					DatabaseName: "testdb",
					UsernameEnv:  "PG_USER",
					PasswordEnv:  "PG_PASS",
					Pool: &PostgresPoolConfig{
						MaxConnections: 0,
						MinConnections: 0,
					},
				},
			},
		}

		if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "pool.maxConnections must be greater than 0") {
			t.Fatalf("expected maxConnections validation error, got: %v", err)
		}
	})

	t.Run("pool minConnections cannot exceed maxConnections", func(t *testing.T) {
		setEnv(t, "PG_USER", "user")
		setEnv(t, "PG_PASS", "pass")

		config := &IpMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "postgres",
				Postgres: &PostgresConfig{
					Query:        "SELECT 1 FROM test WHERE ip = $1",
					Host:         "localhost",
					Port:         5432,
					DatabaseName: "testdb",
					UsernameEnv:  "PG_USER",
					PasswordEnv:  "PG_PASS",
					Pool: &PostgresPoolConfig{
						MaxConnections: 5,
						MinConnections: 10,
					},
				},
			},
		}

		if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "must not exceed") {
			t.Fatalf("expected minConnections validation error, got: %v", err)
		}
	})

	t.Run("pool duration fields must parse and be positive", func(t *testing.T) {
		setEnv(t, "PG_USER", "user")
		setEnv(t, "PG_PASS", "pass")

		config := &IpMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "postgres",
				Postgres: &PostgresConfig{
					Query:        "SELECT 1 FROM test WHERE ip = $1",
					Host:         "localhost",
					Port:         5432,
					DatabaseName: "testdb",
					UsernameEnv:  "PG_USER",
					PasswordEnv:  "PG_PASS",
					Pool: &PostgresPoolConfig{
						MaxConnections:    5,
						MinConnections:    1,
						MaxIdleTime:       "not-a-duration",
						ConnectionTimeout: "0s",
					},
				},
			},
		}

		if err := config.Validate(); err == nil || (!strings.Contains(err.Error(), "invalid pool.maxIdleTime") && !strings.Contains(err.Error(), "pool.connectionTimeout")) {
			t.Fatalf("expected duration validation error, got: %v", err)
		}
	})

	t.Run("invalid TLS mode fails", func(t *testing.T) {
		setEnv(t, "PG_USER", "user")
		setEnv(t, "PG_PASS", "pass")

		config := &IpMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "postgres",
				Postgres: &PostgresConfig{
					Query:        "SELECT 1 FROM test WHERE ip = $1",
					Host:         "localhost",
					Port:         5432,
					DatabaseName: "testdb",
					UsernameEnv:  "PG_USER",
					PasswordEnv:  "PG_PASS",
					TLS: &PostgresTLSConfig{
						Mode: "bad-mode",
					},
				},
			},
		}

		if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "invalid ssl mode") {
			t.Fatalf("expected TLS mode validation error, got: %v", err)
		}
	})

	t.Run("client certificate without key fails", func(t *testing.T) {
		fixtures := createTLSFixtures(t)
		setEnv(t, "PG_USER", "user")
		setEnv(t, "PG_PASS", "pass")

		config := &IpMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "postgres",
				Postgres: &PostgresConfig{
					Query:        "SELECT 1 FROM test WHERE ip = $1",
					Host:         "localhost",
					Port:         5432,
					DatabaseName: "testdb",
					UsernameEnv:  "PG_USER",
					PasswordEnv:  "PG_PASS",
					TLS: &PostgresTLSConfig{
						Mode:       "require",
						ClientCert: fixtures.clientCertPath,
					},
				},
			},
		}

		if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "both clientCert and clientKey must be provided") {
			t.Fatalf("expected mutual TLS pairing error, got: %v", err)
		}
	})

	t.Run("invalid PEM client key fails", func(t *testing.T) {
		fixtures := createTLSFixtures(t)
		setEnv(t, "PG_USER", "user")
		setEnv(t, "PG_PASS", "pass")

		config := &IpMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "postgres",
				Postgres: &PostgresConfig{
					Query:        "SELECT 1 FROM test WHERE ip = $1",
					Host:         "localhost",
					Port:         5432,
					DatabaseName: "testdb",
					UsernameEnv:  "PG_USER",
					PasswordEnv:  "PG_PASS",
					TLS: &PostgresTLSConfig{
						Mode:       "require",
						ClientCert: fixtures.clientCertPath,
						ClientKey:  fixtures.invalidPEMPath,
					},
				},
			},
		}

		if err := config.Validate(); err == nil || (!strings.Contains(err.Error(), "valid PEM-encoded data") && !strings.Contains(err.Error(), "valid private key")) {
			t.Fatalf("expected invalid PEM error, got: %v", err)
		}
	})
}
