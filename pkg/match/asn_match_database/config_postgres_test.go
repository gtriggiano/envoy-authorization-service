package asn_match_database

import (
	"strings"
	"testing"
	"time"
)

func TestValidatePostgresConfig(t *testing.T) {
	t.Run("requires postgres config when type is postgres", func(t *testing.T) {
		config := &ASNMatchDatabaseConfig{
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

		config := &ASNMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "postgres",
				Postgres: &PostgresConfig{
					Query:        "SELECT 1 FROM test WHERE ip = $1",
					Host:         "localhost",
					Port:         5432,
					DatabaseName: "testdb",
					Username:     "user",
					Password:     "pass",
					Pool: &PostgresPoolConfig{
						MaxConnections:    10,
						MinConnections:    1,
						MaxIdleTime:       durationPtr(5 * time.Minute),
						ConnectionTimeout: durationPtr(time.Second),
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

		config := &ASNMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "postgres",
				Postgres: &PostgresConfig{
					Query:        "SELECT 1 FROM table",
					Host:         "localhost",
					Port:         5432,
					DatabaseName: "testdb",
					Username:     "user",
					Password:     "pass",
				},
			},
		}

		if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "query must contain exactly one parameter placeholder") {
			t.Fatalf("expected placeholder validation error, got: %v", err)
		}
	})

	t.Run("query with more than one placeholder fails", func(t *testing.T) {

		config := &ASNMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "postgres",
				Postgres: &PostgresConfig{
					Query:        "SELECT 1 FROM table WHERE ip = $1 AND port = $2",
					Host:         "localhost",
					Port:         5432,
					DatabaseName: "testdb",
					Username:     "user",
					Password:     "pass",
				},
			},
		}

		if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "query must contain exactly one parameter placeholder") {
			t.Fatalf("expected placeholder validation error, got: %v", err)
		}
	})

	t.Run("query with exactly one placeholder succeeds", func(t *testing.T) {

		config := &ASNMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "postgres",
				Postgres: &PostgresConfig{
					Query:        "SELECT 1 FROM table WHERE ip = $1",
					Host:         "localhost",
					Port:         5432,
					DatabaseName: "testdb",
					Username:     "user",
					Password:     "pass",
				},
			},
		}

		if err := config.Validate(); err != nil {
			t.Fatalf("expected validation to succeed with exactly one placeholder, got: %v", err)
		}
	})

	t.Run("username and usernameFile are mutually exclusive", func(t *testing.T) {
		config := &ASNMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "postgres",
				Postgres: &PostgresConfig{
					Query:        "SELECT 1 FROM test WHERE ip = $1",
					Host:         "localhost",
					Port:         5432,
					DatabaseName: "testdb",
					Username:     "user",
					UsernameFile: "/secrets/user",
					Password:     "pass",
				},
			},
		}

		if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "database.postgres.username and database.postgres.usernameFile are mutually exclusive") {
			t.Fatalf("expected mutual exclusion error, got: %v", err)
		}
	})

	t.Run("password and passwordFile are mutually exclusive", func(t *testing.T) {
		config := &ASNMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "postgres",
				Postgres: &PostgresConfig{
					Query:        "SELECT 1 FROM test WHERE ip = $1",
					Host:         "localhost",
					Port:         5432,
					DatabaseName: "testdb",
					Username:     "user",
					Password:     "pass",
					PasswordFile: "/secrets/pass",
				},
			},
		}

		if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "database.postgres.password and database.postgres.passwordFile are mutually exclusive") {
			t.Fatalf("expected mutual exclusion error, got: %v", err)
		}
	})

	t.Run("pool maxConnections must be positive", func(t *testing.T) {

		config := &ASNMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "postgres",
				Postgres: &PostgresConfig{
					Query:        "SELECT 1 FROM test WHERE ip = $1",
					Host:         "localhost",
					Port:         5432,
					DatabaseName: "testdb",
					Username:     "user",
					Password:     "pass",
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

		config := &ASNMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "postgres",
				Postgres: &PostgresConfig{
					Query:        "SELECT 1 FROM test WHERE ip = $1",
					Host:         "localhost",
					Port:         5432,
					DatabaseName: "testdb",
					Username:     "user",
					Password:     "pass",
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

		config := &ASNMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "postgres",
				Postgres: &PostgresConfig{
					Query:        "SELECT 1 FROM test WHERE ip = $1",
					Host:         "localhost",
					Port:         5432,
					DatabaseName: "testdb",
					Username:     "user",
					Password:     "pass",
					Pool: &PostgresPoolConfig{
						MaxConnections:    5,
						MinConnections:    1,
						MaxIdleTime:       durationPtr(0),
						ConnectionTimeout: durationPtr(0),
					},
				},
			},
		}

		if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "pool.maxIdleTime must be positive") {
			t.Fatalf("expected duration validation error, got: %v", err)
		}
	})

	t.Run("invalid TLS mode fails", func(t *testing.T) {

		config := &ASNMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "postgres",
				Postgres: &PostgresConfig{
					Query:        "SELECT 1 FROM test WHERE ip = $1",
					Host:         "localhost",
					Port:         5432,
					DatabaseName: "testdb",
					Username:     "user",
					Password:     "pass",
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

		config := &ASNMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "postgres",
				Postgres: &PostgresConfig{
					Query:        "SELECT 1 FROM test WHERE ip = $1",
					Host:         "localhost",
					Port:         5432,
					DatabaseName: "testdb",
					Username:     "user",
					Password:     "pass",
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

		config := &ASNMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "postgres",
				Postgres: &PostgresConfig{
					Query:        "SELECT 1 FROM test WHERE ip = $1",
					Host:         "localhost",
					Port:         5432,
					DatabaseName: "testdb",
					Username:     "user",
					Password:     "pass",
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
