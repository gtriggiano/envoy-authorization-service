package ip_match_database

import (
	"os"
	"strings"
	"testing"
)

func TestValidateSQLServerConfig(t *testing.T) {
	t.Run("requires sqlserver config when type is sqlserver", func(t *testing.T) {
		config := &IpMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "sqlserver",
			},
		}

		if err := config.Validate(); err == nil {
			t.Fatal("expected validation error when sqlserver config is missing")
		}
	})

	t.Run("valid sqlserver config passes", func(t *testing.T) {
		fixtures := createTLSFixtures(t)
		setEnv(t, "MSSQL_USER", "sa")
		setEnv(t, "MSSQL_PASS", "secret")

		config := &IpMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "sqlserver",
				SQLServer: &SQLServerConfig{
					Query:        "SELECT 1 FROM trusted_ips WHERE ip = @p1",
					Host:         "localhost",
					Port:         1433,
					DatabaseName: "security",
					UsernameEnv:  "MSSQL_USER",
					PasswordEnv:  "MSSQL_PASS",
					Pool: &SQLServerPoolConfig{
						MaxConnections:    10,
						MinConnections:    1,
						MaxIdleTime:       "5m",
						ConnectionTimeout: "1s",
					},
					TLS: &SQLServerTLSConfig{
						Encrypt:                "strict",
						TrustServerCertificate: false,
						CACert:                 fixtures.caCertPath,
						HostNameInCertificate:  "sqlserver.example.com",
						TLSMin:                 "1.2",
					},
				},
			},
		}

		if err := config.Validate(); err != nil {
			t.Fatalf("expected valid config, got error: %v", err)
		}
	})

	t.Run("query with zero placeholders fails", func(t *testing.T) {
		setEnv(t, "MSSQL_USER", "sa")
		setEnv(t, "MSSQL_PASS", "secret")

		config := &IpMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "sqlserver",
				SQLServer: &SQLServerConfig{
					Query:        "SELECT 1 FROM trusted_ips",
					Host:         "localhost",
					Port:         1433,
					DatabaseName: "security",
					UsernameEnv:  "MSSQL_USER",
					PasswordEnv:  "MSSQL_PASS",
				},
			},
		}

		if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "query must contain exactly one parameter placeholder") {
			t.Fatalf("expected placeholder validation error, got: %v", err)
		}
	})

	t.Run("query with more than one placeholder fails", func(t *testing.T) {
		setEnv(t, "MSSQL_USER", "sa")
		setEnv(t, "MSSQL_PASS", "secret")

		config := &IpMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "sqlserver",
				SQLServer: &SQLServerConfig{
					Query:        "SELECT 1 FROM trusted_ips WHERE ip = @p1 AND id = @p2",
					Host:         "localhost",
					Port:         1433,
					DatabaseName: "security",
					UsernameEnv:  "MSSQL_USER",
					PasswordEnv:  "MSSQL_PASS",
				},
			},
		}

		if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "query must contain exactly one parameter placeholder") {
			t.Fatalf("expected placeholder validation error, got: %v", err)
		}
	})

	t.Run("query with exactly one placeholder succeeds", func(t *testing.T) {
		setEnv(t, "MSSQL_USER", "sa")
		setEnv(t, "MSSQL_PASS", "secret")

		config := &IpMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "sqlserver",
				SQLServer: &SQLServerConfig{
					Query:        "SELECT 1 FROM trusted_ips WHERE ip = @p1",
					Host:         "localhost",
					Port:         1433,
					DatabaseName: "security",
					UsernameEnv:  "MSSQL_USER",
					PasswordEnv:  "MSSQL_PASS",
				},
			},
		}

		if err := config.Validate(); err != nil {
			t.Fatalf("expected validation to succeed with exactly one placeholder, got: %v", err)
		}
	})

	t.Run("query with non-first placeholder fails", func(t *testing.T) {
		setEnv(t, "MSSQL_USER", "sa")
		setEnv(t, "MSSQL_PASS", "secret")

		config := &IpMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "sqlserver",
				SQLServer: &SQLServerConfig{
					Query:        "SELECT 1 FROM trusted_ips WHERE ip = @p2",
					Host:         "localhost",
					Port:         1433,
					DatabaseName: "security",
					UsernameEnv:  "MSSQL_USER",
					PasswordEnv:  "MSSQL_PASS",
				},
			},
		}

		if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "must use @p1") {
			t.Fatalf("expected @p1 validation error, got: %v", err)
		}
	})

	t.Run("missing username env fails", func(t *testing.T) {
		_ = os.Unsetenv("MSSQL_USER_MISSING")
		setEnv(t, "MSSQL_PASS_PRESENT", "secret")

		config := &IpMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "sqlserver",
				SQLServer: &SQLServerConfig{
					Query:        "SELECT 1 FROM trusted_ips WHERE ip = @p1",
					Host:         "localhost",
					Port:         1433,
					DatabaseName: "security",
					UsernameEnv:  "MSSQL_USER_MISSING",
					PasswordEnv:  "MSSQL_PASS_PRESENT",
				},
			},
		}

		if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "environment variable 'MSSQL_USER_MISSING' not found") {
			t.Fatalf("expected missing username env error, got: %v", err)
		}
	})

	t.Run("missing password env fails", func(t *testing.T) {
		setEnv(t, "MSSQL_USER_PRESENT", "sa")
		_ = os.Unsetenv("MSSQL_PASS_MISSING")

		config := &IpMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "sqlserver",
				SQLServer: &SQLServerConfig{
					Query:        "SELECT 1 FROM trusted_ips WHERE ip = @p1",
					Host:         "localhost",
					Port:         1433,
					DatabaseName: "security",
					UsernameEnv:  "MSSQL_USER_PRESENT",
					PasswordEnv:  "MSSQL_PASS_MISSING",
				},
			},
		}

		if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "environment variable 'MSSQL_PASS_MISSING' not found") {
			t.Fatalf("expected missing password env error, got: %v", err)
		}
	})

	t.Run("pool maxConnections must be positive", func(t *testing.T) {
		setEnv(t, "MSSQL_USER", "sa")
		setEnv(t, "MSSQL_PASS", "secret")

		config := &IpMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "sqlserver",
				SQLServer: &SQLServerConfig{
					Query:        "SELECT 1 FROM trusted_ips WHERE ip = @p1",
					Host:         "localhost",
					Port:         1433,
					DatabaseName: "security",
					UsernameEnv:  "MSSQL_USER",
					PasswordEnv:  "MSSQL_PASS",
					Pool: &SQLServerPoolConfig{
						MaxConnections: 0,
					},
				},
			},
		}

		if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "pool.maxConnections must be greater than 0") {
			t.Fatalf("expected maxConnections validation error, got: %v", err)
		}
	})

	t.Run("pool minConnections cannot exceed maxConnections", func(t *testing.T) {
		setEnv(t, "MSSQL_USER", "sa")
		setEnv(t, "MSSQL_PASS", "secret")

		config := &IpMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "sqlserver",
				SQLServer: &SQLServerConfig{
					Query:        "SELECT 1 FROM trusted_ips WHERE ip = @p1",
					Host:         "localhost",
					Port:         1433,
					DatabaseName: "security",
					UsernameEnv:  "MSSQL_USER",
					PasswordEnv:  "MSSQL_PASS",
					Pool: &SQLServerPoolConfig{
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

	t.Run("uses default localhost and 1433", func(t *testing.T) {
		setEnv(t, "MSSQL_USER", "sa")
		setEnv(t, "MSSQL_PASS", "secret")

		config := &IpMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "sqlserver",
				SQLServer: &SQLServerConfig{
					Query:        "SELECT 1 FROM trusted_ips WHERE ip = @p1",
					DatabaseName: "security",
					UsernameEnv:  "MSSQL_USER",
					PasswordEnv:  "MSSQL_PASS",
				},
			},
		}
		config.ApplyDefaults()

		if config.Database.SQLServer.Host != "localhost" {
			t.Fatalf("expected default host localhost, got %q", config.Database.SQLServer.Host)
		}
		if config.Database.SQLServer.Port != 1433 {
			t.Fatalf("expected default port 1433, got %d", config.Database.SQLServer.Port)
		}
		if err := config.Validate(); err != nil {
			t.Fatalf("expected valid config, got error: %v", err)
		}
	})

	t.Run("raw connectionString passes without username and password env", func(t *testing.T) {
		config := &IpMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "sqlserver",
				SQLServer: &SQLServerConfig{
					Query:            "SELECT 1 FROM trusted_ips WHERE ip = @p1",
					ConnectionString: "sqlserver://sa:secret@localhost:1433?database=security&encrypt=disable",
				},
			},
		}

		if err := config.Validate(); err != nil {
			t.Fatalf("expected valid raw connection string config, got error: %v", err)
		}
	})

	t.Run("raw connectionStringEnv passes without username and password env", func(t *testing.T) {
		setEnv(t, "SQLSERVER_DSN", "sqlserver://sa:secret@localhost:1433?database=security&encrypt=disable")

		config := &IpMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "sqlserver",
				SQLServer: &SQLServerConfig{
					Query:               "SELECT 1 FROM trusted_ips WHERE ip = @p1",
					ConnectionStringEnv: "SQLSERVER_DSN",
				},
			},
		}

		if err := config.Validate(); err != nil {
			t.Fatalf("expected valid raw connection string env config, got error: %v", err)
		}
	})

	t.Run("connectionString and connectionStringEnv are mutually exclusive", func(t *testing.T) {
		setEnv(t, "SQLSERVER_DSN", "sqlserver://sa:secret@localhost:1433?database=security&encrypt=disable")

		config := &IpMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "sqlserver",
				SQLServer: &SQLServerConfig{
					Query:               "SELECT 1 FROM trusted_ips WHERE ip = @p1",
					ConnectionString:    "sqlserver://sa:secret@localhost:1433?database=security",
					ConnectionStringEnv: "SQLSERVER_DSN",
				},
			},
		}

		if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
			t.Fatalf("expected mutually exclusive validation error, got: %v", err)
		}
	})

	t.Run("connectionString mode rejects structured TLS fields", func(t *testing.T) {
		fixtures := createTLSFixtures(t)

		config := &IpMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "sqlserver",
				SQLServer: &SQLServerConfig{
					Query:            "SELECT 1 FROM trusted_ips WHERE ip = @p1",
					ConnectionString: "sqlserver://sa:secret@localhost:1433?database=security&encrypt=strict",
					TLS: &SQLServerTLSConfig{
						CACert: fixtures.caCertPath,
					},
				},
			},
		}

		if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "cannot be used with connectionString") {
			t.Fatalf("expected raw-connection/TLS validation error, got: %v", err)
		}
	})

	t.Run("connectionString mode rejects structured sqlserver connection fields", func(t *testing.T) {
		config := &IpMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "sqlserver",
				SQLServer: &SQLServerConfig{
					Query:            "SELECT 1 FROM trusted_ips WHERE ip = @p1",
					ConnectionString: "sqlserver://sa:secret@localhost:1433?database=security&encrypt=strict",
					Instance:         "SQLEXPRESS",
				},
			},
		}

		if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "structured connection fields cannot be combined") {
			t.Fatalf("expected raw-connection/structured-fields validation error, got: %v", err)
		}
	})

	t.Run("connectionString mode rejects host field", func(t *testing.T) {
		config := &IpMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "sqlserver",
				SQLServer: &SQLServerConfig{
					Query:            "SELECT 1 FROM trusted_ips WHERE ip = @p1",
					ConnectionString: "sqlserver://sa:secret@localhost:1433?database=security&encrypt=strict",
					Host:             "example.com",
				},
			},
		}

		if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "structured connection fields cannot be combined") {
			t.Fatalf("expected raw-connection/structured-fields validation error, got: %v", err)
		}
	})

	t.Run("connectionString mode rejects port field", func(t *testing.T) {
		config := &IpMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "sqlserver",
				SQLServer: &SQLServerConfig{
					Query:            "SELECT 1 FROM trusted_ips WHERE ip = @p1",
					ConnectionString: "sqlserver://sa:secret@localhost:1433?database=security&encrypt=strict",
					Port:             1433,
				},
			},
		}

		if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "structured connection fields cannot be combined") {
			t.Fatalf("expected raw-connection/structured-fields validation error, got: %v", err)
		}
	})

	t.Run("failoverPort requires failoverPartner", func(t *testing.T) {
		setEnv(t, "MSSQL_USER", "sa")
		setEnv(t, "MSSQL_PASS", "secret")

		config := &IpMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "sqlserver",
				SQLServer: &SQLServerConfig{
					Query:        "SELECT 1 FROM trusted_ips WHERE ip = @p1",
					Host:         "localhost",
					Port:         1433,
					DatabaseName: "security",
					UsernameEnv:  "MSSQL_USER",
					PasswordEnv:  "MSSQL_PASS",
					FailoverPort: 1433,
				},
			},
		}

		if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "failoverPartner is required") {
			t.Fatalf("expected failover partner validation error, got: %v", err)
		}
	})

	t.Run("invalid application intent fails", func(t *testing.T) {
		setEnv(t, "MSSQL_USER", "sa")
		setEnv(t, "MSSQL_PASS", "secret")

		config := &IpMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "sqlserver",
				SQLServer: &SQLServerConfig{
					Query:             "SELECT 1 FROM trusted_ips WHERE ip = @p1",
					Host:              "localhost",
					Port:              1433,
					DatabaseName:      "security",
					UsernameEnv:       "MSSQL_USER",
					PasswordEnv:       "MSSQL_PASS",
					ApplicationIntent: "write-mostly",
				},
			},
		}

		if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "invalid applicationIntent") {
			t.Fatalf("expected applicationIntent validation error, got: %v", err)
		}
	})

	t.Run("invalid protocol fails", func(t *testing.T) {
		setEnv(t, "MSSQL_USER", "sa")
		setEnv(t, "MSSQL_PASS", "secret")

		config := &IpMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "sqlserver",
				SQLServer: &SQLServerConfig{
					Query:        "SELECT 1 FROM trusted_ips WHERE ip = @p1",
					Host:         "localhost",
					Port:         1433,
					DatabaseName: "security",
					UsernameEnv:  "MSSQL_USER",
					PasswordEnv:  "MSSQL_PASS",
					Protocol:     "http",
				},
			},
		}

		if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "invalid protocol") {
			t.Fatalf("expected protocol validation error, got: %v", err)
		}
	})

	t.Run("invalid TLS encrypt mode fails", func(t *testing.T) {
		setEnv(t, "MSSQL_USER", "sa")
		setEnv(t, "MSSQL_PASS", "secret")

		config := &IpMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "sqlserver",
				SQLServer: &SQLServerConfig{
					Query:        "SELECT 1 FROM trusted_ips WHERE ip = @p1",
					Host:         "localhost",
					Port:         1433,
					DatabaseName: "security",
					UsernameEnv:  "MSSQL_USER",
					PasswordEnv:  "MSSQL_PASS",
					TLS: &SQLServerTLSConfig{
						Encrypt: "bad-mode",
					},
				},
			},
		}

		if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "invalid encrypt mode") {
			t.Fatalf("expected TLS encrypt mode validation error, got: %v", err)
		}
	})

	t.Run("invalid TLS min version fails", func(t *testing.T) {
		setEnv(t, "MSSQL_USER", "sa")
		setEnv(t, "MSSQL_PASS", "secret")

		config := &IpMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "sqlserver",
				SQLServer: &SQLServerConfig{
					Query:        "SELECT 1 FROM trusted_ips WHERE ip = @p1",
					Host:         "localhost",
					Port:         1433,
					DatabaseName: "security",
					UsernameEnv:  "MSSQL_USER",
					PasswordEnv:  "MSSQL_PASS",
					TLS: &SQLServerTLSConfig{
						TLSMin: "1.4",
					},
				},
			},
		}

		if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "invalid tlsMin") {
			t.Fatalf("expected TLS min version validation error, got: %v", err)
		}
	})

	t.Run("TLS verification options with disabled encryption fails", func(t *testing.T) {
		fixtures := createTLSFixtures(t)
		setEnv(t, "MSSQL_USER", "sa")
		setEnv(t, "MSSQL_PASS", "secret")

		config := &IpMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "sqlserver",
				SQLServer: &SQLServerConfig{
					Query:        "SELECT 1 FROM trusted_ips WHERE ip = @p1",
					Host:         "localhost",
					Port:         1433,
					DatabaseName: "security",
					UsernameEnv:  "MSSQL_USER",
					PasswordEnv:  "MSSQL_PASS",
					TLS: &SQLServerTLSConfig{
						Encrypt: "disable",
						CACert:  fixtures.caCertPath,
					},
				},
			},
		}

		if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "require encrypt to be true, mandatory, or strict") {
			t.Fatalf("expected TLS/encrypt compatibility validation error, got: %v", err)
		}
	})
}
