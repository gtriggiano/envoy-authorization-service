package ip_match_database

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestBuildSQLServerConnectionString(t *testing.T) {
	multiSubnetFailover := true
	config := &SQLServerConfig{
		Host:                "localhost",
		Port:                1433,
		Instance:            "SQLEXPRESS",
		DatabaseName:        "security",
		FailoverPartner:     "localhost",
		FailoverPort:        1444,
		MultiSubnetFailover: &multiSubnetFailover,
		ApplicationIntent:   "ReadOnly",
		Protocol:            "tcp",
		AppName:             "envoy-authz-tests",
	}

	connString := buildSQLServerConnectionString(config, "sa", "secret", 7*time.Second)

	expectedParts := []string{
		"sqlserver://sa:secret@localhost:1433",
		"/SQLEXPRESS?",
		"database=security",
		"connection+timeout=7",
		"failoverpartner=localhost",
		"failoverport=1444",
		"multisubnetfailover=true",
		"applicationintent=ReadOnly",
		"protocol=tcp",
		"app+name=envoy-authz-tests",
	}
	for _, part := range expectedParts {
		if !strings.Contains(connString, part) {
			t.Fatalf("connection string %q must contain %q", connString, part)
		}
	}
}

func TestResolveSQLServerConnectionString(t *testing.T) {
	t.Run("returns inline connection string as-is", func(t *testing.T) {
		cfg := &SQLServerConfig{
			ConnectionString: "sqlserver://sa:secret@localhost:1433?database=security",
		}
		got, err := resolveSQLServerConnectionString(cfg, 5*time.Second)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != cfg.ConnectionString {
			t.Fatalf("expected inline connection string, got %q", got)
		}
	})

	t.Run("returns connection string from env", func(t *testing.T) {
		key := "SQLSERVER_DSN_TEST"
		value := "sqlserver://sa:secret@localhost:1433?database=security"
		if err := os.Setenv(key, value); err != nil {
			t.Fatalf("failed setting env: %v", err)
		}
		t.Cleanup(func() { _ = os.Unsetenv(key) })

		cfg := &SQLServerConfig{
			ConnectionStringEnv: key,
		}
		got, err := resolveSQLServerConnectionString(cfg, 5*time.Second)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != value {
			t.Fatalf("expected env connection string, got %q", got)
		}
	})

	t.Run("structured mode requires non-empty env credentials", func(t *testing.T) {
		cfg := &SQLServerConfig{
			Host:         "localhost",
			Port:         1433,
			DatabaseName: "security",
			UsernameEnv:  "MISSING_USER_ENV",
			PasswordEnv:  "MISSING_PASS_ENV",
		}
		_, err := resolveSQLServerConnectionString(cfg, 5*time.Second)
		if err == nil {
			t.Fatal("expected error for missing env credentials")
		}
	})

	t.Run("structured mode builds a valid connection string", func(t *testing.T) {
		if err := os.Setenv("MSSQL_USER_TEST", "sa"); err != nil {
			t.Fatalf("failed setting env: %v", err)
		}
		if err := os.Setenv("MSSQL_PASS_TEST", "secret"); err != nil {
			t.Fatalf("failed setting env: %v", err)
		}
		t.Cleanup(func() {
			_ = os.Unsetenv("MSSQL_USER_TEST")
			_ = os.Unsetenv("MSSQL_PASS_TEST")
		})

		cfg := &SQLServerConfig{
			Host:         "localhost",
			Port:         1433,
			DatabaseName: "security",
			UsernameEnv:  "MSSQL_USER_TEST",
			PasswordEnv:  "MSSQL_PASS_TEST",
		}
		got, err := resolveSQLServerConnectionString(cfg, 9*time.Second)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(got, "sqlserver://sa:secret@localhost:1433") {
			t.Fatalf("unexpected connection string: %q", got)
		}
		if !strings.Contains(got, "connection+timeout=9") {
			t.Fatalf("missing timeout in connection string: %q", got)
		}
	})
}

func TestNewSQLServerDataSourceWithRawConnectionStringRejectsInvalidDSN(t *testing.T) {
	_, err := NewSQLServerDataSource(context.Background(), &SQLServerConfig{
		ConnectionString: "://bad-dsn",
		Query:            "SELECT 1 FROM trusted_ips WHERE ip = @p1",
	})
	if err == nil {
		t.Fatal("expected error for invalid raw connection string")
	}
}

func TestBuildSQLServerConnectionStringWithTLS(t *testing.T) {
	config := &SQLServerConfig{
		Host:         "localhost",
		Port:         1433,
		DatabaseName: "security",
		TLS: &SQLServerTLSConfig{
			Encrypt:                "strict",
			TrustServerCertificate: true,
			CACert:                 "/etc/ca.pem",
			HostNameInCertificate:  "db.example.com",
			TLSMin:                 "1.2",
		},
	}

	connString := buildSQLServerConnectionString(config, "sa", "secret", 7*time.Second)

	expectedParts := []string{
		"encrypt=strict",
		"TrustServerCertificate=true",
		"certificate=%2Fetc%2Fca.pem",
		"hostNameInCertificate=db.example.com",
		"tlsmin=1.2",
	}
	for _, part := range expectedParts {
		if !strings.Contains(connString, part) {
			t.Fatalf("connection string %q must contain %q", connString, part)
		}
	}
}
