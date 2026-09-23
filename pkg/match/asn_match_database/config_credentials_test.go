package asn_match_database

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gtriggiano/envoy-authorization-service/pkg/controller"
)

func postgresConfigWithCredentials(user, userFile, pass, passFile string) *ASNMatchDatabaseConfig {
	return &ASNMatchDatabaseConfig{
		Database: DatabaseConfig{
			Type: "postgres",
			Postgres: &PostgresConfig{
				Query:        "SELECT 1 FROM t WHERE ip = $1",
				Host:         "localhost",
				Port:         5432,
				DatabaseName: "db",
				Username:     user,
				UsernameFile: userFile,
				Password:     pass,
				PasswordFile: passFile,
			},
		},
	}
}

func writeSecret(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func TestCredentialFiles(t *testing.T) {
	dir := t.TempDir()
	userFile := writeSecret(t, dir, "user", "dbuser\n")
	passFile := writeSecret(t, dir, "pass", "s3cret")

	t.Run("file based credentials pass validation", func(t *testing.T) {
		cfg := postgresConfigWithCredentials("", userFile, "", passFile)
		if err := cfg.Validate(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		user, err := cfg.Database.Postgres.UsernameSource().Resolve("database.postgres.username")
		if err != nil || user != "dbuser" {
			t.Fatalf("expected trimmed user name, got %q (%v)", user, err)
		}
	})

	t.Run("inline value and file for the same credential are mutually exclusive", func(t *testing.T) {
		cfg := postgresConfigWithCredentials("u", userFile, "", passFile)
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
			t.Fatalf("expected mutual exclusion error, got %v", err)
		}
	})

	t.Run("missing credential source is required", func(t *testing.T) {
		cfg := postgresConfigWithCredentials("", "", "", passFile)
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "database.postgres.username or database.postgres.usernameFile is required") {
			t.Fatalf("expected required credential error, got %v", err)
		}
	})

	t.Run("missing credential file fails", func(t *testing.T) {
		cfg := postgresConfigWithCredentials("", filepath.Join(dir, "nope"), "", passFile)
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "usernameFile") {
			t.Fatalf("expected missing file error, got %v", err)
		}
	})

	t.Run("offline validation turns missing credential files into warnings", func(t *testing.T) {
		cfg := postgresConfigWithCredentials("", filepath.Join(dir, "nope-user"), "", filepath.Join(dir, "nope"))
		var warnings []string
		opts := controller.ValidationOptions{Offline: true, Warn: func(f string, a ...any) { warnings = append(warnings, f) }}
		if err := cfg.ValidateWith(opts); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(warnings) != 2 {
			t.Fatalf("expected 2 warnings, got %v", warnings)
		}
	})

	t.Run("inline credentials resolve verbatim", func(t *testing.T) {
		cfg := postgresConfigWithCredentials("${NOT_EXPANDED_HERE}", "", "p", "")
		if err := cfg.Validate(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Expansion happens when the file is loaded; the controller receives the final value.
		if v, _ := cfg.Database.Postgres.UsernameSource().Resolve("n"); v != "${NOT_EXPANDED_HERE}" {
			t.Fatalf("unexpected value %q", v)
		}
	})

	t.Run("redis credentials are optional but checked when set", func(t *testing.T) {
		cfg := &ASNMatchDatabaseConfig{Database: DatabaseConfig{Type: "redis", Redis: &RedisConfig{
			KeyPrefix: "k:", Host: "localhost", Port: 6379, PasswordFile: passFile,
		}}}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		cfg.Database.Redis.PasswordFile = filepath.Join(dir, "missing")
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error for missing redis password file")
		}
	})
}

func TestResolvePathsUsesBaseDirectory(t *testing.T) {
	cfg := &ASNMatchDatabaseConfig{Database: DatabaseConfig{
		Type: "postgres",
		Postgres: &PostgresConfig{
			UsernameFile: "secrets/user",
			PasswordFile: "/abs/pass",
			TLS:          &PostgresTLSConfig{CACert: "certs/ca.pem"},
		},
		Redis: &RedisConfig{PasswordFile: "redis/pass", TLS: &RedisTLSConfig{ClientKey: "redis/key.pem"}},
	}}
	resolve := func(p string) (string, error) {
		if filepath.IsAbs(p) {
			return p, nil
		}
		return filepath.Join("/etc/authz", p), nil
	}
	if err := cfg.ResolvePaths(resolve); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pg := cfg.Database.Postgres
	if pg.UsernameFile != "/etc/authz/secrets/user" || pg.PasswordFile != "/abs/pass" || pg.TLS.CACert != "/etc/authz/certs/ca.pem" {
		t.Fatalf("postgres paths not resolved: %+v %+v", pg, pg.TLS)
	}
	if cfg.Database.Redis.PasswordFile != "/etc/authz/redis/pass" || cfg.Database.Redis.TLS.ClientKey != "/etc/authz/redis/key.pem" {
		t.Fatalf("redis paths not resolved: %+v", cfg.Database.Redis)
	}
}

func TestOfflineValidationWarnsOnMissingCertificates(t *testing.T) {
	cfg := postgresConfigWithCredentials("u", "", "p", "")
	cfg.Database.Postgres.TLS = &PostgresTLSConfig{Mode: "verify-full", CACert: "/nonexistent/ca.pem"}

	if err := cfg.Validate(); err == nil {
		t.Fatal("expected missing CA certificate to fail online validation")
	}

	var warnings []string
	opts := controller.ValidationOptions{Offline: true, Warn: func(f string, a ...any) { warnings = append(warnings, f) }}
	if err := cfg.ValidateWith(opts); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(warnings) != 1 {
		t.Fatalf("expected one warning, got %v", warnings)
	}
}
