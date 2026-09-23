package asn_match_database

import (
	"crypto/tls"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func parseConn(t *testing.T, username, password string, cfg *PostgresConfig) *pgxpool.Config {
	t.Helper()
	connString := buildPostgresConnString(username, password, cfg)
	poolConfig, err := pgxpool.ParseConfig(connString)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	return poolConfig
}

func TestBuildPostgresConnString_Credentials(t *testing.T) {
	base := &PostgresConfig{Host: "db.example.com", Port: 5432, DatabaseName: "security"}

	cases := []struct {
		name, username, password string
	}{
		{"plain", "app", "secret"},
		{"url reserved characters", "us er@corp", "p@ss/w:rd#%?&=+;"},
		{"unicode", "ユーザー", "pässwörd"},
		{"empty password", "app", ""},
		{"whitespace and quotes", "a b", `it's "quoted" \ and spaced`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := parseConn(t, tc.username, tc.password, base)
			if cfg.ConnConfig.User != tc.username {
				t.Errorf("user: got %q, want %q", cfg.ConnConfig.User, tc.username)
			}
			if cfg.ConnConfig.Password != tc.password {
				t.Errorf("password: got %q, want %q", cfg.ConnConfig.Password, tc.password)
			}
			if cfg.ConnConfig.Host != "db.example.com" || cfg.ConnConfig.Port != 5432 || cfg.ConnConfig.Database != "security" {
				t.Errorf("endpoint: got %s:%d/%s", cfg.ConnConfig.Host, cfg.ConnConfig.Port, cfg.ConnConfig.Database)
			}
		})
	}
}

func TestBuildPostgresConnString_DatabaseNameAndIPv6Host(t *testing.T) {
	cfg := parseConn(t, "app", "secret", &PostgresConfig{Host: "::1", Port: 5433, DatabaseName: "my db/prod"})
	if cfg.ConnConfig.Host != "::1" || cfg.ConnConfig.Port != 5433 {
		t.Errorf("endpoint: got %s:%d", cfg.ConnConfig.Host, cfg.ConnConfig.Port)
	}
	if cfg.ConnConfig.Database != "my db/prod" {
		t.Errorf("database: got %q", cfg.ConnConfig.Database)
	}
}

func TestBuildPostgresConnString_NoTLSBlockUsesLibpqDefault(t *testing.T) {
	// The configuration, not the environment, decides the TLS mode.
	t.Setenv("PGSSLMODE", "disable")
	cfg := parseConn(t, "app", "secret", &PostgresConfig{Host: "db", Port: 5432, DatabaseName: "d"})
	// prefer: TLS attempted first, plaintext fallback
	if cfg.ConnConfig.TLSConfig == nil || !cfg.ConnConfig.TLSConfig.InsecureSkipVerify {
		t.Fatalf("expected an unverified TLS attempt for sslmode=prefer, got %+v", cfg.ConnConfig.TLSConfig)
	}
	if len(cfg.ConnConfig.Fallbacks) != 1 || cfg.ConnConfig.Fallbacks[0].TLSConfig != nil {
		t.Fatalf("expected one plaintext fallback, got %+v", cfg.ConnConfig.Fallbacks)
	}
}

func TestBuildPostgresConnString_TLSModes(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t, dir, "ca")
	clientCert, clientKey := ca.issue(t, dir, "client", nil, nil, true)
	base := PostgresConfig{Host: "db.example.com", Port: 5432, DatabaseName: "security"}

	t.Run("sslmode never reaches the server as a runtime parameter", func(t *testing.T) {
		for _, mode := range postgresSSLModes {
			cfg := base
			cfg.TLS = &PostgresTLSConfig{Mode: mode, CACert: ca.CertPath}
			pc := parseConn(t, "app", "secret", &cfg)
			for k := range pc.ConnConfig.RuntimeParams {
				if strings.HasPrefix(k, "ssl") {
					t.Errorf("mode %s: runtime parameter %q would be rejected by PostgreSQL", mode, k)
				}
			}
		}
	})

	t.Run("disable", func(t *testing.T) {
		cfg := base
		cfg.TLS = &PostgresTLSConfig{Mode: "disable"}
		pc := parseConn(t, "app", "secret", &cfg)
		if pc.ConnConfig.TLSConfig != nil || len(pc.ConnConfig.Fallbacks) != 0 {
			t.Fatalf("expected plaintext only, got tls=%v fallbacks=%d", pc.ConnConfig.TLSConfig, len(pc.ConnConfig.Fallbacks))
		}
	})

	t.Run("empty mode defaults to prefer", func(t *testing.T) {
		cfg := base
		cfg.TLS = &PostgresTLSConfig{}
		pc := parseConn(t, "app", "secret", &cfg)
		if pc.ConnConfig.TLSConfig == nil || !pc.ConnConfig.TLSConfig.InsecureSkipVerify || len(pc.ConnConfig.Fallbacks) != 1 {
			t.Fatalf("expected prefer semantics, got tls=%+v fallbacks=%d", pc.ConnConfig.TLSConfig, len(pc.ConnConfig.Fallbacks))
		}
	})

	t.Run("require without CA does not verify", func(t *testing.T) {
		cfg := base
		cfg.TLS = &PostgresTLSConfig{Mode: "require"}
		pc := parseConn(t, "app", "secret", &cfg)
		tc := pc.ConnConfig.TLSConfig
		if tc == nil || !tc.InsecureSkipVerify || tc.VerifyPeerCertificate != nil || len(pc.ConnConfig.Fallbacks) != 0 {
			t.Fatalf("expected unverified TLS with no fallback, got %+v", tc)
		}
	})

	t.Run("require with CA verifies the chain", func(t *testing.T) {
		cfg := base
		cfg.TLS = &PostgresTLSConfig{Mode: "require", CACert: ca.CertPath}
		pc := parseConn(t, "app", "secret", &cfg)
		tc := pc.ConnConfig.TLSConfig
		if tc == nil || tc.VerifyPeerCertificate == nil || tc.RootCAs == nil {
			t.Fatalf("expected verify-ca semantics, got %+v", tc)
		}
	})

	t.Run("verify-ca", func(t *testing.T) {
		cfg := base
		cfg.TLS = &PostgresTLSConfig{Mode: "verify-ca", CACert: ca.CertPath}
		pc := parseConn(t, "app", "secret", &cfg)
		tc := pc.ConnConfig.TLSConfig
		// pgx keeps ServerName for SNI but skips the built-in host name check
		// (InsecureSkipVerify) and verifies the chain in VerifyPeerCertificate.
		if tc == nil || !tc.InsecureSkipVerify || tc.VerifyPeerCertificate == nil || tc.RootCAs == nil {
			t.Fatalf("expected chain verification without host name check, got %+v", tc)
		}
	})

	t.Run("verify-full checks the host name", func(t *testing.T) {
		cfg := base
		cfg.TLS = &PostgresTLSConfig{Mode: "verify-full", CACert: ca.CertPath, ClientCert: clientCert, ClientKey: clientKey}
		pc := parseConn(t, "app", "secret", &cfg)
		tc := pc.ConnConfig.TLSConfig
		if tc == nil || tc.InsecureSkipVerify || tc.ServerName != "db.example.com" || tc.RootCAs == nil {
			t.Fatalf("expected full verification against db.example.com, got %+v", tc)
		}
		if len(tc.Certificates) != 1 {
			t.Fatalf("expected the client certificate to be loaded, got %d", len(tc.Certificates))
		}
		if len(pc.ConnConfig.Fallbacks) != 0 {
			t.Fatalf("verify-full must not fall back to plaintext, got %d fallbacks", len(pc.ConnConfig.Fallbacks))
		}
	})

	t.Run("unreadable CA fails at parse time", func(t *testing.T) {
		cfg := base
		cfg.TLS = &PostgresTLSConfig{Mode: "verify-full", CACert: dir + "/missing.pem"}
		if _, err := pgxpool.ParseConfig(buildPostgresConnString("app", "secret", &cfg)); err == nil {
			t.Fatal("expected an error for a missing CA file")
		}
	})
}

func TestPostgresTLSConfig_VerifiesServer(t *testing.T) {
	cases := []struct {
		cfg  *PostgresTLSConfig
		want bool
	}{
		{nil, false},
		{&PostgresTLSConfig{}, false},
		{&PostgresTLSConfig{Mode: "disable"}, false},
		{&PostgresTLSConfig{Mode: "allow", CACert: "ca.pem"}, false},
		{&PostgresTLSConfig{Mode: "prefer", CACert: "ca.pem"}, false},
		{&PostgresTLSConfig{Mode: "require"}, false},
		{&PostgresTLSConfig{Mode: "require", CACert: "ca.pem"}, true},
		{&PostgresTLSConfig{Mode: "verify-ca"}, true},
		{&PostgresTLSConfig{Mode: "verify-full"}, true},
	}
	for _, tc := range cases {
		if got := tc.cfg.VerifiesServer(); got != tc.want {
			t.Errorf("%+v: VerifiesServer() = %v, want %v", tc.cfg, got, tc.want)
		}
	}
	if (*PostgresTLSConfig)(nil).EffectiveMode() != "prefer" {
		t.Error("nil TLS config should report the libpq default mode")
	}
}

func TestBuildRedisTLSConfig_MinimumVersion(t *testing.T) {
	cfg, err := buildRedisTLSConfig(&RedisTLSConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %#x, want TLS 1.2", cfg.MinVersion)
	}
	if cfg.InsecureSkipVerify {
		t.Error("verification must be on by default")
	}
}
