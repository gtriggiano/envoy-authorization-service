package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// loadRaw loads a document as written, without the server/metrics preamble loadYAML adds.
func loadRaw(t *testing.T, body string) (*Config, error) {
	t.Helper()
	tmpFile := createTempFile(t, body)
	defer os.Remove(tmpFile)
	return Load(tmpFile)
}

func TestLoadRejectsUnknownKeys(t *testing.T) {
	tests := map[string]struct{ yaml, want string }{
		"top level":       {"loggin:\n  level: debug\n", `line 1: unknown key "loggin"`},
		"nested":          {"server:\n  adress: \":9001\"\n", `unknown key "adress"`},
		"metrics":         {"metrics:\n  trackCountries: true\n", `unknown key "trackCountries"`},
		"controller":      {"matchControllers:\n  - name: a\n    type: ip-match\n    setting: {}\n", `unknown key "setting"`},
		"clientIp xff":    {"clientIp:\n  sources:\n    - xff:\n        trustedHop: 1\n", `unknown key "trustedHop"`},
		"wrong type":      {"authorizationPolicyBypass: maybe\n", "cannot unmarshal"},
		"bad duration":    {"shutdown:\n  timeout: 20 seconds\n", "invalid duration \"20 seconds\""},
		"bad log level":   {"logging:\n  level: verbose\n", "'logging.level' must be one of debug, info, warn, error"},
		"policy unknown":  {"authorizationPolicy: \"a && nope\"\nmatchControllers:\n  - name: a\n    type: ip-match\n", "'authorizationPolicy' is invalid"},
		"policy syntax":   {"authorizationPolicy: \"a &&\"\nmatchControllers:\n  - name: a\n    type: ip-match\n", "'authorizationPolicy' is invalid"},
		"policy disabled": {"authorizationPolicy: \"a\"\nmatchControllers:\n  - name: a\n    type: ip-match\n    enabled: false\n", "'authorizationPolicy' is invalid"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := loadRaw(t, tt.yaml)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got %v", tt.want, err)
			}
		})
	}

	t.Run("duplicate keys are rejected", func(t *testing.T) {
		_, err := loadRaw(t, "server:\n  address: a\nserver:\n  address: b\n")
		if err == nil || !strings.Contains(err.Error(), "already defined") {
			t.Fatalf("expected duplicate key error, got %v", err)
		}
	})
}

func TestLoadAcceptsEmptyDocument(t *testing.T) {
	cfg, err := loadYAML(t, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.Address != ":9001" {
		t.Fatalf("defaults not applied: %+v", cfg.Server)
	}
	// A file with only comments is also valid.
	tmp := createTempFile(t, "# nothing here\n")
	defer os.Remove(tmp)
	if _, err := Load(tmp); err != nil {
		t.Fatalf("unexpected error for comment-only file: %v", err)
	}
}

func TestLoadSetsBaseDirAndResolvesPaths(t *testing.T) {
	dir := t.TempDir()
	certDir := filepath.Join(dir, "certs")
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"cert.pem", "key.pem"} {
		if err := os.WriteFile(filepath.Join(certDir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "config.yaml")
	body := "server:\n  tls:\n    certFile: certs/cert.pem\n    keyFile: certs/key.pem\nmatchControllers:\n  - name: a\n    type: ip-match\n    settings:\n      cidrList: lists/a.txt\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	// Load from a different working directory to prove paths do not depend on it.
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.BaseDir != dir {
		t.Fatalf("expected base dir %s, got %s", dir, cfg.BaseDir)
	}
	if cfg.Server.TLS.CertFile != filepath.Join(certDir, "cert.pem") {
		t.Fatalf("TLS path not resolved against the config directory: %s", cfg.Server.TLS.CertFile)
	}
	if cfg.MatchControllers[0].BaseDir != dir {
		t.Fatalf("controller base dir not set: %q", cfg.MatchControllers[0].BaseDir)
	}
	resolved, err := cfg.MatchControllers[0].ResolvePath("lists/a.txt")
	if err != nil || resolved != filepath.Join(dir, "lists/a.txt") {
		t.Fatalf("unexpected controller path resolution: %s (%v)", resolved, err)
	}
	abs, _ := cfg.ResolvePath("/abs/x")
	if abs != "/abs/x" {
		t.Fatalf("absolute path must be kept: %s", abs)
	}
	if _, err := cfg.ResolvePath(""); err == nil {
		t.Fatal("empty path must be rejected")
	}

	cwd, _ := os.Getwd()
	viaCwd, _ := ControllerConfig{}.ResolvePath("x.txt")
	if viaCwd != filepath.Join(cwd, "x.txt") {
		t.Fatalf("without base dir paths resolve against the working directory, got %s", viaCwd)
	}
}

func TestLoadExpandsEnvironment(t *testing.T) {
	t.Setenv("EAS_TEST_ADDR", ":7001")
	cfg, err := loadRaw(t, "server:\n  address: ${EAS_TEST_ADDR}\nlogging:\n  level: ${EAS_TEST_LEVEL:-warn}\n")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.Address != ":7001" || cfg.Logging.Level != "warn" {
		t.Fatalf("unexpected expansion: %+v %+v", cfg.Server, cfg.Logging)
	}

	_, err = loadRaw(t, "server:\n  address: ${EAS_TEST_UNSET_ADDR}\n")
	if err == nil || !strings.Contains(err.Error(), "EAS_TEST_UNSET_ADDR") {
		t.Fatalf("expected missing variable error, got %v", err)
	}
}

func TestExpandEnv(t *testing.T) {
	env := map[string]string{"HOST": "db.local", "EMPTY": ""}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }

	tests := map[string]struct{ in, want string }{
		"plain":              {"host: ${HOST}", "host: db.local"},
		"default unused":     {"${HOST:-x}", "db.local"},
		"default on unset":   {"${PORT:-5432}", "5432"},
		"default on empty":   {"${EMPTY:-fallback}", "fallback"},
		"empty default":      {"${PORT:-}", ""},
		"escape":             {"$${HOST}", "${HOST}"},
		"sql placeholder":    {"WHERE ip = $1", "WHERE ip = $1"},
		"bare dollar name":   {"$HOST", "$HOST"},
		"multiple":           {"${HOST}:${PORT:-1}", "db.local:1"},
		"default with colon": {"${URL:-http://x:1}", "http://x:1"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			out, err := ExpandEnv([]byte(tt.in), lookup)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(out) != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, out)
			}
		})
	}

	_, err := ExpandEnv([]byte("${B} ${A} ${B}"), lookup)
	if err == nil || !strings.Contains(err.Error(), "not set: A, B") {
		t.Fatalf("expected sorted list of missing variables, got %v", err)
	}
}

func TestMetricsTrackFlags(t *testing.T) {
	cfg, err := loadRaw(t, "metrics:\n  trackCountry: true\n  trackGeofence: true\n")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.Metrics.TrackCountryEnabled() || !cfg.Metrics.TrackGeofenceEnabled() {
		t.Fatalf("flags not honoured: %+v", cfg.Metrics)
	}
	if (MetricsConfig{}).TrackCountryEnabled() || (MetricsConfig{}).TrackGeofenceEnabled() {
		t.Fatal("unexpected zero-value defaults")
	}
}

func TestFormatYAMLError(t *testing.T) {
	if FormatYAMLError(nil, true) != nil {
		t.Fatal("nil must stay nil")
	}
	plain := os.ErrNotExist
	if FormatYAMLError(plain, true) != plain {
		t.Fatal("non-yaml errors must be returned unchanged")
	}
	_, err := Parse([]byte("server:\n  adress: x\n  addr: y\n"))
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, `line 2: unknown key "adress"`) || !strings.Contains(msg, `line 3: unknown key "addr"`) {
		t.Fatalf("unexpected message: %s", msg)
	}
	if strings.Contains(msg, "not found in type") {
		t.Fatalf("Go type names must not leak: %s", msg)
	}
}

func TestCredentialSource(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "secret")
	if err := os.WriteFile(file, []byte("value\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if (CredentialSource{}).IsSet() || !(CredentialSource{Value: "x"}).IsSet() || !(CredentialSource{File: "f"}).IsSet() {
		t.Fatal("IsSet mismatch")
	}
	if err := (CredentialSource{Value: "a", File: "b"}).Validate("database.postgres.username"); err == nil || !strings.Contains(err.Error(), "database.postgres.username and database.postgres.usernameFile are mutually exclusive") {
		t.Fatalf("unexpected validate error: %v", err)
	}
	if err := (CredentialSource{Value: "a"}).Validate("n"); err != nil {
		t.Fatalf("single source must validate: %v", err)
	}

	if err := (CredentialSource{File: filepath.Join(dir, "nope")}).Check("n"); err == nil || !isUnavailable(err) || !strings.Contains(err.Error(), "nFile") {
		t.Fatalf("unexpected check error: %v", err)
	}
	if err := (CredentialSource{Value: "anything"}).Check("n"); err != nil {
		t.Fatalf("inline values need no check: %v", err)
	}
	if err := (CredentialSource{File: file}).Check("n"); err != nil {
		t.Fatalf("existing file passes check: %v", err)
	}

	if v, err := (CredentialSource{File: file}).Resolve("n"); err != nil || v != "value" {
		t.Fatalf("file resolve: %q %v", v, err)
	}
	if v, err := (CredentialSource{Value: "inline"}).Resolve("n"); err != nil || v != "inline" {
		t.Fatalf("inline resolve: %q %v", v, err)
	}
	if _, err := (CredentialSource{File: filepath.Join(dir, "nope")}).Resolve("n"); err == nil {
		t.Fatal("missing file must fail resolve")
	}
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (CredentialSource{File: empty}).Resolve("n"); err == nil || !strings.Contains(err.Error(), "is empty") {
		t.Fatalf("empty file must fail resolve: %v", err)
	}
	if _, err := (CredentialSource{}).Resolve("n"); err == nil {
		t.Fatal("unset source must fail resolve")
	}
}

func isUnavailable(err error) bool {
	for e := err; e != nil; {
		if e == ErrCredentialUnavailable {
			return true
		}
		if u, ok := e.(interface{ Is(error) bool }); ok && u.Is(ErrCredentialUnavailable) {
			return true
		}
		if w, ok := e.(interface{ Unwrap() error }); ok {
			e = w.Unwrap()
			continue
		}
		return false
	}
	return false
}
