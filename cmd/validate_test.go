package cmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gtriggiano/envoy-authorization-service/pkg/controller"
)

func repoPath(t *testing.T, rel string) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", rel))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func requireMaxMind(t *testing.T) {
	t.Helper()
	for _, f := range []string{"config/GeoLite2-ASN.mmdb", "config/GeoLite2-City.mmdb"} {
		if _, err := os.Stat(repoPath(t, f)); err != nil {
			t.Skipf("MaxMind database %s not available (run scripts/fetch-maxmind.sh)", f)
		}
	}
}

func TestValidateShippedConfigurations(t *testing.T) {
	t.Run("ip-match sample validates online", func(t *testing.T) {
		requireMaxMind(t)
		res, err := validateConfiguration(context.Background(), repoPath(t, "config/config.ip-match.yaml"), controller.BuildModeValidate)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(res.matchControllers) != 2 || len(res.analysisControllers) != 2 || res.skipped != 0 || len(res.warnings) != 0 {
			t.Fatalf("unexpected result %+v", res)
		}
	})

	t.Run("database samples validate offline", func(t *testing.T) {
		requireMaxMind(t)
		for _, name := range []string{"config/config.redis.yaml", "config/config.postgres.yaml"} {
			res, err := validateConfiguration(context.Background(), repoPath(t, name), controller.BuildModeValidateOffline)
			if err != nil {
				t.Fatalf("%s: unexpected error: %v", name, err)
			}
			if res.skipped != 1 || len(res.warnings) == 0 {
				t.Fatalf("%s: expected the database controller to be skipped with warnings, got %+v", name, res)
			}
		}
	})

	t.Run("kubernetes examples validate offline with warnings", func(t *testing.T) {
		matches, err := filepath.Glob(repoPath(t, "kubernetes/examples/*/config.yaml"))
		if err != nil || len(matches) == 0 {
			t.Fatalf("no kubernetes examples found: %v", err)
		}
		for _, path := range matches {
			res, err := validateConfiguration(context.Background(), path, controller.BuildModeValidateOffline)
			if err != nil {
				t.Fatalf("%s: unexpected error: %v", path, err)
			}
			if len(res.warnings) == 0 || res.skipped == 0 {
				t.Fatalf("%s: expected mounted files to be reported as warnings, got %+v", path, res)
			}
			if _, err := validateConfiguration(context.Background(), path, controller.BuildModeValidate); err == nil {
				t.Fatalf("%s: online validation must fail when mounted files are missing", path)
			}
		}
	})
}

func TestValidateReportsErrors(t *testing.T) {
	write := func(body string) string {
		p := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	tests := map[string]struct{ body, want string }{
		"unknown top-level key": {"loggin:\n  level: info\n", `unknown key "loggin"`},
		"unknown setting":       {"matchControllers:\n  - name: a\n    type: ip-match\n    settings:\n      cidrLst: x\n", `unknown key "cidrLst"`},
		"missing list file":     {"matchControllers:\n  - name: a\n    type: ip-match\n    settings:\n      cidrList: nope.txt\n", "could not read cidrList file"},
		"unknown controller":    {"matchControllers:\n  - name: a\n    type: ip-matcher\n", "unknown type 'ip-matcher'"},
		"bad policy":            {"authorizationPolicy: \"x\"\n", "'authorizationPolicy' is invalid"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := validateConfiguration(context.Background(), write(tt.body), controller.BuildModeValidate)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got %v", tt.want, err)
			}
		})
	}

	t.Run("offline turns a missing list file into a warning", func(t *testing.T) {
		res, err := validateConfiguration(context.Background(), write("matchControllers:\n  - name: a\n    type: ip-match\n    settings:\n      cidrList: nope.txt\n"), controller.BuildModeValidateOffline)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.skipped != 1 || len(res.warnings) != 1 || !strings.Contains(res.warnings[0], "nope.txt not found") {
			t.Fatalf("unexpected result %+v", res)
		}
	})
}

func TestValidateCommandOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	body := "authorizationPolicyBypass: true\nmatchControllers:\n  - name: a\n    type: ip-match\n    settings:\n      cidrList: missing.txt\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&errOut)
	t.Cleanup(func() { rootCmd.SetOut(nil); rootCmd.SetErr(nil) })

	rootCmd.SetArgs([]string{"validate", "--offline", "--config", path})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v (%s)", err, errOut.String())
	}
	text := out.String()
	for _, want := range []string{"✓ configuration is valid", "mode: offline", "(empty: every request is allowed)", "bypass: enabled", "warnings:", "missing.txt not found"} {
		if !strings.Contains(text, want) {
			t.Fatalf("output missing %q:\n%s", want, text)
		}
	}

	out.Reset()
	errOut.Reset()
	rootCmd.SetArgs([]string{"validate", "--offline=false", "--config", path})
	if err := rootCmd.Execute(); err == nil {
		t.Fatal("online validation of a missing file must fail")
	}
	if !strings.Contains(errOut.String(), "✗ configuration is invalid") {
		t.Fatalf("expected failure banner on stderr, got %q", errOut.String())
	}
}
