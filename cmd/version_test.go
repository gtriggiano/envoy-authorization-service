package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gtriggiano/envoy-authorization-service/pkg/version"
)

// runCLI executes the root command with args, capturing stdout and stderr.
func runCLI(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var out, errOut bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&errOut)
	t.Cleanup(func() {
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		rootCmd.SetArgs(nil)
		versionOutput = "text"
		cfgFile, validateCfgFile, validateOffline = "config.yaml", "config.yaml", false
		if f := rootCmd.Flags().Lookup("version"); f != nil {
			_ = f.Value.Set("false")
		}
	})
	rootCmd.SetArgs(args)
	err = Execute()
	return out.String(), errOut.String(), err
}

func TestVersionCommand(t *testing.T) {
	info := version.Get()

	t.Run("text", func(t *testing.T) {
		out, errOut, err := runCLI(t, "version")
		if err != nil || errOut != "" {
			t.Fatalf("unexpected err=%v stderr=%q", err, errOut)
		}
		if want := "envoy-authorization-service " + info.String() + "\n"; out != want {
			t.Fatalf("got %q, want %q", out, want)
		}
	})

	t.Run("short", func(t *testing.T) {
		out, _, err := runCLI(t, "version", "--output", "short")
		if err != nil || out != info.Version+"\n" {
			t.Fatalf("got %q err=%v", out, err)
		}
	})

	t.Run("json", func(t *testing.T) {
		out, _, err := runCLI(t, "version", "-o", "json")
		if err != nil {
			t.Fatal(err)
		}
		var got map[string]string
		if err := json.Unmarshal([]byte(out), &got); err != nil {
			t.Fatalf("invalid JSON %q: %v", out, err)
		}
		if got["version"] != info.Version || got["commit"] != info.Commit || got["goVersion"] != info.GoVersion || got["platform"] != info.Platform || got["buildDate"] != info.BuildDate {
			t.Fatalf("unexpected JSON %v", got)
		}
	})

	t.Run("unknown format", func(t *testing.T) {
		_, errOut, err := runCLI(t, "version", "-o", "yaml")
		if err == nil || !strings.Contains(errOut, `Error: unknown output format "yaml"`) {
			t.Fatalf("expected a printed error, got err=%v stderr=%q", err, errOut)
		}
	})

	t.Run("--version flag", func(t *testing.T) {
		out, _, err := runCLI(t, "--version")
		if err != nil || out != "envoy-authorization-service "+info.String()+"\n" {
			t.Fatalf("got %q err=%v", out, err)
		}
	})
}

func TestStartFailsWhenServerCannotBind(t *testing.T) {
	// Occupy a port so the gRPC listener cannot bind to it.
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	metricsAddr := free.Addr().String()
	free.Close()

	cfg := filepath.Join(t.TempDir(), "config.yaml")
	content := fmt.Sprintf("server:\n  address: %s\nmetrics:\n  address: %s\nlogging:\n  level: error\n", taken.Addr().String(), metricsAddr)
	if err := os.WriteFile(cfg, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, _, err := runCLI(t, "start", "--config", cfg)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("start must fail when the gRPC listener cannot bind")
		}
		var already reportedError
		if !errors.As(err, &already) {
			t.Fatalf("a logged server error must be marked as reported, got %T: %v", err, err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("start did not exit after the listener failed to bind")
	}
}

func TestExecuteReportsErrorsOnce(t *testing.T) {
	t.Run("start with a missing configuration prints the error, not the usage", func(t *testing.T) {
		_, errOut, err := runCLI(t, "start", "--config", "/nonexistent/config.yaml")
		if err == nil {
			t.Fatal("expected an error")
		}
		if !strings.Contains(errOut, "Error: could not read the configuration file") || !strings.Contains(errOut, "/nonexistent/config.yaml") {
			t.Fatalf("the error must be printed on stderr, got %q", errOut)
		}
		if strings.Contains(errOut, "Usage:") {
			t.Fatalf("usage must not be printed for runtime errors, got %q", errOut)
		}
	})

	t.Run("unknown flag prints the error and the usage", func(t *testing.T) {
		_, errOut, err := runCLI(t, "start", "--bogus")
		if err == nil {
			t.Fatal("expected an error")
		}
		if !strings.Contains(errOut, "Error: unknown flag: --bogus") || !strings.Contains(errOut, "Usage:") || !strings.Contains(errOut, "--config string") {
			t.Fatalf("expected error followed by usage, got %q", errOut)
		}
	})

	t.Run("unexpected argument is rejected", func(t *testing.T) {
		for _, sub := range []string{"start", "validate", "version", "validate-geojson", "synthesize-cidr-list", "synthesize-asn-list"} {
			_, errOut, err := runCLI(t, sub, "extra")
			if err == nil || !strings.Contains(errOut, `Error: unknown command "extra" for "envoy-authorization-service `+sub+`"`) {
				t.Fatalf("%s: got err=%v stderr=%q", sub, err, errOut)
			}
		}
	})

	t.Run("utility command errors are printed once without usage", func(t *testing.T) {
		_, errOut, err := runCLI(t, "validate-geojson", "--file", "/nonexistent.json")
		if err == nil || strings.Count(errOut, "Error:") != 1 || !strings.Contains(errOut, "could not stat file /nonexistent.json") || strings.Contains(errOut, "Usage:") {
			t.Fatalf("got err=%v stderr=%q", err, errOut)
		}
	})

	t.Run("utility command output goes through the command writer", func(t *testing.T) {
		list := filepath.Join(t.TempDir(), "cidrs.txt")
		if err := os.WriteFile(list, []byte("10.0.0.0/8\n10.1.0.0/16\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		out, errOut, err := runCLI(t, "synthesize-cidr-list", "--file", list)
		if err != nil || errOut != "" || strings.TrimSpace(out) != "10.0.0.0/8" {
			t.Fatalf("got out=%q stderr=%q err=%v", out, errOut, err)
		}
	})

	t.Run("validate failure is printed exactly once", func(t *testing.T) {
		_, errOut, err := runCLI(t, "validate", "--config", "/nonexistent/config.yaml")
		if err == nil {
			t.Fatal("expected an error")
		}
		if strings.Count(errOut, "could not read the configuration file") != 1 || !strings.HasPrefix(errOut, "✗ configuration is invalid: ") || strings.Contains(errOut, "Error:") {
			t.Fatalf("expected a single ✗ line, got %q", errOut)
		}
	})
}
