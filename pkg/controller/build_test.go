package controller

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/gtriggiano/envoy-authorization-service/pkg/config"
)

func TestBuildModeContext(t *testing.T) {
	ctx := context.Background()
	if BuildModeFrom(ctx) != BuildModeServe {
		t.Fatal("default mode must be serve")
	}
	offline := WithBuildMode(ctx, BuildModeValidateOffline)
	if !BuildModeFrom(offline).Offline() || !BuildModeFrom(offline).Validating() {
		t.Fatal("offline mode not carried")
	}
	if BuildModeValidate.Offline() || !BuildModeValidate.Validating() || BuildModeServe.Validating() {
		t.Fatal("mode predicates mismatch")
	}
}

func TestDiagnostics(t *testing.T) {
	Warn(context.Background(), "ignored %d", 1) // no diagnostics: must not panic

	d := &Diagnostics{}
	ctx := WithDiagnostics(context.Background(), d)
	Warn(ctx, "first %s", "a")
	Warn(ctx, "second")
	got := d.Warnings()
	if len(got) != 2 || got[0] != "first a" || got[1] != "second" {
		t.Fatalf("unexpected warnings %v", got)
	}
	got[0] = "mutated"
	if d.Warnings()[0] != "first a" {
		t.Fatal("Warnings must return a copy")
	}
	var nilDiag *Diagnostics
	if nilDiag.Warnings() != nil {
		t.Fatal("nil diagnostics must have no warnings")
	}

	opts := ValidationOptionsFrom(ctx)
	opts.Warnf("third")
	if len(d.Warnings()) != 3 {
		t.Fatal("ValidationOptions must record into the same diagnostics")
	}
	(ValidationOptions{}).Warnf("no-op without a Warn function")
}

func TestReadFileAndCheckFileOfflineSemantics(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "list.txt")
	if err := os.WriteFile(existing, []byte("1.1.1.1"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing.txt")

	serve := context.Background()
	d := &Diagnostics{}
	offline := WithDiagnostics(WithBuildMode(serve, BuildModeValidateOffline), d)

	if content, err := ReadFile(serve, existing, "cidrList"); err != nil || string(content) != "1.1.1.1" {
		t.Fatalf("existing file must be read: %q %v", content, err)
	}
	if _, err := ReadFile(serve, missing, "cidrList"); err == nil || errors.Is(err, ErrSkipped) || !strings.Contains(err.Error(), "could not read cidrList file") {
		t.Fatalf("missing file must be a hard error when serving: %v", err)
	}
	if err := CheckFile(serve, missing, "databasePath"); err == nil || errors.Is(err, ErrSkipped) {
		t.Fatalf("CheckFile must fail when serving: %v", err)
	}

	if _, err := ReadFile(offline, missing, "cidrList"); !errors.Is(err, ErrSkipped) {
		t.Fatalf("missing file must be skipped offline: %v", err)
	}
	if err := CheckFile(offline, missing, "databasePath"); !errors.Is(err, ErrSkipped) {
		t.Fatalf("CheckFile must skip offline: %v", err)
	}
	if err := CheckFile(offline, existing, "databasePath"); err != nil {
		t.Fatalf("existing file passes offline: %v", err)
	}
	warnings := d.Warnings()
	if len(warnings) != 2 || !strings.Contains(warnings[0], "cidrList: file "+missing+" not found") {
		t.Fatalf("unexpected warnings %v", warnings)
	}

	// A directory is not a missing file: still a hard error offline.
	if _, err := ReadFile(offline, dir, "cidrList"); err == nil || errors.Is(err, ErrSkipped) {
		t.Fatalf("unreadable path must remain an error offline: %v", err)
	}
}

func TestBuildControllersSkipOnlyInOfflineMode(t *testing.T) {
	oldReg := matchControllersRegistry
	t.Cleanup(func() { matchControllersRegistry = oldReg })
	matchControllersRegistry = newRegistry[MatchControllerFactory]()

	RegisterMatchControllerFactory("skipping", func(ctx context.Context, _ *zap.Logger, cfg config.ControllerConfig) (MatchController, error) {
		return nil, SkipOffline(ctx, "controller '%s' skipped", cfg.Name)
	})
	RegisterMatchControllerFactory("ok", func(_ context.Context, _ *zap.Logger, cfg config.ControllerConfig) (MatchController, error) {
		return &mockMatchController{name: cfg.Name, kind: "ok"}, nil
	})
	configs := []config.ControllerConfig{{Name: "a", Type: "skipping"}, {Name: "b", Type: "ok"}}
	logger := zap.NewNop()

	d := &Diagnostics{}
	offline := WithDiagnostics(WithBuildMode(context.Background(), BuildModeValidateOffline), d)
	built, err := BuildMatchControllers(offline, logger, configs)
	if err != nil {
		t.Fatalf("offline build must tolerate skipped controllers: %v", err)
	}
	if len(built) != 1 || built[0].Name() != "b" {
		t.Fatalf("expected only 'b' to be built, got %d", len(built))
	}
	if w := d.Warnings(); len(w) != 1 || w[0] != "controller 'a' skipped" {
		t.Fatalf("unexpected warnings %v", w)
	}

	if _, err := BuildMatchControllers(context.Background(), logger, configs); err == nil || !errors.Is(err, ErrSkipped) {
		t.Fatalf("ErrSkipped must be fatal outside offline validation: %v", err)
	}
	if _, err := BuildMatchControllers(WithBuildMode(context.Background(), BuildModeValidate), logger, configs); err == nil {
		t.Fatal("ErrSkipped must be fatal in online validation")
	}
}

func TestDecodeControllerSettingsIsStrict(t *testing.T) {
	type settings struct {
		CIDRList string           `yaml:"cidrList"`
		Timeout  *config.Duration `yaml:"timeout"`
	}

	var s settings
	err := DecodeControllerSettings(map[string]any{"cidrLst": "x"}, &s)
	if err == nil || !strings.Contains(err.Error(), `invalid settings: unknown key "cidrLst"`) {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(err.Error(), "line ") {
		t.Fatalf("line numbers of the re-encoded document must not leak: %v", err)
	}

	err = DecodeControllerSettings(map[string]any{"timeout": "soon"}, &s)
	if err == nil || !strings.Contains(err.Error(), "invalid duration") {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := DecodeControllerSettings(map[string]any{"cidrList": "a", "timeout": "1s"}, &s); err != nil || s.CIDRList != "a" || s.Timeout.Std().Seconds() != 1 {
		t.Fatalf("valid settings failed: %+v %v", s, err)
	}
}
