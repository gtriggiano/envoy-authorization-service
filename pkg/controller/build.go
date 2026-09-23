package controller

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
)

// BuildMode tells controller factories why they are being invoked.
type BuildMode int

const (
	// BuildModeServe is the default: controllers are built to serve traffic and must be
	// fully functional (files loaded, databases connected).
	BuildModeServe BuildMode = iota
	// BuildModeValidate builds controllers exactly as BuildModeServe does, but the caller
	// only inspects the outcome and tears everything down afterwards.
	BuildModeValidate
	// BuildModeValidateOffline validates configuration without the deployment environment:
	// no network connections are made, and missing credentials or referenced files are
	// reported as warnings instead of errors. Factories return ErrSkipped for the parts they
	// could not check.
	BuildModeValidateOffline
)

// Offline reports whether external dependencies must not be touched.
func (m BuildMode) Offline() bool { return m == BuildModeValidateOffline }

// Validating reports whether controllers are being built for validation only.
func (m BuildMode) Validating() bool {
	return m == BuildModeValidate || m == BuildModeValidateOffline
}

type buildModeKey struct{}

// WithBuildMode returns a context carrying the build mode consulted by factories.
func WithBuildMode(ctx context.Context, mode BuildMode) context.Context {
	return context.WithValue(ctx, buildModeKey{}, mode)
}

// BuildModeFrom returns the build mode carried by ctx (BuildModeServe when absent).
func BuildModeFrom(ctx context.Context) BuildMode {
	if mode, ok := ctx.Value(buildModeKey{}).(BuildMode); ok {
		return mode
	}
	return BuildModeServe
}

// ErrSkipped is returned by a factory in offline validation when a controller could not
// be fully built because it depends on the deployment environment (a database, a
// credential, a mounted file). Build functions turn it into a warning.
var ErrSkipped = errors.New("skipped in offline validation")

// Diagnostics collects non-fatal findings emitted while controllers are built.
type Diagnostics struct {
	mu       sync.Mutex
	warnings []string
}

type diagnosticsKey struct{}

// WithDiagnostics returns a context that records warnings into d.
func WithDiagnostics(ctx context.Context, d *Diagnostics) context.Context {
	return context.WithValue(ctx, diagnosticsKey{}, d)
}

// Warn records a warning on the Diagnostics carried by ctx; it is a no-op otherwise.
func Warn(ctx context.Context, format string, args ...any) {
	d, ok := ctx.Value(diagnosticsKey{}).(*Diagnostics)
	if !ok || d == nil {
		return
	}
	d.mu.Lock()
	d.warnings = append(d.warnings, fmt.Sprintf(format, args...))
	d.mu.Unlock()
}

// Warnings returns the recorded warnings in emission order.
func (d *Diagnostics) Warnings() []string {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]string, len(d.warnings))
	copy(out, d.warnings)
	return out
}

// ReadFile reads a data file referenced by a controller setting. description names the
// setting in messages (e.g. "cidrList"). In offline validation a missing file is recorded
// as a warning and ErrSkipped is returned, because mounted files are part of the
// deployment environment; any other read error is always fatal.
func ReadFile(ctx context.Context, path, description string) ([]byte, error) {
	content, err := os.ReadFile(path)
	if err == nil {
		return content, nil
	}
	if errors.Is(err, os.ErrNotExist) && BuildModeFrom(ctx).Offline() {
		Warn(ctx, "%s: file %s not found, its content was not checked", description, path)
		return nil, fmt.Errorf("%s: %w", description, ErrSkipped)
	}
	return nil, fmt.Errorf("could not read %s file: %w", description, err)
}

// CheckFile verifies that a file referenced by a controller setting exists, with the same
// offline semantics as ReadFile. It is meant for files opened by third-party readers.
func CheckFile(ctx context.Context, path, description string) error {
	_, err := os.Stat(path)
	if err == nil {
		return nil
	}
	if errors.Is(err, os.ErrNotExist) && BuildModeFrom(ctx).Offline() {
		Warn(ctx, "%s: file %s not found, its content was not checked", description, path)
		return fmt.Errorf("%s: %w", description, ErrSkipped)
	}
	return fmt.Errorf("could not access %s file: %w", description, err)
}

// SkipOffline records that name could not be checked because of an external dependency and
// returns ErrSkipped. Factories call it in offline validation before connecting to anything.
func SkipOffline(ctx context.Context, format string, args ...any) error {
	Warn(ctx, format, args...)
	return ErrSkipped
}

// ValidationOptions parametrise settings validation performed by controllers.
type ValidationOptions struct {
	// Offline is true when the deployment environment (network, credentials, mounted files)
	// is not available and checks that depend on it should produce warnings, not errors.
	Offline bool
	// Warn records a non-fatal finding; it may be nil.
	Warn func(format string, args ...any)
}

// Warnf records a warning when a Warn function is configured.
func (o ValidationOptions) Warnf(format string, args ...any) {
	if o.Warn != nil {
		o.Warn(format, args...)
	}
}

// ValidationOptionsFrom derives the options from the build mode and diagnostics carried by ctx.
func ValidationOptionsFrom(ctx context.Context) ValidationOptions {
	return ValidationOptions{
		Offline: BuildModeFrom(ctx).Offline(),
		Warn:    func(format string, args ...any) { Warn(ctx, format, args...) },
	}
}
