// Package logging provides structured logging configuration using zap with logfmt encoding.
// It supports configurable log levels and outputs to stdout for container-friendly logging.
package logging

import (
	"fmt"
	"os"
	"strings"

	zaplogfmt "github.com/allir/zap-logfmt"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Config holds logger configuration options.
type Config struct {
	// Level specifies the minimum log level (debug, info, warn, error).
	Level string `yaml:"level"`
}

// Validate rejects log levels outside the supported set (debug, info, warn/warning, error).
// An empty level is accepted and means info.
func (c Config) Validate() error {
	if _, ok := lookupLevel(c.Level); !ok {
		return fmt.Errorf("configuration 'logging.level' must be one of debug, info, warn, error; got %q", c.Level)
	}
	return nil
}

// New initializes a zap logger configured to emit logfmt output to stdout.
// The logger uses production-grade settings with the specified log level.
func New(cfg Config) (*zap.Logger, error) {
	level := parseLevel(cfg.Level)
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = ""
	encoderConfig.EncodeTime = zapcore.RFC3339TimeEncoder
	encoderConfig.ConsoleSeparator = " "

	core := zapcore.NewCore(
		zaplogfmt.NewEncoder(encoderConfig),
		zapcore.Lock(os.Stdout),
		zap.NewAtomicLevelAt(level),
	)

	return zap.New(core), nil
}

// parseLevel converts a string level name to a zapcore.Level constant.
// It defaults to info level for empty values; Config.Validate rejects unknown ones.
func parseLevel(v string) zapcore.Level {
	level, _ := lookupLevel(v)
	return level
}

// lookupLevel maps a level name to zapcore.Level and reports whether it is known.
func lookupLevel(v string) (zapcore.Level, bool) {
	switch strings.ToLower(v) {
	case "debug":
		return zap.DebugLevel, true
	case "info", "":
		return zap.InfoLevel, true
	case "warn", "warning":
		return zap.WarnLevel, true
	case "error":
		return zap.ErrorLevel, true
	default:
		return zap.InfoLevel, false
	}
}
