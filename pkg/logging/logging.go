// Package logging provides structured logging configuration using zap with logfmt encoding.
// It supports configurable log levels and outputs to stdout for container-friendly logging.
package logging

import (
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
// It defaults to info level for empty or unrecognized values.
func parseLevel(v string) zapcore.Level {
	switch strings.ToLower(v) {
	case "debug":
		return zap.DebugLevel
	case "info", "":
		return zap.InfoLevel
	case "warn", "warning":
		return zap.WarnLevel
	case "error":
		return zap.ErrorLevel
	default:
		return zap.InfoLevel
	}
}
