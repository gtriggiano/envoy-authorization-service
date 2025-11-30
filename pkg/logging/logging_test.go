package logging

import (
	"testing"

	"go.uber.org/zap/zapcore"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name          string
		config        Config
		expectedLevel zapcore.Level
	}{
		{"default level is info", Config{}, zapcore.InfoLevel},
		{"debug level", Config{Level: "debug"}, zapcore.DebugLevel},
		{"info level", Config{Level: "info"}, zapcore.InfoLevel},
		{"warn level", Config{Level: "warn"}, zapcore.WarnLevel},
		{"warning level", Config{Level: "warning"}, zapcore.WarnLevel},
		{"error level", Config{Level: "error"}, zapcore.ErrorLevel},
		{"unknown level defaults to info", Config{Level: "invalid"}, zapcore.InfoLevel},
		{"empty level defaults to info", Config{Level: ""}, zapcore.InfoLevel},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, err := New(tt.config)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if logger == nil {
				t.Fatal("logger is nil")
			}

			// Verify the logger was created
			core := logger.Core()
			if core == nil {
				t.Fatal("logger core is nil")
			}

			// Check if the level is correct
			if !core.Enabled(tt.expectedLevel) {
				t.Errorf("expected level %v to be enabled", tt.expectedLevel)
			}
		})
	}
}

func TestParseLevel(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected zapcore.Level
	}{
		{"debug", "debug", zapcore.DebugLevel},
		{"DEBUG uppercase", "DEBUG", zapcore.DebugLevel},
		{"info", "info", zapcore.InfoLevel},
		{"INFO uppercase", "INFO", zapcore.InfoLevel},
		{"warn", "warn", zapcore.WarnLevel},
		{"warning", "warning", zapcore.WarnLevel},
		{"WARN uppercase", "WARN", zapcore.WarnLevel},
		{"error", "error", zapcore.ErrorLevel},
		{"ERROR uppercase", "ERROR", zapcore.ErrorLevel},
		{"empty string defaults to info", "", zapcore.InfoLevel},
		{"unknown defaults to info", "unknown", zapcore.InfoLevel},
		{"mixed case", "DeBuG", zapcore.DebugLevel},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			level := parseLevel(tt.input)
			if level != tt.expected {
				t.Errorf("parseLevel(%q) = %v, want %v", tt.input, level, tt.expected)
			}
		})
	}
}
