package asn_match_database

import (
	"strings"
	"testing"
	"time"

	"github.com/gtriggiano/envoy-authorization-service/pkg/config"
	"github.com/gtriggiano/envoy-authorization-service/pkg/controller"
)

// TestConfigValidation tests configuration validation
func TestConfigValidation(t *testing.T) {
	t.Run("invalid database type fails", func(t *testing.T) {
		config := &ASNMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "invalid",
			},
		}

		if err := config.Validate(); err == nil {
			t.Fatal("expected validation error for invalid database type")
		}
	})

	t.Run("invalid cache TTL is rejected when settings are decoded", func(t *testing.T) {
		var decoded ASNMatchDatabaseConfig
		err := controller.DecodeControllerSettings(map[string]any{
			"cache":    map[string]any{"ttl": "invalid"},
			"database": map[string]any{"type": "redis"},
		}, &decoded)
		if err == nil || !strings.Contains(err.Error(), "invalid duration") {
			t.Fatalf("expected invalid duration error, got %v", err)
		}
	})

	t.Run("unknown settings keys are rejected", func(t *testing.T) {
		var decoded ASNMatchDatabaseConfig
		err := controller.DecodeControllerSettings(map[string]any{
			"matchOnFailure": true,
			"database":       map[string]any{"type": "redis"},
		}, &decoded)
		if err == nil || !strings.Contains(err.Error(), `unknown key "matchOnFailure"`) {
			t.Fatalf("expected unknown key error, got %v", err)
		}
	})

	t.Run("missing cache TTL fails when cache is set", func(t *testing.T) {
		config := &ASNMatchDatabaseConfig{
			Cache: &CacheConfig{},
			Database: DatabaseConfig{
				Type: "redis",
				Redis: &RedisConfig{
					KeyPrefix: "test:",
					Host:      "localhost",
					Port:      6379,
				},
			},
		}

		if err := config.Validate(); err == nil {
			t.Fatal("expected validation error for missing cache TTL")
		}
	})

	t.Run("valid cache config passes", func(t *testing.T) {
		config := &ASNMatchDatabaseConfig{
			Cache: &CacheConfig{
				TTL: config.Duration(10 * time.Minute),
			},
			Database: DatabaseConfig{
				Type: "redis",
				Redis: &RedisConfig{
					KeyPrefix: "test:",
					Host:      "localhost",
					Port:      6379,
				},
			},
		}

		if err := config.Validate(); err != nil {
			t.Fatalf("expected valid config, got error: %v", err)
		}
	})
}

// TestGetCacheTTL tests the GetCacheTTL helper
func TestGetCacheTTL(t *testing.T) {
	t.Run("returns zero when cache is nil", func(t *testing.T) {
		config := &ASNMatchDatabaseConfig{}
		if ttl := config.GetCacheTTL(); ttl != 0 {
			t.Fatalf("expected 0, got %v", ttl)
		}
	})

	t.Run("returns parsed TTL when cache is configured", func(t *testing.T) {
		config := &ASNMatchDatabaseConfig{
			Cache: &CacheConfig{
				TTL: config.Duration(15 * time.Minute),
			},
		}
		expected := 15 * time.Minute
		if ttl := config.GetCacheTTL(); ttl != expected {
			t.Fatalf("expected %v, got %v", expected, ttl)
		}
	})
}

// TestGetDatabaseConnectionTimeout tests the GetDatabaseConnectionTimeout helper
func TestGetDatabaseConnectionTimeout(t *testing.T) {
	t.Run("returns default when connectionTimeout is empty", func(t *testing.T) {
		config := &ASNMatchDatabaseConfig{
			Database: DatabaseConfig{},
		}
		expected := DefaultDatabaseConnectionTimeout
		if timeout := config.GetDatabaseConnectionTimeout(); timeout != expected {
			t.Fatalf("expected %v, got %v", expected, timeout)
		}
	})

	t.Run("returns parsed connectionTimeout when configured", func(t *testing.T) {
		config := &ASNMatchDatabaseConfig{
			Database: DatabaseConfig{
				ConnectionTimeout: durationPtr(500 * time.Millisecond),
			},
		}
		expected := 500 * time.Millisecond
		if timeout := config.GetDatabaseConnectionTimeout(); timeout != expected {
			t.Fatalf("expected %v, got %v", expected, timeout)
		}
	})
}
