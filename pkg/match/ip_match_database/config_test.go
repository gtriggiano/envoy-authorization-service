package ip_match_database

import (
	"testing"
	"time"
)

// TestConfigValidation tests configuration validation
func TestConfigValidation(t *testing.T) {
	t.Run("invalid database type fails", func(t *testing.T) {
		config := &IpMatchDatabaseConfig{
			Database: DatabaseConfig{
				Type: "invalid",
			},
		}

		if err := config.Validate(); err == nil {
			t.Fatal("expected validation error for invalid database type")
		}
	})

	t.Run("invalid cache TTL fails", func(t *testing.T) {
		config := &IpMatchDatabaseConfig{
			Cache: &CacheConfig{
				TTL: "invalid",
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

		if err := config.Validate(); err == nil {
			t.Fatal("expected validation error for invalid cache TTL")
		}
	})

	t.Run("missing cache TTL fails when cache is set", func(t *testing.T) {
		config := &IpMatchDatabaseConfig{
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
		config := &IpMatchDatabaseConfig{
			Cache: &CacheConfig{
				TTL: "10m",
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
		config := &IpMatchDatabaseConfig{}
		if ttl := config.GetCacheTTL(); ttl != 0 {
			t.Fatalf("expected 0, got %v", ttl)
		}
	})

	t.Run("returns parsed TTL when cache is configured", func(t *testing.T) {
		config := &IpMatchDatabaseConfig{
			Cache: &CacheConfig{
				TTL: "15m",
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
		config := &IpMatchDatabaseConfig{
			Database: DatabaseConfig{},
		}
		expected := DefaultDatabaseConnectionTimeout
		if timeout := config.GetDatabaseConnectionTimeout(); timeout != expected {
			t.Fatalf("expected %v, got %v", expected, timeout)
		}
	})

	t.Run("returns parsed connectionTimeout when configured", func(t *testing.T) {
		config := &IpMatchDatabaseConfig{
			Database: DatabaseConfig{
				ConnectionTimeout: "500ms",
			},
		}
		expected := 500 * time.Millisecond
		if timeout := config.GetDatabaseConnectionTimeout(); timeout != expected {
			t.Fatalf("expected %v, got %v", expected, timeout)
		}
	})
}
