package ip_match_database

import (
	"testing"
	"time"
)

// TestCache tests the TTL-based cache implementation
func TestCache(t *testing.T) {
	t.Run("cache hit returns stored value", func(t *testing.T) {
		cache := NewCache(1 * time.Hour)
		cache.Set("1.2.3.4", true)

		matches, found := cache.Get("1.2.3.4")
		if !found {
			t.Fatal("expected cache hit")
		}
		if !matches {
			t.Fatal("expected matches to be true")
		}
	})

	t.Run("cache miss returns not found", func(t *testing.T) {
		cache := NewCache(1 * time.Hour)

		_, found := cache.Get("1.2.3.4")
		if found {
			t.Fatal("expected cache miss")
		}
	})

	t.Run("cache stores both match and no-match", func(t *testing.T) {
		cache := NewCache(1 * time.Hour)
		cache.Set("1.2.3.4", true)
		cache.Set("5.6.7.8", false)

		matches1, found1 := cache.Get("1.2.3.4")
		if !found1 || !matches1 {
			t.Fatal("expected match result for 1.2.3.4")
		}

		matches2, found2 := cache.Get("5.6.7.8")
		if !found2 || matches2 {
			t.Fatal("expected no-match result for 5.6.7.8")
		}
	})

	t.Run("expired entries return not found", func(t *testing.T) {
		cache := NewCache(10 * time.Millisecond)
		cache.Set("1.2.3.4", true)

		// Wait for expiration
		time.Sleep(20 * time.Millisecond)

		_, found := cache.Get("1.2.3.4")
		if found {
			t.Fatal("expected cache miss for expired entry")
		}
	})

	t.Run("clear removes all entries", func(t *testing.T) {
		cache := NewCache(1 * time.Hour)
		cache.Set("1.2.3.4", true)
		cache.Set("5.6.7.8", false)

		cache.Clear()

		if cache.Size() != 0 {
			t.Fatalf("expected size 0, got %d", cache.Size())
		}
	})

	t.Run("size returns entry count", func(t *testing.T) {
		cache := NewCache(1 * time.Hour)
		if cache.Size() != 0 {
			t.Fatal("expected initial size 0")
		}

		cache.Set("1.2.3.4", true)
		if cache.Size() != 1 {
			t.Fatal("expected size 1")
		}

		cache.Set("5.6.7.8", false)
		if cache.Size() != 2 {
			t.Fatal("expected size 2")
		}
	})
}
