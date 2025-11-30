package asn_match_database

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strconv"

	"github.com/redis/go-redis/v9"
)

// RedisDataSource implements DataSource for Redis
type RedisDataSource struct {
	client    *redis.Client
	keyPrefix string
}

// NewRedisDataSource creates a new Redis data source from configuration
func NewRedisDataSource(ctx context.Context, config *RedisConfig) (*RedisDataSource, error) {
	if config == nil {
		return nil, fmt.Errorf("redis configuration is required")
	}

	// Build Redis options
	opts := &redis.Options{
		Addr: fmt.Sprintf("%s:%d", config.Host, config.Port),
		DB:   config.DB,
	}

	// Add username if configured
	if config.UsernameEnv != "" {
		username := os.Getenv(config.UsernameEnv)
		opts.Username = username
	}

	// Add password if configured
	if config.PasswordEnv != "" {
		password := os.Getenv(config.PasswordEnv)
		opts.Password = password
	}

	// Configure TLS if enabled
	if config.TLS != nil {
		tlsConfig, err := buildRedisTLSConfig(config.TLS)
		if err != nil {
			return nil, fmt.Errorf("failed to build TLS configuration: %w", err)
		}
		opts.TLSConfig = tlsConfig
	}

	// Create client
	client := redis.NewClient(opts)

	// Test connection
	if err := client.Ping(ctx).Err(); err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &RedisDataSource{
		client:    client,
		keyPrefix: config.KeyPrefix,
	}, nil
}

// Contains checks if the ASN exists in Redis
func (r *RedisDataSource) Contains(ctx context.Context, asn uint) (bool, error) {
	key := r.keyPrefix + strconv.FormatUint(uint64(asn), 10)

	result, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("redis query failed: %w", err)
	}

	return result > 0, nil
}

// Close releases Redis client resources
func (r *RedisDataSource) Close() error {
	if r.client != nil {
		return r.client.Close()
	}
	return nil
}

// HealthCheck verifies connectivity to Redis
func (r *RedisDataSource) HealthCheck(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
}

// buildRedisTLSConfig creates a TLS configuration from the provided settings
func buildRedisTLSConfig(config *RedisTLSConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: config.InsecureSkipVerify,
	}

	// Load CA certificate if provided
	if config.CACert != "" {
		caCertData, err := os.ReadFile(config.CACert)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate file '%s': %w", config.CACert, err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCertData) {
			return nil, fmt.Errorf("failed to parse CA certificate from file '%s'", config.CACert)
		}
		tlsConfig.RootCAs = caCertPool
	}

	// Load client certificate and key if provided
	if config.ClientCert != "" && config.ClientKey != "" {
		cert, err := tls.LoadX509KeyPair(config.ClientCert, config.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate pair: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return tlsConfig, nil
}
