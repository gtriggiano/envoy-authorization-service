package asn_match_database

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresDataSource implements DataSource for PostgreSQL
type PostgresDataSource struct {
	pool  *pgxpool.Pool
	query string
}

// NewPostgresDataSource creates a new PostgreSQL data source from configuration
func NewPostgresDataSource(ctx context.Context, config *PostgresConfig) (*PostgresDataSource, error) {
	if config == nil {
		return nil, fmt.Errorf("postgres configuration is required")
	}

	// Get credentials from environment
	username := os.Getenv(config.UsernameEnv)
	if username == "" {
		return nil, fmt.Errorf("username is empty in environment variable '%s'", config.UsernameEnv)
	}

	password := os.Getenv(config.PasswordEnv)
	if password == "" {
		return nil, fmt.Errorf("password is empty in environment variable '%s'", config.PasswordEnv)
	}

	// Build connection string
	connString := fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s",
		username,
		password,
		config.Host,
		config.Port,
		config.DatabaseName,
	)

	// Parse pool config
	poolConfig, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse connection string: %w", err)
	}

	// Apply defaults
	poolConfig.MaxConns = 10
	poolConfig.MinConns = 2
	poolConfig.MaxConnIdleTime = 5 * time.Minute
	poolConfig.ConnConfig.ConnectTimeout = 5 * time.Second

	// Apply pool settings
	if config.Pool != nil {
		if config.Pool.MaxConnections > 0 {
			poolConfig.MaxConns = int32(config.Pool.MaxConnections)
		}

		if config.Pool.MinConnections >= 0 {
			poolConfig.MinConns = int32(config.Pool.MinConnections)
		}

		if config.Pool.MaxIdleTime != "" {
			maxIdleTime, err := time.ParseDuration(config.Pool.MaxIdleTime)
			if err == nil && maxIdleTime > 0 {
				poolConfig.MaxConnIdleTime = maxIdleTime
			}
		}

		if config.Pool.ConnectionTimeout != "" {
			connTimeout, err := time.ParseDuration(config.Pool.ConnectionTimeout)
			if err == nil && connTimeout > 0 {
				poolConfig.ConnConfig.ConnectTimeout = connTimeout
			}
		}
	}

	// Configure TLS if enabled
	if config.TLS != nil {
		tlsConfig, sslMode, err := buildPostgresTLSConfig(config.TLS)
		if err != nil {
			return nil, fmt.Errorf("failed to build TLS configuration: %w", err)
		}

		if tlsConfig != nil {
			poolConfig.ConnConfig.TLSConfig = tlsConfig
		}

		// Set SSL mode in connection string
		if sslMode != "" {
			poolConfig.ConnConfig.RuntimeParams["sslmode"] = sslMode
		}
	}

	// Create pool
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Test connection
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("failed to connect to PostgreSQL: %w", err)
	}

	return &PostgresDataSource{
		pool:  pool,
		query: config.Query,
	}, nil
}

// Contains checks if the ASN exists in PostgreSQL
func (p *PostgresDataSource) Contains(ctx context.Context, asn uint) (bool, error) {
	rows, err := p.pool.Query(ctx, p.query, int64(asn))
	if err != nil {
		return false, fmt.Errorf("postgres query failed: %w", err)
	}
	defer rows.Close()

	// Any rows returned = match, zero rows = no match
	return rows.Next(), nil
}

// Close releases PostgreSQL pool resources
func (p *PostgresDataSource) Close() error {
	if p.pool != nil {
		p.pool.Close()
	}
	return nil
}

// HealthCheck verifies connectivity to PostgreSQL
func (p *PostgresDataSource) HealthCheck(ctx context.Context) error {
	return p.pool.Ping(ctx)
}

// buildPostgresTLSConfig creates a TLS configuration from the provided settings
// Returns (tlsConfig, sslMode, error)
func buildPostgresTLSConfig(config *PostgresTLSConfig) (*tls.Config, string, error) {
	// Determine SSL mode
	sslMode := "prefer" // Default
	if config.Mode != "" {
		sslMode = config.Mode
	}

	// If mode is "disable", no TLS config needed
	if sslMode == "disable" {
		return nil, sslMode, nil
	}

	tlsConfig := &tls.Config{}

	// Load CA certificate if provided
	if config.CACert != "" {
		caCertData, err := os.ReadFile(config.CACert)
		if err != nil {
			return nil, "", fmt.Errorf("failed to read CA certificate file '%s': %w", config.CACert, err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCertData) {
			return nil, "", fmt.Errorf("failed to parse CA certificate from file '%s'", config.CACert)
		}
		tlsConfig.RootCAs = caCertPool
	}

	// Load client certificate and key if provided
	if config.ClientCert != "" && config.ClientKey != "" {
		cert, err := tls.LoadX509KeyPair(config.ClientCert, config.ClientKey)
		if err != nil {
			return nil, "", fmt.Errorf("failed to load client certificate pair: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return tlsConfig, sslMode, nil
}
