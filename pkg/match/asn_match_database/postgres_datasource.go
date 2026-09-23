package asn_match_database

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
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

	// Resolve credentials from their inline value or file
	username, err := config.UsernameSource().Resolve("database.postgres.username")
	if err != nil {
		return nil, err
	}

	password, err := config.PasswordSource().Resolve("database.postgres.password")
	if err != nil {
		return nil, err
	}

	// Parse pool config. TLS is expressed as libpq parameters in the connection
	// string so that pgx implements the sslmode semantics (fallbacks, verify-ca,
	// verify-full host name checks) instead of a hand-built tls.Config.
	poolConfig, err := pgxpool.ParseConfig(buildPostgresConnString(username, password, config))
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

		if config.Pool.MaxIdleTime != nil {
			poolConfig.MaxConnIdleTime = config.Pool.MaxIdleTime.Std()
		}

		if config.Pool.ConnectionTimeout != nil {
			poolConfig.ConnConfig.ConnectTimeout = config.Pool.ConnectionTimeout.Std()
		}
	}

	// Create pool
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Test connection
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to connect to PostgreSQL: %w", err)
	}

	return &PostgresDataSource{
		pool:  pool,
		query: config.Query,
	}, nil
}

// buildPostgresConnString assembles the pgx connection URL.
//
// Credentials and the database name are percent-encoded, so any character is
// allowed in them. TLS settings travel as the libpq parameters sslmode,
// sslrootcert, sslcert and sslkey; pgx strips them from the startup message and
// builds the TLS configuration itself. sslmode is always set so that the
// configuration, not a PGSSLMODE environment variable, decides the TLS mode.
func buildPostgresConnString(username, password string, config *PostgresConfig) string {
	u := url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(username, password),
		Host:   net.JoinHostPort(config.Host, strconv.Itoa(config.Port)),
		Path:   "/" + config.DatabaseName,
	}

	params := url.Values{}
	params.Set("sslmode", config.TLS.EffectiveMode())
	if config.TLS != nil {
		if config.TLS.CACert != "" {
			params.Set("sslrootcert", config.TLS.CACert)
		}
		if config.TLS.ClientCert != "" {
			params.Set("sslcert", config.TLS.ClientCert)
		}
		if config.TLS.ClientKey != "" {
			params.Set("sslkey", config.TLS.ClientKey)
		}
	}
	u.RawQuery = params.Encode()

	return u.String()
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
