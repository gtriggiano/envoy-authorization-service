package ip_match_database

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	_ "github.com/microsoft/go-mssqldb"
)

// SQLServerDataSource implements DataSource for SQL Server.
type SQLServerDataSource struct {
	db    *sql.DB
	query string
}

// NewSQLServerDataSource creates a new SQL Server data source from configuration.
func NewSQLServerDataSource(ctx context.Context, config *SQLServerConfig) (*SQLServerDataSource, error) {
	if config == nil {
		return nil, fmt.Errorf("sqlserver configuration is required")
	}

	connectTimeout := 5 * time.Second
	maxOpenConns := 10
	maxIdleConns := 2
	maxIdleTime := 5 * time.Minute

	if config.Pool != nil {
		if config.Pool.MaxConnections > 0 {
			maxOpenConns = config.Pool.MaxConnections
		}
		// Note: database/sql does not support a minimum pool size. We use
		// MaxIdleConnections to set the maximum number of idle connections via SetMaxIdleConns.
		// Validation already ensures MaxIdleConnections does not exceed MaxConnections.
		if config.Pool.MaxIdleConnections >= 0 {
			maxIdleConns = config.Pool.MaxIdleConnections
		}
		if config.Pool.MaxIdleTime != "" {
			if parsed, err := time.ParseDuration(config.Pool.MaxIdleTime); err == nil && parsed >= 0 {
				maxIdleTime = parsed
			}
		}
		if config.Pool.ConnectionTimeout != "" {
			if parsed, err := time.ParseDuration(config.Pool.ConnectionTimeout); err == nil && parsed > 0 {
				connectTimeout = parsed
			}
		}
	}

	connString, err := resolveSQLServerConnectionString(config, connectTimeout)
	if err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlserver", connString)
	if err != nil {
		return nil, fmt.Errorf("failed to open SQL Server connection: %w", err)
	}

	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)
	db.SetConnMaxIdleTime(maxIdleTime)

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to connect to SQL Server: %w", err)
	}

	return &SQLServerDataSource{
		db:    db,
		query: config.Query,
	}, nil
}

func resolveSQLServerConnectionString(config *SQLServerConfig, connectTimeout time.Duration) (string, error) {
	if connectionString := strings.TrimSpace(config.ConnectionString); connectionString != "" {
		return connectionString, nil
	}

	if config.ConnectionStringEnv != "" {
		connectionString := strings.TrimSpace(os.Getenv(config.ConnectionStringEnv))
		if connectionString == "" {
			return "", fmt.Errorf("connection string is empty in environment variable '%s'", config.ConnectionStringEnv)
		}
		return connectionString, nil
	}

	username := os.Getenv(config.UsernameEnv)
	if username == "" {
		return "", fmt.Errorf("username is empty in environment variable '%s'", config.UsernameEnv)
	}
	password := os.Getenv(config.PasswordEnv)
	if password == "" {
		return "", fmt.Errorf("password is empty in environment variable '%s'", config.PasswordEnv)
	}

	return buildSQLServerConnectionString(config, username, password, connectTimeout), nil
}

func buildSQLServerConnectionString(config *SQLServerConfig, username, password string, connectTimeout time.Duration) string {
	query := url.Values{}
	query.Set("database", config.DatabaseName)
	query.Set("connection timeout", strconv.Itoa(int(connectTimeout.Seconds())))

	if config.FailoverPartner != "" {
		query.Set("failoverpartner", config.FailoverPartner)
	}
	if config.FailoverPort > 0 {
		query.Set("failoverport", strconv.Itoa(config.FailoverPort))
	}
	if config.MultiSubnetFailover != nil {
		query.Set("multisubnetfailover", strconv.FormatBool(*config.MultiSubnetFailover))
	}
	if config.ApplicationIntent != "" {
		query.Set("applicationintent", config.ApplicationIntent)
	}
	if config.Protocol != "" {
		query.Set("protocol", config.Protocol)
	}
	if config.AppName != "" {
		query.Set("app name", config.AppName)
	}

	if config.TLS != nil {
		if config.TLS.Encrypt != "" {
			query.Set("encrypt", config.TLS.Encrypt)
		} else {
			query.Set("encrypt", "true")
		}
		query.Set("TrustServerCertificate", strconv.FormatBool(config.TLS.TrustServerCertificate))
		if config.TLS.CACert != "" {
			query.Set("certificate", config.TLS.CACert)
		}
		if config.TLS.HostNameInCertificate != "" {
			query.Set("hostNameInCertificate", config.TLS.HostNameInCertificate)
		}
		if config.TLS.TLSMin != "" {
			query.Set("tlsmin", config.TLS.TLSMin)
		}
	}

	path := ""
	if config.Instance != "" {
		path = "/" + url.PathEscape(config.Instance)
	}

	return (&url.URL{
		Scheme:   "sqlserver",
		User:     url.UserPassword(username, password),
		Host:     fmt.Sprintf("%s:%d", config.Host, config.Port),
		Path:     path,
		RawQuery: query.Encode(),
	}).String()
}

// Contains checks if the IP address exists in SQL Server.
func (s *SQLServerDataSource) Contains(ctx context.Context, ipAddress string) (bool, error) {
	rows, err := s.db.QueryContext(ctx, s.query, ipAddress)
	if err != nil {
		return false, fmt.Errorf("sqlserver query failed: %w", err)
	}
	defer rows.Close()

	return rows.Next(), nil
}

// Close releases SQL Server resources.
func (s *SQLServerDataSource) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// HealthCheck verifies connectivity to SQL Server.
func (s *SQLServerDataSource) HealthCheck(ctx context.Context) error {
	return s.db.PingContext(ctx)
}
