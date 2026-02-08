package ip_match_database

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

const defaultSQLServerHost = "localhost"

// SQLServerConfig represents SQL Server-specific configuration.
type SQLServerConfig struct {
	Query               string               `yaml:"query"`
	ConnectionString    string               `yaml:"connectionString"`
	ConnectionStringEnv string               `yaml:"connectionStringEnv"`
	Host                string               `yaml:"host"`
	Port                int                  `yaml:"port"`
	Instance            string               `yaml:"instance"`
	DatabaseName        string               `yaml:"databaseName"`
	UsernameEnv         string               `yaml:"usernameEnv"`
	PasswordEnv         string               `yaml:"passwordEnv"`
	FailoverPartner     string               `yaml:"failoverPartner"`
	FailoverPort        int                  `yaml:"failoverPort"`
	MultiSubnetFailover *bool                `yaml:"multiSubnetFailover"`
	ApplicationIntent   string               `yaml:"applicationIntent"`
	Protocol            string               `yaml:"protocol"`
	AppName             string               `yaml:"appName"`
	Pool                *SQLServerPoolConfig `yaml:"pool"`
	TLS                 *SQLServerTLSConfig  `yaml:"tls"`
}

// SQLServerPoolConfig represents connection pool configuration.
// Note: database/sql (used for SQL Server) does not support a minimum pool size.
// MaxIdleConnections sets the maximum number of idle connections kept in the pool
// (via SetMaxIdleConns), which differs from backends like pgx where a minimum
// pool size can be enforced.
type SQLServerPoolConfig struct {
	MaxConnections     int    `yaml:"maxConnections"`
	MaxIdleConnections int    `yaml:"maxIdleConnections"`
	MaxIdleTime        string `yaml:"maxIdleTime"`
	ConnectionTimeout  string `yaml:"connectionTimeout"`
}

// SQLServerTLSConfig represents TLS configuration for SQL Server.
type SQLServerTLSConfig struct {
	Encrypt                string `yaml:"encrypt"`
	TrustServerCertificate bool   `yaml:"trustServerCertificate"`
	CACert                 string `yaml:"caCert"`
	HostNameInCertificate  string `yaml:"hostNameInCertificate"`
	TLSMin                 string `yaml:"tlsMin"`
}

// ApplyDefaults sets default values for SQL Server configuration.
func (c *SQLServerConfig) ApplyDefaults() {
	if c != nil {
		if c.Host == "" {
			c.Host = defaultSQLServerHost
		}
		if c.Port == 0 {
			c.Port = defaultSQLServerPort
		}
	}
}

// validateSQLServerConfig checks SQL Server-specific configuration.
func (c *IpMatchDatabaseConfig) validateSQLServerConfig() error {
	if c.Database.SQLServer == nil {
		return fmt.Errorf("database.sqlserver configuration is required when database.type is 'sqlserver'")
	}

	sqlServer := c.Database.SQLServer

	if sqlServer.Query == "" {
		return fmt.Errorf("database.sqlserver.query is required")
	}

	placeholderRegex := regexp.MustCompile(`@p\d+`)
	matches := placeholderRegex.FindAllString(sqlServer.Query, -1)
	if len(matches) != 1 {
		return fmt.Errorf("database.sqlserver.query must contain exactly one parameter placeholder (@p1), found %d", len(matches))
	}
	if matches[0] != "@p1" {
		return fmt.Errorf("database.sqlserver.query must use @p1 as the parameter placeholder, found %s", matches[0])
	}

	hasInlineConnectionString := strings.TrimSpace(sqlServer.ConnectionString) != ""
	hasConnectionStringEnv := strings.TrimSpace(sqlServer.ConnectionStringEnv) != ""
	usingRawConnectionString := hasInlineConnectionString || hasConnectionStringEnv

	if hasInlineConnectionString && hasConnectionStringEnv {
		return fmt.Errorf("database.sqlserver.connectionString and database.sqlserver.connectionStringEnv are mutually exclusive")
	}

	if hasConnectionStringEnv {
		value, exists := os.LookupEnv(sqlServer.ConnectionStringEnv)
		if !exists {
			return fmt.Errorf("environment variable '%s' not found", sqlServer.ConnectionStringEnv)
		}
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("environment variable '%s' is empty", sqlServer.ConnectionStringEnv)
		}
	}

	if usingRawConnectionString {
		if sqlServer.TLS != nil {
			return fmt.Errorf("database.sqlserver.tls cannot be used with connectionString/connectionStringEnv; include TLS options directly in the raw connection string")
		}
		if sqlServer.Instance != "" || sqlServer.DatabaseName != "" || sqlServer.UsernameEnv != "" || sqlServer.PasswordEnv != "" ||
			sqlServer.FailoverPartner != "" || sqlServer.FailoverPort != 0 || sqlServer.MultiSubnetFailover != nil ||
			sqlServer.ApplicationIntent != "" || sqlServer.Protocol != "" || sqlServer.AppName != "" {
			return fmt.Errorf("database.sqlserver structured connection fields cannot be combined with connectionString/connectionStringEnv")
		}
	}

	if !usingRawConnectionString {
		if sqlServer.Host == "" {
			return fmt.Errorf("database.sqlserver.host is required")
		}

		if sqlServer.Port < 1 || sqlServer.Port > 65535 {
			return fmt.Errorf("database.sqlserver.port must be between 1 and 65535")
		}

		if sqlServer.DatabaseName == "" {
			return fmt.Errorf("database.sqlserver.databaseName is required")
		}

		if sqlServer.UsernameEnv == "" {
			return fmt.Errorf("database.sqlserver.usernameEnv is required")
		}
		if sqlServer.PasswordEnv == "" {
			return fmt.Errorf("database.sqlserver.passwordEnv is required")
		}

		if _, exists := os.LookupEnv(sqlServer.UsernameEnv); !exists {
			return fmt.Errorf("environment variable '%s' not found", sqlServer.UsernameEnv)
		}
		if _, exists := os.LookupEnv(sqlServer.PasswordEnv); !exists {
			return fmt.Errorf("environment variable '%s' not found", sqlServer.PasswordEnv)
		}
	}

	if sqlServer.FailoverPort != 0 {
		if sqlServer.FailoverPartner == "" {
			return fmt.Errorf("database.sqlserver.failoverPartner is required when failoverPort is set")
		}
		if sqlServer.FailoverPort < 1 || sqlServer.FailoverPort > 65535 {
			return fmt.Errorf("database.sqlserver.failoverPort must be between 1 and 65535")
		}
	}

	if sqlServer.ApplicationIntent != "" {
		validIntents := []string{"ReadOnly", "ReadWrite"}
		valid := false
		for _, intent := range validIntents {
			if strings.EqualFold(sqlServer.ApplicationIntent, intent) {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("invalid applicationIntent '%s', must be one of: %s", sqlServer.ApplicationIntent, strings.Join(validIntents, ", "))
		}
	}

	if sqlServer.Protocol != "" {
		validProtocols := []string{"tcp", "np", "lpc"}
		valid := false
		for _, protocol := range validProtocols {
			if strings.EqualFold(sqlServer.Protocol, protocol) {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("invalid protocol '%s', must be one of: %s", sqlServer.Protocol, strings.Join(validProtocols, ", "))
		}
	}

	if sqlServer.Pool != nil {
		if err := validateSQLServerPoolConfig(sqlServer.Pool); err != nil {
			return fmt.Errorf("invalid pool configuration: %w", err)
		}
	}

	if sqlServer.TLS != nil {
		if err := validateSQLServerTLS(sqlServer.TLS); err != nil {
			return fmt.Errorf("invalid sqlserver TLS configuration: %w", err)
		}
	}

	return nil
}

func validateSQLServerPoolConfig(pool *SQLServerPoolConfig) error {
	if pool.MaxConnections <= 0 {
		return fmt.Errorf("pool.maxConnections must be greater than 0")
	}
	if pool.MaxIdleConnections < 0 {
		return fmt.Errorf("pool.maxIdleConnections must be non-negative")
	}
	if pool.MaxIdleConnections > pool.MaxConnections {
		return fmt.Errorf("pool.maxIdleConnections (%d) must not exceed pool.maxConnections (%d)", pool.MaxIdleConnections, pool.MaxConnections)
	}

	if pool.MaxIdleTime != "" {
		maxIdleTime, err := time.ParseDuration(pool.MaxIdleTime)
		if err != nil {
			return fmt.Errorf("invalid pool.maxIdleTime: %w", err)
		}
		if maxIdleTime < 0 {
			return fmt.Errorf("pool.maxIdleTime must be non-negative")
		}
	}

	if pool.ConnectionTimeout != "" {
		timeout, err := time.ParseDuration(pool.ConnectionTimeout)
		if err != nil {
			return fmt.Errorf("invalid pool.connectionTimeout: %w", err)
		}
		if timeout <= 0 {
			return fmt.Errorf("pool.connectionTimeout must be positive")
		}
	}

	return nil
}

func validateSQLServerTLS(tls *SQLServerTLSConfig) error {
	validEncryptModes := []string{"strict", "disable", "false", "optional", "no", "0", "f", "true", "mandatory", "yes", "1", "t"}
	if tls.Encrypt != "" {
		valid := false
		for _, mode := range validEncryptModes {
			if strings.EqualFold(tls.Encrypt, mode) {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("invalid encrypt mode '%s', must be one of: %s", tls.Encrypt, strings.Join(validEncryptModes, ", "))
		}
	}

	if tls.CACert != "" {
		if err := validateCertificateFile(tls.CACert, "CA certificate"); err != nil {
			return err
		}
	}

	if tls.TLSMin != "" {
		validTLSMin := []string{"1.0", "1.1", "1.2", "1.3"}
		valid := false
		for _, version := range validTLSMin {
			if tls.TLSMin == version {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("invalid tlsMin '%s', must be one of: %s", tls.TLSMin, strings.Join(validTLSMin, ", "))
		}
	}

	encryptMode := strings.ToLower(strings.TrimSpace(tls.Encrypt))
	encryptDisabled := encryptMode == "disable" || encryptMode == "false" || encryptMode == "optional" || encryptMode == "no" || encryptMode == "0" || encryptMode == "f"
	hasTLSVerificationOptions := tls.CACert != "" || tls.HostNameInCertificate != ""
	if encryptDisabled && hasTLSVerificationOptions {
		return fmt.Errorf("tls verification options require encrypt to be true, mandatory, or strict")
	}

	return nil
}
