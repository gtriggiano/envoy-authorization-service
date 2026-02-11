//go:build e2e

package ip_match_database

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/netip"
	stdruntime "runtime"
	"strconv"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/jackc/pgx/v5"
	_ "github.com/microsoft/go-mssqldb"
	"github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	"github.com/gtriggiano/envoy-authorization-service/pkg/config"
	"github.com/gtriggiano/envoy-authorization-service/pkg/controller"
	"github.com/gtriggiano/envoy-authorization-service/pkg/runtime"
)

func TestRedisIpMatchDatabase(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	container, host, port := startRedis(t, ctx)
	defer func() { _ = container.Terminate(ctx) }()

	client := redis.NewClient(&redis.Options{
		Addr: fmt.Sprintf("%s:%d", host, port),
		DB:   0,
	})
	requireNoErr(t, client.Set(ctx, "block:203.0.113.10", "1", 0).Err())

	logger := zaptest.NewLogger(t)
	ctrl := buildController(t, ctx, logger, config.ControllerConfig{
		Name: "ip-db-redis",
		Type: ControllerKind,
		Settings: map[string]any{
			"action": "deny",
			"cache": map[string]any{
				"ttl": "1m",
			},
			"database": map[string]any{
				"type": "redis",
				"redis": map[string]any{
					"keyPrefix": "block:",
					"host":      host,
					"port":      port,
					"db":        0,
				},
			},
		},
	})

	request := &runtime.RequestContext{
		Request:    minimalCheckRequest("203.0.113.10"),
		ReceivedAt: time.Now(),
		IpAddress:  netip.MustParseAddr("203.0.113.10"),
	}

	verdict, err := ctrl.Match(ctx, request, nil)
	requireNoErr(t, err)
	if !verdict.IsMatch {
		t.Fatalf("expected to match IP, got: %s", verdict.Description)
	}

	request.IpAddress = netip.MustParseAddr("198.51.100.42")
	request.Request = minimalCheckRequest("198.51.100.42")
	verdict, err = ctrl.Match(ctx, request, nil)
	requireNoErr(t, err)
	if verdict.IsMatch {
		t.Fatalf("expected to miss IP, got: %s", verdict.Description)
	}
}

func TestPostgresIpMatchDatabase(t *testing.T) {
	t.Setenv("POSTGRES_USER", "postgres")
	t.Setenv("POSTGRES_PASSWORD", "postgres")

	ctx := context.Background()
	container, host, port := startPostgres(t, ctx)
	defer func() { _ = container.Terminate(ctx) }()

	dsn := fmt.Sprintf("postgres://postgres:postgres@%s:%d/security?sslmode=disable", host, port)
	conn, err := pgx.Connect(ctx, dsn)
	requireNoErr(t, err)
	t.Cleanup(func() { _ = conn.Close(ctx) })

	_, err = conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS trusted_ips (ip inet PRIMARY KEY);
		INSERT INTO trusted_ips (ip) VALUES ('203.0.113.10') ON CONFLICT DO NOTHING;
	`)
	requireNoErr(t, err)

	logger := zaptest.NewLogger(t)
	ctrl := buildController(t, ctx, logger, config.ControllerConfig{
		Name: "ip-db-postgres",
		Type: ControllerKind,
		Settings: map[string]any{
			"action": "allow",
			"database": map[string]any{
				"type":              "postgres",
				"connectionTimeout": "1s",
				"postgres": map[string]any{
					"query":        "SELECT 1 FROM trusted_ips WHERE ip = $1 LIMIT 1",
					"host":         host,
					"port":         port,
					"databaseName": "security",
					"usernameEnv":  "POSTGRES_USER",
					"passwordEnv":  "POSTGRES_PASSWORD",
					"pool": map[string]any{
						"maxConnections":    5,
						"minConnections":    1,
						"maxIdleTime":       "5m",
						"connectionTimeout": "5s",
					},
				},
			},
		},
	})

	request := &runtime.RequestContext{
		Request:    minimalCheckRequest("203.0.113.10"),
		ReceivedAt: time.Now(),
		IpAddress:  netip.MustParseAddr("203.0.113.10"),
	}

	verdict, err := ctrl.Match(ctx, request, nil)
	requireNoErr(t, err)
	if !verdict.IsMatch {
		t.Fatalf("expected to match IP, got: %s", verdict.Description)
	}

	request.IpAddress = netip.MustParseAddr("198.51.100.42")
	request.Request = minimalCheckRequest("198.51.100.42")

	verdict, err = ctrl.Match(ctx, request, nil)
	requireNoErr(t, err)
	if verdict.IsMatch {
		t.Fatalf("expected to miss IP, got: %s", verdict.Description)
	}
}

func TestSQLServerIpMatchDatabase(t *testing.T) {
	if stdruntime.GOARCH == "arm64" {
		t.Skip("SQL Server container e2e test is skipped on arm64 due image/runtime compatibility")
	}

	t.Setenv("SQLSERVER_USER", "sa")
	t.Setenv("SQLSERVER_PASSWORD", "sqlServer_P4ssword!")

	ctx := context.Background()
	container, host, port := startSQLServer(t, ctx)
	defer func() { _ = container.Terminate(ctx) }()

	dsn := fmt.Sprintf("server=%s;port=%d;user id=sa;password=sqlServer_P4ssword!;database=master;encrypt=disable", host, port)
	db, err := sql.Open("sqlserver", dsn)
	requireNoErr(t, err)
	t.Cleanup(func() { _ = db.Close() })

	_, err = db.ExecContext(ctx, `
		IF OBJECT_ID('trusted_ips', 'U') IS NULL
		BEGIN
			CREATE TABLE trusted_ips (ip VARCHAR(64) PRIMARY KEY)
		END
		MERGE trusted_ips AS target
		USING (VALUES ('203.0.113.10')) AS source (ip)
		ON (target.ip = source.ip)
		WHEN NOT MATCHED THEN
			INSERT (ip) VALUES (source.ip);
	`)
	requireNoErr(t, err)

	logger := zaptest.NewLogger(t)
	ctrl := buildController(t, ctx, logger, config.ControllerConfig{
		Name: "ip-db-sqlserver",
		Type: ControllerKind,
		Settings: map[string]any{
			"action": "allow",
			"database": map[string]any{
				"type":              "sqlserver",
				"connectionTimeout": "2s",
				"sqlserver": map[string]any{
					"query":        "SELECT 1 FROM trusted_ips WHERE ip = @p1",
					"host":         host,
					"port":         port,
					"databaseName": "master",
					"usernameEnv":  "SQLSERVER_USER",
					"passwordEnv":  "SQLSERVER_PASSWORD",
					"pool": map[string]any{
						"maxConnections":    5,
						"minConnections":    1,
						"maxIdleTime":       "5m",
						"connectionTimeout": "5s",
					},
				},
			},
		},
	})

	request := &runtime.RequestContext{
		Request:    minimalCheckRequest("203.0.113.10"),
		ReceivedAt: time.Now(),
		IpAddress:  netip.MustParseAddr("203.0.113.10"),
	}

	verdict, err := ctrl.Match(ctx, request, nil)
	requireNoErr(t, err)
	if !verdict.IsMatch {
		t.Fatalf("expected to match IP, got: %s", verdict.Description)
	}

	request.IpAddress = netip.MustParseAddr("198.51.100.42")
	request.Request = minimalCheckRequest("198.51.100.42")

	verdict, err = ctrl.Match(ctx, request, nil)
	requireNoErr(t, err)
	if verdict.IsMatch {
		t.Fatalf("expected to miss IP, got: %s", verdict.Description)
	}
}

// --- helpers ---

func startRedis(t *testing.T, ctx context.Context) (testcontainers.Container, string, int) {
	t.Helper()

	req := testcontainers.ContainerRequest{
		Image:        "redis:7-alpine",
		ExposedPorts: []string{"6379/tcp"},
		WaitingFor:   wait.ForLog("Ready to accept connections"),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	requireNoErr(t, err)

	endpoint, err := container.Endpoint(ctx, "")
	requireNoErr(t, err)
	host, portStr, err := net.SplitHostPort(endpoint)
	requireNoErr(t, err)
	port, err := strconv.Atoi(portStr)
	requireNoErr(t, err)

	return container, host, port
}

func startPostgres(t *testing.T, ctx context.Context) (testcontainers.Container, string, int) {
	t.Helper()

	req := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_PASSWORD": "postgres",
			"POSTGRES_USER":     "postgres",
			"POSTGRES_DB":       "security",
		},
		WaitingFor: wait.ForAll(
			wait.ForListeningPort("5432/tcp"),
			wait.ForLog("database system is ready to accept connections"),
		).WithDeadline(2 * time.Minute),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	requireNoErr(t, err)

	endpoint, err := container.Endpoint(ctx, "")
	requireNoErr(t, err)
	host, portStr, err := net.SplitHostPort(endpoint)
	requireNoErr(t, err)
	port, err := strconv.Atoi(portStr)
	requireNoErr(t, err)

	return container, host, port
}

func startSQLServer(t *testing.T, ctx context.Context) (testcontainers.Container, string, int) {
	t.Helper()

	req := testcontainers.ContainerRequest{
		Image:        "mcr.microsoft.com/mssql/server:2022-latest",
		ExposedPorts: []string{"1433/tcp"},
		Env: map[string]string{
			"ACCEPT_EULA":       "Y",
			"MSSQL_SA_PASSWORD": "sqlServer_P4ssword!",
			"MSSQL_PID":         "Developer",
		},
		WaitingFor: wait.ForAll(
			wait.ForListeningPort("1433/tcp"),
			wait.ForLog("SQL Server is now ready for client connections"),
		).WithDeadline(4 * time.Minute),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	requireNoErr(t, err)

	endpoint, err := container.Endpoint(ctx, "")
	requireNoErr(t, err)
	host, portStr, err := net.SplitHostPort(endpoint)
	requireNoErr(t, err)
	port, err := strconv.Atoi(portStr)
	requireNoErr(t, err)

	return container, host, port
}

func minimalCheckRequest(ip string) *authv3.CheckRequest {
	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Source: &authv3.AttributeContext_Peer{
				Address: &corev3.Address{
					Address: &corev3.Address_SocketAddress{
						SocketAddress: &corev3.SocketAddress{
							Address: ip,
						},
					},
				},
			},
		},
	}
}

func buildController(t *testing.T, ctx context.Context, logger *zap.Logger, cfg config.ControllerConfig) controller.MatchController {
	t.Helper()

	controllers, err := controller.BuildMatchControllers(ctx, logger.Named("controller"), []config.ControllerConfig{cfg})
	requireNoErr(t, err)
	if len(controllers) != 1 {
		t.Fatalf("expected 1 controller, got %d", len(controllers))
	}
	return controllers[0]
}

func requireNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
