//go:build e2e
// +build e2e

package ip_match_database

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/jackc/pgx/v5"
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
		WaitingFor: wait.ForListeningPort("5432/tcp").
			WithStartupTimeout(2 * time.Minute),
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
