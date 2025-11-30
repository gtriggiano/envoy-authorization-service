//go:build e2e
// +build e2e

package service

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap/zaptest"
	"google.golang.org/grpc/codes"

	// Register controller types under test
	_ "github.com/gtriggiano/envoy-authorization-service/pkg/match/ip_match_database"

	"github.com/gtriggiano/envoy-authorization-service/pkg/config"
	"github.com/gtriggiano/envoy-authorization-service/pkg/controller"
	"github.com/gtriggiano/envoy-authorization-service/pkg/metrics"
	"github.com/gtriggiano/envoy-authorization-service/pkg/policy"
	"github.com/gtriggiano/envoy-authorization-service/pkg/runtime"
)

func TestManagerWithRedisController(t *testing.T) {
	ctx := context.Background()
	container, host, port := startRedis(t, ctx)
	defer func() { _ = container.Terminate(ctx) }()

	seedRedis(t, ctx, host, port, "block:203.0.113.10", "1")

	authControllers, policyExpr := buildIPMatchDatabaseControllers(t, ctx, config.ControllerConfig{
		Name: "ip-db-redis",
		Type: "ip-match-database",
		Settings: map[string]any{
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

	allow := runManagerCheck(t, ctx, authControllers, fmt.Sprintf("!%s", policyExpr), "198.51.100.42")
	if !allow {
		t.Fatalf("expected allow for IP not in redis block key")
	}

	allow = runManagerCheck(t, ctx, authControllers, fmt.Sprintf("!%s", policyExpr), "203.0.113.10")
	if allow {
		t.Fatalf("expected deny for redis-blocked IP")
	}
}

func TestManagerWithPostgresController(t *testing.T) {
	ctx := context.Background()
	container, host, port := startPostgres(t, ctx)
	defer func() { _ = container.Terminate(ctx) }()

	seedPostgresAllowlist(t, ctx, host, port, "203.0.113.10")

	t.Setenv("POSTGRES_USER", "postgres")
	t.Setenv("POSTGRES_PASSWORD", "postgres")

	authControllers, policyExpr := buildIPMatchDatabaseControllers(t, ctx, config.ControllerConfig{
		Name: "ip-db-postgres",
		Type: "ip-match-database",
		Settings: map[string]any{
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
				},
			},
		},
	})

	allow := runManagerCheck(t, ctx, authControllers, policyExpr, "203.0.113.10")
	if !allow {
		t.Fatalf("expected allow for trusted postgres IP")
	}

	deny := runManagerCheck(t, ctx, authControllers, policyExpr, "198.51.100.42")
	if deny {
		t.Fatalf("expected deny for unknown postgres IP")
	}
}

// --- helpers ---

func buildIPMatchDatabaseControllers(t *testing.T, ctx context.Context, cfg config.ControllerConfig) ([]controller.MatchController, string) {
	t.Helper()

	controllers, err := controller.BuildMatchControllers(ctx, zaptest.NewLogger(t), []config.ControllerConfig{cfg})
	requireNoErr(t, err)
	if len(controllers) != 1 {
		t.Fatalf("expected 1 controller, got %d", len(controllers))
	}
	return controllers, cfg.Name
}

func runManagerCheck(t *testing.T, ctx context.Context, authControllers []controller.MatchController, policyExpr, ip string) bool {
	t.Helper()

	inst := metrics.NewInstrumentation(prometheus.NewRegistry())
	pol, err := policy.Parse(policyExpr, []string{authControllers[0].Name()})
	requireNoErr(t, err)

	mgr := NewManager(nil, authControllers, inst, pol, false, zaptest.NewLogger(t))

	req := runtime.NewRequestContext(minimalCheckRequest(ip))
	resp, err := mgr.Check(ctx, req.Request)
	requireNoErr(t, err)
	return resp.GetStatus().GetCode() == int32(codes.OK)
}

func seedRedis(t *testing.T, ctx context.Context, host string, port int, key, value string) {
	t.Helper()
	client := redis.NewClient(&redis.Options{
		Addr: fmt.Sprintf("%s:%d", host, port),
		DB:   0,
	})
	requireNoErr(t, client.Set(ctx, key, value, 0).Err())
}

func seedPostgresAllowlist(t *testing.T, ctx context.Context, host string, port int, ip string) {
	t.Helper()
	dsn := fmt.Sprintf("postgres://postgres:postgres@%s:%d/security?sslmode=disable", host, port)
	conn, err := pgx.Connect(ctx, dsn)
	requireNoErr(t, err)
	t.Cleanup(func() { _ = conn.Close(ctx) })

	_, err = conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS trusted_ips (ip inet PRIMARY KEY);`)
	requireNoErr(t, err)

	_, err = conn.Exec(ctx, `INSERT INTO trusted_ips (ip) VALUES ($1) ON CONFLICT DO NOTHING;`, ip)
	requireNoErr(t, err)
}

func startRedis(t *testing.T, ctx context.Context) (testcontainers.Container, string, int) {
	t.Helper()
	req := testcontainers.ContainerRequest{
		Image:        "redis:7-alpine",
		ExposedPorts: []string{"6379/tcp"},
		WaitingFor:   wait.ForLog("Ready to accept connections"),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{ContainerRequest: req, Started: true})
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
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{ContainerRequest: req, Started: true})
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

func requireNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
