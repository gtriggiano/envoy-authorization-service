//go:build e2e

package asn_match_database

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	"github.com/gtriggiano/envoy-authorization-service/pkg/config"
	"github.com/gtriggiano/envoy-authorization-service/pkg/controller"
	"github.com/gtriggiano/envoy-authorization-service/pkg/runtime"
)

func TestRedisAsnMatchDatabase(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	container, host, port := startRedis(t, ctx)
	defer func() { _ = container.Terminate(ctx) }()

	client := redis.NewClient(&redis.Options{
		Addr: fmt.Sprintf("%s:%d", host, port),
		DB:   0,
	})
	requireNoErr(t, client.Set(ctx, "asn:block:13335", "1", 0).Err())

	logger := zaptest.NewLogger(t)
	ctrl := buildController(t, ctx, logger, config.ControllerConfig{
		Name: "asn-db-redis",
		Type: ControllerKind,
		Settings: map[string]any{
			"cache": map[string]any{
				"ttl": "1m",
			},
			"database": map[string]any{
				"type": "redis",
				"redis": map[string]any{
					"keyPrefix": "asn:block:",
					"host":      host,
					"port":      port,
					"db":        0,
				},
			},
		},
	})

	request := runtime.NewRequestContext(minimalCheckRequest("203.0.113.10"))
	request.ReceivedAt = time.Now()

	verdict, err := ctrl.Match(ctx, request, asnReports(13335))
	requireNoErr(t, err)
	if !verdict.IsMatch {
		t.Fatalf("expected to match ASN, got: %s", verdict.Description)
	}

	request.Request = minimalCheckRequest("198.51.100.42")
	verdict, err = ctrl.Match(ctx, request, asnReports(15169))
	requireNoErr(t, err)
	if verdict.IsMatch {
		t.Fatalf("expected to miss ASN, got: %s", verdict.Description)
	}
}

func TestPostgresAsnMatchDatabase(t *testing.T) {
	t.Parallel()

	// Use test-unique env var names so parallel tests cannot clobber each
	// other's credentials. t.Setenv is incompatible with t.Parallel, so we
	// manage the env directly with a Cleanup to restore prior state.
	userEnv := "ASN_PG_USER_" + sanitizeEnvName(t.Name())
	passEnv := "ASN_PG_PASS_" + sanitizeEnvName(t.Name())
	setEnvForTest(t, userEnv, "postgres")
	setEnvForTest(t, passEnv, "postgres")

	ctx := context.Background()
	container, host, port := startPostgres(t, ctx)
	defer func() { _ = container.Terminate(ctx) }()

	dsn := fmt.Sprintf("postgres://postgres:postgres@%s:%d/security?sslmode=disable", host, port)
	conn, err := pgx.Connect(ctx, dsn)
	requireNoErr(t, err)
	t.Cleanup(func() { _ = conn.Close(ctx) })

	_, err = conn.Exec(ctx, `
        CREATE TABLE IF NOT EXISTS trusted_asns (asn bigint PRIMARY KEY);
        INSERT INTO trusted_asns (asn) VALUES (13335) ON CONFLICT DO NOTHING;
    `)
	requireNoErr(t, err)

	logger := zaptest.NewLogger(t)
	ctrl := buildController(t, ctx, logger, config.ControllerConfig{
		Name: "asn-db-postgres",
		Type: ControllerKind,
		Settings: map[string]any{
			"database": map[string]any{
				"type":              "postgres",
				"connectionTimeout": "1s",
				"postgres": map[string]any{
					"query":        "SELECT 1 FROM trusted_asns WHERE asn = $1 LIMIT 1",
					"host":         host,
					"port":         port,
					"databaseName": "security",
					"usernameEnv":  userEnv,
					"passwordEnv":  passEnv,
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

	request := runtime.NewRequestContext(minimalCheckRequest("203.0.113.10"))
	request.ReceivedAt = time.Now()

	verdict, err := ctrl.Match(ctx, request, asnReports(13335))
	requireNoErr(t, err)
	if !verdict.IsMatch {
		t.Fatalf("expected to match ASN, got: %s", verdict.Description)
	}

	request.Request = minimalCheckRequest("198.51.100.42")
	verdict, err = ctrl.Match(ctx, request, asnReports(15169))
	requireNoErr(t, err)
	if verdict.IsMatch {
		t.Fatalf("expected to miss ASN, got: %s", verdict.Description)
	}
}

// --- helpers ---

func startRedis(t *testing.T, ctx context.Context) (testcontainers.Container, string, int) {
	t.Helper()

	container, err := tcredis.Run(ctx, "redis:7-alpine")
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

	container, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("security"),
		tcpostgres.WithUsername("postgres"),
		tcpostgres.WithPassword("postgres"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(2*time.Minute),
			wait.ForExec([]string{"pg_isready", "-U", "postgres", "-d", "security"}).
				WithStartupTimeout(2*time.Minute),
		),
	)
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

// setEnvForTest sets an environment variable for the duration of the test and
// restores its prior value on cleanup. Unlike t.Setenv, it is safe to use with
// t.Parallel, provided the env var name is unique per test (so parallel tests
// do not race on the same key).
func setEnvForTest(t *testing.T, key, value string) {
	t.Helper()
	prev, hadPrev := os.LookupEnv(key)
	if err := os.Setenv(key, value); err != nil {
		t.Fatalf("os.Setenv(%q) failed: %v", key, err)
	}
	t.Cleanup(func() {
		if hadPrev {
			_ = os.Setenv(key, prev)
		} else {
			_ = os.Unsetenv(key)
		}
	})
}

// sanitizeEnvName maps a test name into a fragment that is valid in an env var.
func sanitizeEnvName(name string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r >= 'a' && r <= 'z':
			return r - ('a' - 'A')
		default:
			return '_'
		}
	}, name)
}
