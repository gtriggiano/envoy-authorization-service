//go:build e2e

package ip_match_database

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap/zaptest"

	"github.com/gtriggiano/envoy-authorization-service/pkg/config"
	"github.com/gtriggiano/envoy-authorization-service/pkg/controller"
	"github.com/gtriggiano/envoy-authorization-service/pkg/runtime"
)

// Paths inside the container, fixed by tcpostgres.WithSSLCert.
const (
	pgContainerCA   = "/tmp/testcontainers-go/postgres/ca_cert.pem"
	pgContainerCert = "/tmp/testcontainers-go/postgres/server.cert"
	pgContainerKey  = "/tmp/testcontainers-go/postgres/server.key"
)

// pgTLSInitScript seeds the tables and rewrites pg_hba.conf so that plaintext TCP
// connections are rejected and the "security_mtls" database requires a client
// certificate signed by the server CA. It runs against the temporary server the
// image starts during initialisation; the final server reads the new pg_hba.conf.
const pgTLSInitScript = `#!/bin/sh
set -e
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
CREATE TABLE trusted_ips (ip inet PRIMARY KEY);
INSERT INTO trusted_ips (ip) VALUES ('203.0.113.10');
CREATE DATABASE security_mtls;
SQL
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname security_mtls <<'SQL'
CREATE TABLE trusted_ips (ip inet PRIMARY KEY);
INSERT INTO trusted_ips (ip) VALUES ('203.0.113.10');
SQL
{
  echo "hostnossl all all all reject"
  echo "hostssl security_mtls all all scram-sha-256 clientcert=verify-ca"
  cat "$PGDATA/pg_hba.conf"
} > "$PGDATA/pg_hba.conf.new"
mv "$PGDATA/pg_hba.conf.new" "$PGDATA/pg_hba.conf"
`

func TestPostgresIpMatchDatabaseTLS(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	dir := t.TempDir()

	ca := newTestCA(t, dir, "ca")
	otherCA := newTestCA(t, dir, "other-ca")

	// The server certificate must name the host the client connects to for verify-full.
	// One loopback name is deliberately left out of the SANs to exercise the host name check.
	daemonHost := dockerDaemonHost(t, ctx)
	unnamedHost := "127.0.0.1"
	if daemonHost == unnamedHost {
		unnamedHost = "localhost"
	}
	var dnsNames []string
	var ips []net.IP
	if ip := net.ParseIP(daemonHost); ip != nil {
		ips = append(ips, ip)
	} else {
		dnsNames = append(dnsNames, daemonHost)
	}
	serverCert, serverKey := ca.issue(t, dir, "server", dnsNames, ips, false)
	clientCert, clientKey := ca.issue(t, dir, "client", nil, nil, true)

	initScript := filepath.Join(dir, "01-tls.sh")
	requireNoErr(t, os.WriteFile(initScript, []byte(pgTLSInitScript), 0o755))

	container, host, port := startPostgresTLS(t, ctx, ca.CertPath, serverCert, serverKey, initScript)
	defer func() { _ = container.Terminate(ctx) }()

	logger := zaptest.NewLogger(t)
	controllerConfigFor := func(connectHost, database string, tls map[string]any) config.ControllerConfig {
		return config.ControllerConfig{
			Name: "ip-db-postgres-tls",
			Type: ControllerKind,
			Settings: map[string]any{
				"database": map[string]any{
					"type":              "postgres",
					"connectionTimeout": "10s",
					"postgres": map[string]any{
						"query":        "SELECT 1 FROM trusted_ips WHERE ip = $1 LIMIT 1",
						"host":         connectHost,
						"port":         port,
						"databaseName": database,
						"username":     "postgres",
						"password":     "postgres",
						"tls":          tls,
					},
				},
			},
		}
	}
	// Controllers release their pool when the build context is cancelled.
	controllerConfig := func(database string, tls map[string]any) config.ControllerConfig {
		return controllerConfigFor(host, database, tls)
	}
	build := func(t *testing.T, cfg config.ControllerConfig) (controller.MatchController, error) {
		t.Helper()
		buildCtx, cancel := context.WithCancel(ctx)
		t.Cleanup(cancel)
		controllers, err := controller.BuildMatchControllers(buildCtx, logger.Named("controller"), []config.ControllerConfig{cfg})
		if err != nil {
			return nil, err
		}
		return controllers[0], nil
	}
	assertLookups := func(t *testing.T, ctrl controller.MatchController) {
		t.Helper()
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
	// assertRefused expects the controller build to fail with an error that mentions one of the given fragments.
	assertRefused := func(t *testing.T, cfg config.ControllerConfig, wantAny ...string) {
		t.Helper()
		_, err := build(t, cfg)
		if err == nil {
			t.Fatal("expected the connection to be refused")
		}
		for _, want := range wantAny {
			if strings.Contains(err.Error(), want) {
				return
			}
		}
		t.Fatalf("expected error mentioning one of %q, got: %v", wantAny, err)
	}

	t.Run("verify-full with the server CA", func(t *testing.T) {
		ctrl, err := build(t, controllerConfig("security", map[string]any{"mode": "verify-full", "caCert": ca.CertPath}))
		requireNoErr(t, err)
		assertLookups(t, ctrl)
	})

	t.Run("verify-ca with the server CA", func(t *testing.T) {
		ctrl, err := build(t, controllerConfig("security", map[string]any{"mode": "verify-ca", "caCert": ca.CertPath}))
		requireNoErr(t, err)
		assertLookups(t, ctrl)
	})

	t.Run("require without a CA", func(t *testing.T) {
		ctrl, err := build(t, controllerConfig("security", map[string]any{"mode": "require"}))
		requireNoErr(t, err)
		assertLookups(t, ctrl)
	})

	t.Run("prefer negotiates TLS when the server offers it", func(t *testing.T) {
		ctrl, err := build(t, controllerConfig("security", map[string]any{}))
		requireNoErr(t, err)
		assertLookups(t, ctrl)
	})

	t.Run("verify-full with an unrelated CA is refused", func(t *testing.T) {
		assertRefused(t, controllerConfig("security", map[string]any{"mode": "verify-full", "caCert": otherCA.CertPath}), "certificate signed by unknown authority")
	})

	t.Run("verify-ca with an unrelated CA is refused", func(t *testing.T) {
		assertRefused(t, controllerConfig("security", map[string]any{"mode": "verify-ca", "caCert": otherCA.CertPath}), "certificate signed by unknown authority")
	})

	t.Run("verify-full refuses a host the certificate does not name", func(t *testing.T) {
		if !isLoopback(daemonHost) {
			t.Skipf("docker host %s is not loopback, %s may not reach the container", daemonHost, unnamedHost)
		}
		// Same server, reached under a name missing from the certificate SANs:
		// verify-ca still accepts the chain, verify-full does not.
		ctrl, err := build(t, controllerConfigFor(unnamedHost, "security", map[string]any{"mode": "verify-ca", "caCert": ca.CertPath}))
		requireNoErr(t, err)
		assertLookups(t, ctrl)

		assertRefused(t, controllerConfigFor(unnamedHost, "security", map[string]any{"mode": "verify-full", "caCert": ca.CertPath}),
			"certificate is valid for", "doesn't contain any IP SANs")
	})

	t.Run("disable is rejected by a TLS-only server", func(t *testing.T) {
		assertRefused(t, controllerConfig("security", map[string]any{"mode": "disable"}), "pg_hba.conf")
	})

	t.Run("mutual TLS with a client certificate", func(t *testing.T) {
		ctrl, err := build(t, controllerConfig("security_mtls", map[string]any{
			"mode":       "verify-full",
			"caCert":     ca.CertPath,
			"clientCert": clientCert,
			"clientKey":  clientKey,
		}))
		requireNoErr(t, err)
		assertLookups(t, ctrl)
	})

	t.Run("mutual TLS without a client certificate is refused", func(t *testing.T) {
		assertRefused(t, controllerConfig("security_mtls", map[string]any{"mode": "verify-full", "caCert": ca.CertPath}), "client certificate")
	})
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// dockerDaemonHost returns the host name testcontainers will hand out for container endpoints.
func dockerDaemonHost(t *testing.T, ctx context.Context) string {
	t.Helper()
	provider, err := testcontainers.NewDockerProvider()
	requireNoErr(t, err)
	defer provider.Close()
	host, err := provider.DaemonHost(ctx)
	requireNoErr(t, err)
	return host
}

// startPostgresTLS runs PostgreSQL with server TLS enabled, the given CA as the
// client-certificate authority, and the init script applied during first start.
func startPostgresTLS(t *testing.T, ctx context.Context, caCert, serverCert, serverKey, initScript string) (testcontainers.Container, string, int) {
	t.Helper()

	container, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("security"),
		tcpostgres.WithUsername("postgres"),
		tcpostgres.WithPassword("postgres"),
		tcpostgres.WithSSLCert(caCert, serverCert, serverKey),
		tcpostgres.WithInitScripts(initScript),
		testcontainers.WithCmdArgs(
			"-c", "ssl=on",
			"-c", "ssl_ca_file="+pgContainerCA,
			"-c", "ssl_cert_file="+pgContainerCert,
			"-c", "ssl_key_file="+pgContainerKey,
		),
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
