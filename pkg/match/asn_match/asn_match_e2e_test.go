//go:build e2e
// +build e2e

package asn_match

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	"google.golang.org/grpc/codes"

	// Register analysis controller under test
	_ "github.com/gtriggiano/envoy-authorization-service/pkg/analysis/maxmind_asn"

	"github.com/gtriggiano/envoy-authorization-service/pkg/config"
	"github.com/gtriggiano/envoy-authorization-service/pkg/controller"
	"github.com/gtriggiano/envoy-authorization-service/pkg/metrics"
	"github.com/gtriggiano/envoy-authorization-service/pkg/policy"
	"github.com/gtriggiano/envoy-authorization-service/pkg/service"
)

func TestASNMatchAllowList(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logger := zaptest.NewLogger(t)

	asnListPath := writeASNList(t, []string{"AS 13335"})

	mgr := buildManager(t, ctx, logger, config.ControllerConfig{
		Name: "asn-allow",
		Type: ControllerKind,
		Settings: map[string]any{
			"asnList": asnListPath,
			"action":  "allow",
		},
	})

	allow := runCheck(t, mgr, "1.1.1.1") // AS13335 (Cloudflare)
	deny := runCheck(t, mgr, "8.8.8.8")  // AS15169 (Google)

	if !allow {
		t.Fatalf("expected allow for AS13335")
	}
	if deny {
		t.Fatalf("expected deny for non-allowlisted ASN")
	}
}

func TestASNMatchDenyList(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logger := zaptest.NewLogger(t)

	asnListPath := writeASNList(t, []string{"AS 13335"})

	mgr := buildManager(t, ctx, logger, config.ControllerConfig{
		Name: "asn-deny",
		Type: ControllerKind,
		Settings: map[string]any{
			"asnList": asnListPath,
			"action":  "deny",
		},
	})

	deny := runCheck(t, mgr, "1.1.1.1")  // AS13335
	allow := runCheck(t, mgr, "8.8.8.8") // AS15169

	if !deny {
		t.Fatalf("expected deny for deny-listed ASN")
	}
	if !allow {
		t.Fatalf("expected allow for ASN not in deny list")
	}
}

// --- helpers ---

func buildManager(t *testing.T, ctx context.Context, logger *zap.Logger, authCfg config.ControllerConfig) *service.Manager {
	t.Helper()

	dbPath := filepath.Join("config", "GeoLite2-ASN.mmdb")
	if _, err := os.Stat(dbPath); err != nil {
		t.Skipf("ASN database not present at %s", dbPath)
	}

	analysisCfgs := []config.ControllerConfig{
		{
			Name: "asn-detect",
			Type: "maxmind-asn",
			Settings: map[string]any{
				"databasePath": dbPath,
			},
		},
	}

	analysisControllers, err := controller.BuildAnalysisControllers(ctx, logger.Named("analysis"), analysisCfgs)
	requireNoErr(t, err)

	authControllers, err := controller.BuildMatchControllers(ctx, logger.Named("auth"), []config.ControllerConfig{authCfg})
	requireNoErr(t, err)

	inst := metrics.NewInstrumentation(prometheus.NewRegistry(), metrics.TrackOptions{TrackCountry: false, TrackGeofence: true})
	pol, err := policy.Parse(authCfg.Name, []string{authCfg.Name})
	requireNoErr(t, err)

	return service.NewManager(analysisControllers, authControllers, inst, pol, false, logger)
}

func runCheck(t *testing.T, mgr *service.Manager, ip string) bool {
	t.Helper()
	req := minimalCheckRequest(ip)
	resp, err := mgr.Check(context.Background(), req)
	requireNoErr(t, err)
	return resp.GetStatus().GetCode() == int32(codes.OK)
}

func writeASNList(t *testing.T, lines []string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "asn-list.txt")
	data := ""
	for _, l := range lines {
		data += l + "\n"
	}
	requireNoErr(t, os.WriteFile(path, []byte(data), 0o644))
	return path
}

func requireNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
