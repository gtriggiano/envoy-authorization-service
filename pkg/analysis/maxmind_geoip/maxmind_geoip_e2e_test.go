//go:build e2e
// +build e2e

package maxmind_geoip

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap/zaptest"
	"google.golang.org/grpc/codes"

	"github.com/gtriggiano/envoy-authorization-service/pkg/config"
	"github.com/gtriggiano/envoy-authorization-service/pkg/controller"
	"github.com/gtriggiano/envoy-authorization-service/pkg/metrics"
	"github.com/gtriggiano/envoy-authorization-service/pkg/runtime"
	"github.com/gtriggiano/envoy-authorization-service/pkg/service"
)

func TestMaxMindGeoIPHeaders(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join("config", "GeoLite2-City.mmdb")
	if _, err := os.Stat(dbPath); err != nil {
		t.Skipf("GeoIP database not present at %s", dbPath)
	}

	ctx := context.Background()
	logger := zaptest.NewLogger(t)

	analysisCfg := config.ControllerConfig{
		Name: "geoip-detect",
		Type: ControllerKind,
		Settings: map[string]any{
			"databasePath": dbPath,
		},
	}

	analysisControllers, err := controller.BuildAnalysisControllers(ctx, logger.Named("analysis"), []config.ControllerConfig{analysisCfg})
	requireNoErr(t, err)

	inst := metrics.NewInstrumentation(prometheus.NewRegistry(), metrics.TrackOptions{TrackCountry: false, TrackGeofence: true})
	mgr := service.NewManager(analysisControllers, nil, inst, nil, false, logger)

	ip := "8.8.8.8"
	req := runtime.NewRequestContext(minimalCheckRequest(ip))
	resp, err := mgr.Check(ctx, req.Request)
	requireNoErr(t, err)

	if resp.GetStatus().GetCode() != int32(codes.OK) {
		t.Fatalf("expected OK status, got %v", resp.GetStatus())
	}

	headers := headersToMap(resp.GetOkResponse().GetHeaders())
	required := []string{
		"x-geoip-countryiso",
		"x-geoip-country",
		"x-geoip-latitude",
		"x-geoip-longitude",
	}
	for _, h := range required {
		if v := headers[h]; v == "" {
			t.Fatalf("expected header %s to be populated", h)
		}
	}
}

// --- helpers ---

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

func headersToMap(h []*corev3.HeaderValueOption) map[string]string {
	out := make(map[string]string, len(h))
	for _, hv := range h {
		if hv.GetHeader() == nil {
			continue
		}
		out[strings.ToLower(hv.GetHeader().GetKey())] = hv.GetHeader().GetValue()
	}
	return out
}

func requireNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
