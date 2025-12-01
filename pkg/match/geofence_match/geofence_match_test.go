package geofence_match

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"

	"github.com/gtriggiano/envoy-authorization-service/pkg/analysis/maxmind_geoip"
	"github.com/gtriggiano/envoy-authorization-service/pkg/config"
	"github.com/gtriggiano/envoy-authorization-service/pkg/controller"
	"github.com/gtriggiano/envoy-authorization-service/pkg/runtime"
)

// Sample polygon covering a rectangular area around Rome, Italy
const testPolygonsYAML = `polygons:
  - name: rome-area
    polygon:
      - [12.4, 41.8]  # SW
      - [12.6, 41.8]  # SE
      - [12.6, 42.0]  # NE
      - [12.4, 42.0]  # NW
      - [12.4, 41.8]  # Close the polygon
  - name: london-area
    polygon:
      - [-0.2, 51.4]  # SW
      - [0.0, 51.4]   # SE
      - [0.0, 51.6]   # NE
      - [-0.2, 51.6]  # NW
      - [-0.2, 51.4]  # Close the polygon
`

func TestGeofenceMatchController_Match(t *testing.T) {
	ctrl := createTestController(t, testPolygonsYAML)

	tests := []struct {
		name         string
		lat          float64
		lon          float64
		wantMatch    bool
		polygonCount int
	}{
		{"inside rome-area", 41.9, 12.5, true, 1},
		{"inside london-area", 51.5, -0.1, true, 1},
		{"outside all polygons", 45.0, 10.0, false, 0},
		{"on rome boundary", 41.8, 12.5, true, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verdict := matchCoords(t, ctrl, tt.lat, tt.lon)
			if verdict.IsMatch != tt.wantMatch {
				t.Fatalf("expected IsMatch=%v, got %v, description: %s", tt.wantMatch, verdict.IsMatch, verdict.Description)
			}
			if verdict.DenyCode != codes.PermissionDenied {
				t.Fatalf("expected DenyCode PermissionDenied, got %v", verdict.DenyCode)
			}
			if verdict.Description == "" {
				t.Fatal("expected description")
			}
			// Check that upstream headers are set correctly
			headerKey := "X-Geofence-" + ctrl.Name()
			if verdict.AllowUpstreamHeaders == nil {
				t.Fatal("expected AllowUpstreamHeaders to be set")
			}
			headerValue, ok := verdict.AllowUpstreamHeaders[headerKey]
			if !ok {
				t.Fatalf("expected header %s to be set", headerKey)
			}
			expectedHeaderValue := "true"
			if !tt.wantMatch {
				expectedHeaderValue = "false"
			}
			if headerValue != expectedHeaderValue {
				t.Fatalf("expected header value %s, got %s", expectedHeaderValue, headerValue)
			}
		})
	}
}

func TestGeofenceMatchController_NoGeoIPReport(t *testing.T) {
	ctrl := createTestController(t, testPolygonsYAML)
	req := runtime.NewRequestContext(minimalCheckRequest("198.51.100.1"))

	verdict, err := ctrl.Match(context.Background(), req, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.IsMatch {
		t.Fatal("expected no match without GeoIP report")
	}
	if verdict.Description != "no GeoIP information available" {
		t.Fatalf("unexpected description: %s", verdict.Description)
	}
}

func TestGeofenceMatchController_ZeroCoordinates(t *testing.T) {
	ctrl := createTestController(t, testPolygonsYAML)
	req := runtime.NewRequestContext(minimalCheckRequest("198.51.100.1"))

	reports := controller.AnalysisReports{
		"geoip": {
			ControllerKind: maxmind_geoip.ControllerKind,
			Data: map[string]any{
				"result": &maxmind_geoip.IpLookupResult{
					Latitude:  0,
					Longitude: 0,
				},
			},
		},
	}

	verdict, err := ctrl.Match(context.Background(), req, reports)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.IsMatch {
		t.Fatal("expected no match with zero coordinates")
	}
	if verdict.Description != "no valid coordinates in GeoIP data" {
		t.Fatalf("unexpected description: %s", verdict.Description)
	}
}

func TestGeofenceMatchController_Cache(t *testing.T) {
	ctrl := createTestController(t, testPolygonsYAML)
	lat := 41.9
	lon := 12.5

	verdict1 := matchCoords(t, ctrl, lat, lon)
	if !verdict1.IsMatch {
		t.Fatal("expected match on first call")
	}

	c := ctrl.(*geofenceMatchController)
	cacheKey := "41.900000,12.500000"
	c.cacheMu.RLock()
	if _, ok := c.cache[cacheKey]; !ok {
		t.Fatal("expected coordinates cached after first call")
	}
	c.cacheMu.RUnlock()

	verdict2 := matchCoords(t, ctrl, lat, lon)
	if verdict2.Description != verdict1.Description {
		t.Fatal("cache hit produced different verdict")
	}
}

func TestValidatePolygon_NotClosed(t *testing.T) {
	polygonYAML := `polygons:
  - name: not-closed
    polygon:
      - [12.4, 41.8]
      - [12.6, 41.8]
      - [12.6, 42.0]
      - [12.4, 42.0]
`
	_, err := createTestControllerWithError(t, polygonYAML)
	if err == nil {
		t.Fatal("expected error for non-closed polygon")
	}
}

func TestValidatePolygon_TooFewPoints(t *testing.T) {
	polygonYAML := `polygons:
  - name: too-few
    polygon:
      - [12.4, 41.8]
      - [12.6, 41.8]
      - [12.4, 41.8]
`
	_, err := createTestControllerWithError(t, polygonYAML)
	if err == nil {
		t.Fatal("expected error for polygon with too few points")
	}
}

func TestValidatePolygon_InvalidLatitude(t *testing.T) {
	polygonYAML := `polygons:
  - name: invalid-lat
    polygon:
      - [12.4, 91.0]
      - [12.6, 41.8]
      - [12.6, 42.0]
      - [12.4, 42.0]
      - [12.4, 91.0]
`
	_, err := createTestControllerWithError(t, polygonYAML)
	if err == nil {
		t.Fatal("expected error for invalid latitude")
	}
}

func TestValidatePolygon_InvalidLongitude(t *testing.T) {
	polygonYAML := `polygons:
  - name: invalid-lon
    polygon:
      - [181.0, 41.8]
      - [12.6, 41.8]
      - [12.6, 42.0]
      - [12.4, 42.0]
      - [181.0, 41.8]
`
	_, err := createTestControllerWithError(t, polygonYAML)
	if err == nil {
		t.Fatal("expected error for invalid longitude")
	}
}

func TestValidatePolygon_DuplicateName(t *testing.T) {
	polygonYAML := `polygons:
  - name: same-name
    polygon:
      - [12.4, 41.8]
      - [12.6, 41.8]
      - [12.6, 42.0]
      - [12.4, 42.0]
      - [12.4, 41.8]
  - name: same-name
    polygon:
      - [0.0, 0.0]
      - [1.0, 0.0]
      - [1.0, 1.0]
      - [0.0, 1.0]
      - [0.0, 0.0]
`
	_, err := createTestControllerWithError(t, polygonYAML)
	if err == nil {
		t.Fatal("expected error for duplicate polygon name")
	}
}

func TestValidatePolygon_MissingName(t *testing.T) {
	polygonYAML := `polygons:
  - name: ""
    polygon:
      - [12.4, 41.8]
      - [12.6, 41.8]
      - [12.6, 42.0]
      - [12.4, 42.0]
      - [12.4, 41.8]
`
	_, err := createTestControllerWithError(t, polygonYAML)
	if err == nil {
		t.Fatal("expected error for missing polygon name")
	}
}

func TestValidatePolygon_EmptyFile(t *testing.T) {
	polygonYAML := `polygons: []`
	_, err := createTestControllerWithError(t, polygonYAML)
	if err == nil {
		t.Fatal("expected error for empty polygons")
	}
}

func TestValidatePolygon_InvalidCoordinateFormat(t *testing.T) {
	polygonYAML := `polygons:
  - name: wrong-format
    polygon:
      - [12.4]
      - [12.6, 41.8]
      - [12.6, 42.0]
      - [12.4, 42.0]
      - [12.4]
`
	_, err := createTestControllerWithError(t, polygonYAML)
	if err == nil {
		t.Fatal("expected error for invalid coordinate format")
	}
}

func TestNewGeofenceMatchController_MissingPolygonsFile(t *testing.T) {
	cfg := config.ControllerConfig{
		Name: "test",
		Type: ControllerKind,
		Settings: map[string]any{
			"polygonsFile": "",
		},
	}
	_, err := newGeofenceMatchController(context.Background(), zap.NewNop(), cfg)
	if err == nil {
		t.Fatal("expected error for missing polygonsFile")
	}
}

func TestNewGeofenceMatchController_InvalidPath(t *testing.T) {
	cfg := config.ControllerConfig{
		Name: "test",
		Type: ControllerKind,
		Settings: map[string]any{
			"polygonsFile": "/does/not/exist",
		},
	}
	_, err := newGeofenceMatchController(context.Background(), zap.NewNop(), cfg)
	if err == nil {
		t.Fatal("expected error for invalid polygonsFile path")
	}
}

func TestGeofenceMatchController_MultiplePolygonMatch(t *testing.T) {
	// Create overlapping polygons
	overlappingPolygonsYAML := `polygons:
  - name: zone-a
    polygon:
      - [10.0, 40.0]
      - [15.0, 40.0]
      - [15.0, 45.0]
      - [10.0, 45.0]
      - [10.0, 40.0]
  - name: zone-b
    polygon:
      - [12.0, 42.0]
      - [17.0, 42.0]
      - [17.0, 47.0]
      - [12.0, 47.0]
      - [12.0, 42.0]
`
	ctrl := createTestController(t, overlappingPolygonsYAML)

	// Point inside both zones
	verdict := matchCoords(t, ctrl, 43.0, 13.0)
	if !verdict.IsMatch {
		t.Fatal("expected match")
	}

	// Check that both polygon names are in the header
	polygonsHeader := verdict.AllowUpstreamHeaders["X-Geofence-"+ctrl.Name()+"-Polygons"]
	if polygonsHeader == "" {
		t.Fatal("expected polygons header to be set")
	}
	// Both zone-a and zone-b should be present
	if !containsAll(polygonsHeader, []string{"zone-a", "zone-b"}) {
		t.Fatalf("expected both zone-a and zone-b in header, got: %s", polygonsHeader)
	}
}

func TestGeofenceMatchController_ControllerMetadata(t *testing.T) {
	ctrl := createTestController(t, testPolygonsYAML)

	if ctrl.Name() != "geofence-test" {
		t.Fatalf("expected name 'geofence-test', got '%s'", ctrl.Name())
	}

	if ctrl.Kind() != ControllerKind {
		t.Fatalf("expected kind '%s', got '%s'", ControllerKind, ctrl.Kind())
	}

	if err := ctrl.HealthCheck(context.Background()); err != nil {
		t.Fatalf("unexpected health check error: %v", err)
	}
}

// helpers

func createTestController(t *testing.T, polygonsYAML string) controller.MatchController {
	t.Helper()
	ctrl, err := createTestControllerWithError(t, polygonsYAML)
	if err != nil {
		t.Fatalf("failed to create controller: %v", err)
	}
	return ctrl
}

func createTestControllerWithError(t *testing.T, polygonsYAML string) (controller.MatchController, error) {
	t.Helper()
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "polygons.yaml")
	if err := os.WriteFile(path, []byte(polygonsYAML), 0o644); err != nil {
		t.Fatalf("failed to write polygons file: %v", err)
	}
	cfg := config.ControllerConfig{
		Name: "geofence-test",
		Type: ControllerKind,
		Settings: map[string]any{
			"polygonsFile": path,
		},
	}
	return newGeofenceMatchController(context.Background(), zap.NewNop(), cfg)
}

func matchCoords(t *testing.T, ctrl controller.MatchController, lat, lon float64) *controller.MatchVerdict {
	t.Helper()
	req := runtime.NewRequestContext(minimalCheckRequest("198.51.100.1"))
	reports := controller.AnalysisReports{
		"geoip": {
			ControllerKind: maxmind_geoip.ControllerKind,
			Data: map[string]any{
				"result": &maxmind_geoip.IpLookupResult{
					Latitude:  lat,
					Longitude: lon,
				},
			},
		},
	}
	verdict, err := ctrl.Match(context.Background(), req, reports)
	if err != nil {
		t.Fatalf("match returned error: %v", err)
	}
	return verdict
}

func minimalCheckRequest(ip string) *authv3.CheckRequest {
	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Source: &authv3.AttributeContext_Peer{
				Address: &corev3.Address{
					Address: &corev3.Address_SocketAddress{
						SocketAddress: &corev3.SocketAddress{
							Address:       ip,
							PortSpecifier: &corev3.SocketAddress_PortValue{PortValue: 80},
						},
					},
				},
			},
		},
	}
}

func containsAll(s string, items []string) bool {
	parts := strings.Split(s, ",")
	for _, item := range items {
		found := false
		for _, part := range parts {
			if part == item {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
