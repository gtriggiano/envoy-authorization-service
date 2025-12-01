package geofence_match

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/paulmach/orb"
	"github.com/paulmach/orb/planar"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"gopkg.in/yaml.v3"

	"github.com/gtriggiano/envoy-authorization-service/pkg/analysis/maxmind_geoip"
	"github.com/gtriggiano/envoy-authorization-service/pkg/config"
	"github.com/gtriggiano/envoy-authorization-service/pkg/controller"
	"github.com/gtriggiano/envoy-authorization-service/pkg/runtime"
)

const (
	ControllerKind = "geofence-match"
)

// init registers the geofence-match match controller so it can be constructed
// from configuration at runtime.
func init() {
	controller.RegisterMatchContollerFactory(ControllerKind, newGeofenceMatchController)
}

// GeofenceMatchConfig holds the configuration for the geofence match controller.
type GeofenceMatchConfig struct {
	PolygonsFile string `yaml:"polygonsFile"`
}

// PolygonEntry represents a named polygon from the configuration file.
type PolygonEntry struct {
	Name    string      `yaml:"name"`
	Polygon [][]float64 `yaml:"polygon"`
}

// PolygonsFileContent represents the structure of the polygons file.
type PolygonsFileContent struct {
	Polygons []PolygonEntry `yaml:"polygons"`
}

// namedPolygon holds a validated polygon with its name.
type namedPolygon struct {
	name    string
	polygon orb.Polygon
}

type geofenceMatchController struct {
	name     string
	polygons []namedPolygon
	cache    map[string][]string // IP -> matched polygon names
	cacheMu  sync.RWMutex
	logger   *zap.Logger
}

// Match implements controller.MatchController.
func (c *geofenceMatchController) Match(ctx context.Context, req *runtime.RequestContext, reports controller.AnalysisReports) (*controller.MatchVerdict, error) {
	isMatch, description, matchedPolygons := c.deriveMatch(reports)

	allowUpstreamHeaders := map[string]string{
		fmt.Sprintf("X-Geofence-%s", c.name): fmt.Sprintf("%t", isMatch),
	}

	if isMatch && len(matchedPolygons) > 0 {
		allowUpstreamHeaders[fmt.Sprintf("X-Geofence-%s-Polygons", c.name)] = formatMatchedPolygonNames(matchedPolygons)
	}

	return &controller.MatchVerdict{
		Controller:           c.name,
		ControllerKind:       ControllerKind,
		DenyCode:             codes.PermissionDenied,
		Description:          description,
		IsMatch:              isMatch,
		AllowUpstreamHeaders: allowUpstreamHeaders,
	}, nil
}

// Name implements controller.MatchController.
func (c *geofenceMatchController) Name() string {
	return c.name
}

// Kind implements controller.MatchController.
func (c *geofenceMatchController) Kind() string {
	return ControllerKind
}

// HealthCheck implements controller.MatchController.
func (c *geofenceMatchController) HealthCheck(ctx context.Context) error {
	// No external dependencies to check
	return nil
}

// deriveMatch inspects analyzer reports, determines whether the coordinates
// fall within any configured polygon, and returns the result.
func (c *geofenceMatchController) deriveMatch(reports controller.AnalysisReports) (bool, string, []string) {
	var geoipResult *maxmind_geoip.IpLookupResult
	for _, report := range reports {
		if report == nil || report.ControllerKind != maxmind_geoip.ControllerKind {
			continue
		}
		geoipResult = maxmind_geoip.GetIpLookupResultFromReport(report)
	}

	if geoipResult == nil {
		return false, "no GeoIP information available", nil
	}

	// Check if coordinates are valid (not zero)
	if geoipResult.Latitude == 0 && geoipResult.Longitude == 0 {
		return false, "no valid coordinates in GeoIP data", nil
	}

	lat := geoipResult.Latitude
	lon := geoipResult.Longitude

	// Use a cache key based on lat/lon
	cacheKey := fmt.Sprintf("%.6f,%.6f", lat, lon)

	// Check cache
	c.cacheMu.RLock()
	if cachedPolygons, ok := c.cache[cacheKey]; ok {
		c.cacheMu.RUnlock()
		c.logger.Debug("cache hit for coordinates", zap.String("coords", cacheKey))
		if len(cachedPolygons) > 0 {
			return true, fmt.Sprintf("coordinates (%.4f, %.4f) matched %d polygon(s): %v", lat, lon, len(cachedPolygons), cachedPolygons), cachedPolygons
		}
		return false, fmt.Sprintf("coordinates (%.4f, %.4f) did not match any polygon", lat, lon), nil
	}
	c.cacheMu.RUnlock()

	// Cache miss - compute match
	c.logger.Debug("cache miss for coordinates", zap.String("coords", cacheKey))
	matchedPolygons := c.findContainingPolygons(lat, lon)

	// Store in cache
	c.cacheMu.Lock()
	c.cache[cacheKey] = matchedPolygons
	c.cacheMu.Unlock()

	if len(matchedPolygons) > 0 {
		return true, fmt.Sprintf("coordinates (%.4f, %.4f) matched %d polygon(s): %v", lat, lon, len(matchedPolygons), matchedPolygons), matchedPolygons
	}

	return false, fmt.Sprintf("coordinates (%.4f, %.4f) did not match any polygon", lat, lon), nil
}

// findContainingPolygons checks which polygons contain the given point.
func (c *geofenceMatchController) findContainingPolygons(lat, lon float64) []string {
	point := orb.Point{lon, lat} // orb uses [lon, lat] order
	var matched []string

	for _, np := range c.polygons {
		if planar.PolygonContains(np.polygon, point) {
			matched = append(matched, np.name)
		}
	}

	return matched
}

// formatMatchedPolygonNames joins polygon names with commas for the header.
func formatMatchedPolygonNames(names []string) string {
	result := ""
	for i, name := range names {
		if i > 0 {
			result += ","
		}
		result += name
	}
	return result
}

// newGeofenceMatchController constructs a match controller from
// configuration by loading and validating the polygons file.
func newGeofenceMatchController(_ context.Context, logger *zap.Logger, cfg config.ControllerConfig) (controller.MatchController, error) {
	var matchConfig GeofenceMatchConfig
	if err := controller.DecodeControllerSettings(cfg.Settings, &matchConfig); err != nil {
		return nil, err
	}

	if matchConfig.PolygonsFile == "" {
		return nil, fmt.Errorf("polygonsFile is required, check your configuration")
	}

	polygonsFilePath, err := filepath.Abs(matchConfig.PolygonsFile)
	if err != nil {
		return nil, fmt.Errorf("polygonsFile path is not valid: %w", err)
	}

	polygonsFileContent, err := os.ReadFile(polygonsFilePath)
	if err != nil {
		return nil, fmt.Errorf("could not read polygonsFile file: %w", err)
	}

	polygons, err := parseAndValidatePolygons(polygonsFileContent)
	if err != nil {
		return nil, fmt.Errorf("polygons validation failed: %w", err)
	}

	logger.Info("loaded geofence polygons", zap.Int("count", len(polygons)))

	return &geofenceMatchController{
		name:     cfg.Name,
		polygons: polygons,
		cache:    make(map[string][]string),
		logger:   logger,
	}, nil
}

// parseAndValidatePolygons parses the YAML file and validates all polygons.
func parseAndValidatePolygons(content []byte) ([]namedPolygon, error) {
	var fileContent PolygonsFileContent
	if err := yaml.Unmarshal(content, &fileContent); err != nil {
		return nil, fmt.Errorf("failed to parse polygons file: %w", err)
	}

	if len(fileContent.Polygons) == 0 {
		return nil, fmt.Errorf("polygons file must contain at least one polygon")
	}

	result := make([]namedPolygon, 0, len(fileContent.Polygons))
	seenNames := make(map[string]bool)

	for i, entry := range fileContent.Polygons {
		if entry.Name == "" {
			return nil, fmt.Errorf("polygon at index %d must have a name", i)
		}

		if seenNames[entry.Name] {
			return nil, fmt.Errorf("duplicate polygon name: %s", entry.Name)
		}
		seenNames[entry.Name] = true

		polygon, err := validatePolygon(entry.Name, entry.Polygon)
		if err != nil {
			return nil, err
		}

		result = append(result, namedPolygon{
			name:    entry.Name,
			polygon: polygon,
		})
	}

	return result, nil
}

// validatePolygon validates a polygon definition and returns an orb.Polygon.
func validatePolygon(name string, coords [][]float64) (orb.Polygon, error) {
	if len(coords) < 4 {
		return nil, fmt.Errorf("polygon '%s' must have at least 4 points (including closing point)", name)
	}

	ring := make(orb.Ring, len(coords))

	for i, coord := range coords {
		if len(coord) != 2 {
			return nil, fmt.Errorf("polygon '%s' point %d must have exactly 2 coordinates [longitude, latitude]", name, i)
		}

		lon := coord[0]
		lat := coord[1]

		if err := validateGPSCoordinate(name, i, lon, lat); err != nil {
			return nil, err
		}

		ring[i] = orb.Point{lon, lat}
	}

	// Check if polygon is closed
	first := coords[0]
	last := coords[len(coords)-1]
	if first[0] != last[0] || first[1] != last[1] {
		return nil, fmt.Errorf("polygon '%s' must be closed (first and last points must be identical)", name)
	}

	return orb.Polygon{ring}, nil
}

// validateGPSCoordinate checks if coordinates are valid GPS coordinates.
func validateGPSCoordinate(name string, pointIndex int, lon, lat float64) error {
	// Valid latitude range: -90 to 90
	if lat < -90 || lat > 90 {
		return fmt.Errorf("polygon '%s' point %d has invalid latitude %.6f (must be between -90 and 90)", name, pointIndex, lat)
	}

	// Valid longitude range: -180 to 180
	if lon < -180 || lon > 180 {
		return fmt.Errorf("polygon '%s' point %d has invalid longitude %.6f (must be between -180 and 180)", name, pointIndex, lon)
	}

	return nil
}
