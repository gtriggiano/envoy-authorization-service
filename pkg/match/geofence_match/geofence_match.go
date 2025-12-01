package geofence_match

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/paulmach/orb"
	"github.com/paulmach/orb/geojson"
	"github.com/paulmach/orb/planar"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"

	"github.com/gtriggiano/envoy-authorization-service/pkg/analysis/maxmind_geoip"
	"github.com/gtriggiano/envoy-authorization-service/pkg/config"
	"github.com/gtriggiano/envoy-authorization-service/pkg/controller"
	"github.com/gtriggiano/envoy-authorization-service/pkg/metrics"
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
	FeaturesFile string `yaml:"featuresFile"`
}

// geoFeature holds a validated feature with its name and associated polygons.
type geoFeature struct {
	name     string
	polygons []orb.Polygon
}

type geofenceMatchController struct {
	name            string
	features        []geoFeature
	cache           map[string][]string // coordinates -> matched feature names
	cacheMu         sync.RWMutex
	instrumentation *metrics.Instrumentation
	logger          *zap.Logger
}

// SetInstrumentation injects the shared metrics instrumentation.
func (c *geofenceMatchController) SetInstrumentation(inst *metrics.Instrumentation) {
	c.instrumentation = inst
}

// Match implements controller.MatchController.
func (c *geofenceMatchController) Match(ctx context.Context, req *runtime.RequestContext, reports controller.AnalysisReports) (*controller.MatchVerdict, error) {
	isMatch, description, matchedFeatures := c.deriveMatch(reports)

	// Emit metrics for each matched feature
	for _, feature := range matchedFeatures {
		c.instrumentation.ObserveGeofenceMatch(req.Authority, c.name, feature)
	}

	allowUpstreamHeaders := map[string]string{
		fmt.Sprintf("X-Geofence-%s", c.name): fmt.Sprintf("%t", isMatch),
	}

	if isMatch && len(matchedFeatures) > 0 {
		allowUpstreamHeaders[fmt.Sprintf("X-Geofence-%s-Features", c.name)] = formatMatchedFeatureNames(matchedFeatures)
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
// fall within any configured feature's polygons, and returns the result.
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
	if cachedFeatures, ok := c.cache[cacheKey]; ok {
		c.cacheMu.RUnlock()
		c.logger.Debug("cache hit for coordinates", zap.String("coords", cacheKey))
		if len(cachedFeatures) > 0 {
			return true, fmt.Sprintf("coordinates (%.4f, %.4f) matched %d feature(s): %v", lat, lon, len(cachedFeatures), cachedFeatures), cachedFeatures
		}
		return false, fmt.Sprintf("coordinates (%.4f, %.4f) did not match any feature", lat, lon), nil
	}
	c.cacheMu.RUnlock()

	// Cache miss - compute match
	c.logger.Debug("cache miss for coordinates", zap.String("coords", cacheKey))
	matchedFeatures := c.findContainingFeatures(lat, lon)

	// Store in cache
	c.cacheMu.Lock()
	c.cache[cacheKey] = matchedFeatures
	c.cacheMu.Unlock()

	if len(matchedFeatures) > 0 {
		return true, fmt.Sprintf("coordinates (%.4f, %.4f) matched %d feature(s): %v", lat, lon, len(matchedFeatures), matchedFeatures), matchedFeatures
	}

	return false, fmt.Sprintf("coordinates (%.4f, %.4f) did not match any feature", lat, lon), nil
}

// findContainingFeatures checks which features contain the given point.
func (c *geofenceMatchController) findContainingFeatures(lat, lon float64) []string {
	point := orb.Point{lon, lat} // orb uses [lon, lat] order
	var matched []string

	for _, feature := range c.features {
		for _, polygon := range feature.polygons {
			if planar.PolygonContains(polygon, point) {
				matched = append(matched, feature.name)
				break // Once matched, no need to check other polygons of the same feature
			}
		}
	}

	// Sort matched feature names in ascending order
	sort.Strings(matched)

	return matched
}

// formatMatchedFeatureNames joins feature names with commas for the header.
func formatMatchedFeatureNames(names []string) string {
	return strings.Join(names, ",")
}

// newGeofenceMatchController constructs a match controller from
// configuration by loading and validating the GeoJSON features file.
func newGeofenceMatchController(_ context.Context, logger *zap.Logger, cfg config.ControllerConfig) (controller.MatchController, error) {
	var matchConfig GeofenceMatchConfig
	if err := controller.DecodeControllerSettings(cfg.Settings, &matchConfig); err != nil {
		return nil, err
	}

	if matchConfig.FeaturesFile == "" {
		return nil, fmt.Errorf("featuresFile is required, check your configuration")
	}

	featuresFilePath, err := filepath.Abs(matchConfig.FeaturesFile)
	if err != nil {
		return nil, fmt.Errorf("featuresFile path is not valid: %w", err)
	}

	featuresFileContent, err := os.ReadFile(featuresFilePath)
	if err != nil {
		return nil, fmt.Errorf("could not read featuresFile file: %w", err)
	}

	features, err := parseAndValidateGeoJSON(featuresFileContent)
	if err != nil {
		return nil, fmt.Errorf("GeoJSON validation failed: %w", err)
	}

	logger.Info("loaded geofence features from GeoJSON", zap.Int("count", len(features)))

	return &geofenceMatchController{
		name:     cfg.Name,
		features: features,
		cache:    make(map[string][]string),
		logger:   logger,
	}, nil
}

// parseAndValidateGeoJSON parses a GeoJSON FeatureCollection and extracts features.
// Each Feature must have:
//   - A "name" property (string) for identification
//   - A geometry of type Polygon or MultiPolygon with valid GPS coordinates
func parseAndValidateGeoJSON(content []byte) ([]geoFeature, error) {
	fc, err := geojson.UnmarshalFeatureCollection(content)
	if err != nil {
		return nil, fmt.Errorf("failed to parse GeoJSON: %w", err)
	}

	if len(fc.Features) == 0 {
		return nil, fmt.Errorf("GeoJSON FeatureCollection must contain at least one feature")
	}

	result := make([]geoFeature, 0, len(fc.Features))
	seenNames := make(map[string]bool)

	for i, feature := range fc.Features {
		// Get the name from properties
		name, err := getFeatureName(feature, i)
		if err != nil {
			return nil, err
		}

		if seenNames[name] {
			return nil, fmt.Errorf("duplicate feature name: %s", name)
		}
		seenNames[name] = true

		// Extract polygons from the geometry
		polygons, err := extractPolygons(feature, name)
		if err != nil {
			return nil, err
		}

		result = append(result, geoFeature{
			name:     name,
			polygons: polygons,
		})
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no valid features found in GeoJSON")
	}

	return result, nil
}

// getFeatureName extracts the name property from a GeoJSON feature.
func getFeatureName(feature *geojson.Feature, index int) (string, error) {
	if feature.Properties == nil {
		return "", fmt.Errorf("feature at index %d must have properties with a 'name' field", index)
	}

	nameVal, ok := feature.Properties["name"]
	if !ok {
		return "", fmt.Errorf("feature at index %d must have a 'name' property", index)
	}

	name, ok := nameVal.(string)
	if !ok || name == "" {
		return "", fmt.Errorf("feature at index %d 'name' property must be a non-empty string", index)
	}

	return name, nil
}

// extractPolygons extracts orb.Polygon geometries from a GeoJSON feature.
// Supports Polygon and MultiPolygon geometry types.
func extractPolygons(feature *geojson.Feature, name string) ([]orb.Polygon, error) {
	if feature.Geometry == nil {
		return nil, fmt.Errorf("feature '%s' has no geometry", name)
	}

	var result []orb.Polygon

	switch geom := feature.Geometry.(type) {
	case orb.Polygon:
		if err := validatePolygon(name, geom); err != nil {
			return nil, err
		}
		result = append(result, geom)

	case orb.MultiPolygon:
		for i, poly := range geom {
			polyName := fmt.Sprintf("%s-%d", name, i)
			if err := validatePolygon(polyName, poly); err != nil {
				return nil, err
			}
			result = append(result, poly)
		}

	default:
		return nil, fmt.Errorf("feature '%s' has unsupported geometry type: only Polygon and MultiPolygon are supported", name)
	}

	return result, nil
}

// validatePolygon validates a polygon's coordinates are within valid GPS bounds.
func validatePolygon(name string, polygon orb.Polygon) error {
	if len(polygon) == 0 {
		return fmt.Errorf("polygon '%s' has no rings", name)
	}

	for ringIdx, ring := range polygon {
		if len(ring) < 4 {
			return fmt.Errorf("polygon '%s' ring %d must have at least 4 points (including closing point)", name, ringIdx)
		}

		// Check if ring is closed
		first := ring[0]
		last := ring[len(ring)-1]
		if first[0] != last[0] || first[1] != last[1] {
			return fmt.Errorf("polygon '%s' ring %d must be closed (first and last points must be identical)", name, ringIdx)
		}

		// Validate coordinates
		for pointIdx, point := range ring {
			if err := validateGPSCoordinate(name, ringIdx, pointIdx, point[0], point[1]); err != nil {
				return err
			}
		}
	}

	return nil
}

// validateGPSCoordinate checks if coordinates are valid GPS coordinates.
func validateGPSCoordinate(name string, ringIndex, pointIndex int, lon, lat float64) error {
	// Valid latitude range: -90 to 90
	if lat < -90 || lat > 90 {
		return fmt.Errorf("polygon '%s' ring %d point %d has invalid latitude %.6f (must be between -90 and 90)", name, ringIndex, pointIndex, lat)
	}

	// Valid longitude range: -180 to 180
	if lon < -180 || lon > 180 {
		return fmt.Errorf("polygon '%s' ring %d point %d has invalid longitude %.6f (must be between -180 and 180)", name, ringIndex, pointIndex, lon)
	}

	return nil
}

// ValidateGeoJSONFile reads and validates a GeoJSON file, returning the number of features found.
// This is used by the CLI validate-geojson command.
func ValidateGeoJSONFile(filePath string) (int, error) {
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return 0, fmt.Errorf("invalid file path: %w", err)
	}

	content, err := os.ReadFile(absPath)
	if err != nil {
		return 0, fmt.Errorf("could not read file: %w", err)
	}

	features, err := parseAndValidateGeoJSON(content)
	if err != nil {
		return 0, err
	}

	return len(features), nil
}

// GetFeatureNames reads a GeoJSON file and returns the names of all features.
// This is used by the CLI validate-geojson command for detailed output.
func GetFeatureNames(filePath string) ([]string, error) {
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return nil, fmt.Errorf("invalid file path: %w", err)
	}

	content, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("could not read file: %w", err)
	}

	features, err := parseAndValidateGeoJSON(content)
	if err != nil {
		return nil, err
	}

	names := make([]string, len(features))
	for i, f := range features {
		names[i] = f.name
	}

	// Sort names in ascending order
	sort.Strings(names)

	return names, nil
}
