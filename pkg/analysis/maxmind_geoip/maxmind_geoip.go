package maxmind_geoip

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"sync"

	"github.com/oschwald/geoip2-golang/v2"
	"go.uber.org/zap"

	"github.com/gtriggiano/envoy-authorization-service/pkg/config"
	"github.com/gtriggiano/envoy-authorization-service/pkg/controller"
	"github.com/gtriggiano/envoy-authorization-service/pkg/runtime"
)

const (
	ControllerKind = "maxmind-geoip"
)

// init registers the MaxMind GeoIP analysis controller factory.
func init() {
	controller.RegisterAnalysisControllerFactory(ControllerKind, newMaxMindCityAnalysisController)
}

type MaxMindCityAnalysisConfig struct {
	DatabasePath string `yaml:"databasePath"`
}

type IpLookupResult struct {
	City          string
	PostalCode    string
	Region        string
	CountryName   string
	CountryISO    string
	ContinentName string
	TimeZone      string
	Latitude      float64
	Longitude     float64
}

// GetIpLookupResultFromReport extracts the typed GeoIP lookup result from an analysis report.
func GetIpLookupResultFromReport(report *controller.AnalysisReport) *IpLookupResult {
	if report == nil {
		return nil
	}

	data, ok := report.Data["result"]
	if !ok {
		return nil
	}

	result, ok := data.(*IpLookupResult)
	if !ok {
		return nil
	}

	return result
}

type maxMindCityAnalysisController struct {
	name    string
	cityDb  *geoip2.Reader
	cache   map[string]*IpLookupResult
	cacheMu sync.RWMutex
	logger  *zap.Logger
}

// Analyze implements controller.AnalysisController.
func (c *maxMindCityAnalysisController) Analyze(ctx context.Context, req *runtime.RequestContext) (*controller.AnalysisReport, error) {
	ipLookupResult := c.ipLookup(req.IpAddress)

	req.AddLogFields(makeLogFields(ipLookupResult)...)

	report := &controller.AnalysisReport{
		Controller:      c.name,
		ControllerKind:  ControllerKind,
		UpstreamHeaders: makeUpstreamHeaders(ipLookupResult),
		Data: map[string]any{
			"result": ipLookupResult,
		},
	}

	return report, nil
}

// Name implements controller.AnalysisController.
func (c *maxMindCityAnalysisController) Name() string {
	return c.name
}

// Kind implements controller.AnalysisController.
func (c *maxMindCityAnalysisController) Kind() string {
	return ControllerKind
}

// HealthCheck implements controller.AnalysisController.
func (c *maxMindCityAnalysisController) HealthCheck(ctx context.Context) error {
	// No external dependencies to check
	return nil
}

// ipLookup fetches GeoIP information for an address while caching prior lookups.
func (c *maxMindCityAnalysisController) ipLookup(ipAddress netip.Addr) *IpLookupResult {
	ipAddressAsString := ipAddress.String()

	// Check cache with read lock
	c.cacheMu.RLock()
	if cachedResult, ok := c.cache[ipAddressAsString]; ok {
		c.cacheMu.RUnlock()
		c.logger.Debug("cache hit for IP", zap.String("ip", ipAddressAsString))
		return cachedResult
	}
	c.cacheMu.RUnlock()

	// Cache miss - perform database lookup
	c.logger.Debug("cache miss for IP", zap.String("ip", ipAddressAsString))
	ipLookupResult := c.databaseLookup(ipAddress)

	// Store in cache with write lock
	c.cacheMu.Lock()
	c.cache[ipAddressAsString] = ipLookupResult
	c.cacheMu.Unlock()

	c.logger.Debug("cached GeoIP lookup result", zap.String("ip", ipAddressAsString))
	return ipLookupResult
}

// databaseLookup queries the MaxMind City database for geographic metadata.
func (c *maxMindCityAnalysisController) databaseLookup(ip netip.Addr) *IpLookupResult {
	cityRecord, err := c.cityDb.City(ip)
	if err != nil {
		c.logger.Error("could not get GeoIP data from MaxMind database", zap.String("ip", ip.String()), zap.Error(err))
		return nil
	}
	if !cityRecord.HasData() {
		c.logger.Warn("no GeoIP data in MaxMind database", zap.String("ip", ip.String()))
		return nil
	}

	region := ""
	if len(cityRecord.Subdivisions) > 0 {
		region = cityRecord.Subdivisions[0].Names.English
	}

	var latitude float64
	var longitude float64
	if cityRecord.Location.HasCoordinates() {
		latitude = *cityRecord.Location.Latitude
		longitude = *cityRecord.Location.Longitude
	}

	result := &IpLookupResult{
		City:          cityRecord.City.Names.English,
		PostalCode:    cityRecord.Postal.Code,
		Region:        region,
		CountryName:   cityRecord.Country.Names.English,
		CountryISO:    cityRecord.Country.ISOCode,
		ContinentName: cityRecord.Continent.Names.English,
		TimeZone:      cityRecord.Location.TimeZone,
		Latitude:      latitude,
		Longitude:     longitude,
	}

	return result
}

// newMaxMindCityAnalysisController loads the MaxMind City database and returns
// an analysis controller that caches GeoIP lookups.
func newMaxMindCityAnalysisController(ctx context.Context, logger *zap.Logger, cfg config.ControllerConfig) (controller.AnalysisController, error) {
	var config MaxMindCityAnalysisConfig
	if err := controller.DecodeControllerSettings(cfg.Settings, &config); err != nil {
		return nil, err
	}

	if config.DatabasePath == "" {
		return nil, fmt.Errorf("databasePath is required, check your configuration")
	}

	databaseFilePath, err := filepath.Abs(config.DatabasePath)
	if err != nil {
		return nil, fmt.Errorf("databasePath '%s' is not valid: %w", config.DatabasePath, err)
	}

	cityDb, err := geoip2.Open(databaseFilePath)
	if err != nil {
		return nil, fmt.Errorf("could not open City database at %s: %w", databaseFilePath, err)
	}

	// Setup cleanup when context is canceled
	go func() {
		<-ctx.Done()
		if err := cityDb.Close(); err != nil {
			logger.Error("failed to close City database", zap.Error(err))
		}
	}()

	return &maxMindCityAnalysisController{
		name:   cfg.Name,
		cityDb: cityDb,
		cache:  make(map[string]*IpLookupResult),
		logger: logger,
	}, nil
}

// makeUpstreamHeaders serializes lookup results into HTTP headers to forward upstream.
func makeUpstreamHeaders(result *IpLookupResult) map[string]string {
	if result == nil {
		return nil
	}

	headers := map[string]string{
		"X-GeoIP-City":       result.City,
		"X-GeoIP-PostalCode": result.PostalCode,
		"X-GeoIP-Region":     result.Region,
		"X-GeoIP-Country":    result.CountryName,
		"X-GeoIP-CountryISO": result.CountryISO,
		"X-GeoIP-Continent":  result.ContinentName,
		"X-GeoIP-TimeZone":   result.TimeZone,
		"X-GeoIP-Latitude":   fmt.Sprintf("%f", result.Latitude),
		"X-GeoIP-Longitude":  fmt.Sprintf("%f", result.Longitude),
	}

	return headers
}

// makeLogFields converts lookup results to structured logging fields.
func makeLogFields(result *IpLookupResult) []zap.Field {
	if result == nil {
		return nil
	}

	fields := []zap.Field{
		zap.String("geoip_city", result.City),
		zap.String("geoip_postal_code", result.PostalCode),
		zap.String("geoip_region", result.Region),
		zap.String("geoip_country", result.CountryName),
		zap.String("geoip_country_iso", result.CountryISO),
		zap.String("geoip_continent", result.ContinentName),
		zap.String("geoip_timezone", result.TimeZone),
		zap.Float64("geoip_latitude", result.Latitude),
		zap.Float64("geoip_longitude", result.Longitude),
	}

	return fields
}
