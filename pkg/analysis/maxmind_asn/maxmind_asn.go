package maxmind_asn

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
	ControllerKind = "maxmind-asn"
)

// init registers the MaxMind ASN analysis controller factory.
func init() {
	controller.RegisterAnalysisControllerFactory(ControllerKind, newMaxMindAsnAnalysisController)
}

type MaxMindAsnAnalysisConfig struct {
	DatabasePath string `yaml:"databasePath"`
}

type IpLookupResult struct {
	AutonomousSystemOrganization string
	AutonomousSystemNumber       uint
}

// GetIpLookupResultFromReport extracts the typed lookup result from an analysis report.
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

type maxMindAsnAnalysisController struct {
	name    string
	asnDb   *geoip2.Reader
	cache   map[string]*IpLookupResult
	cacheMu sync.RWMutex
	logger  *zap.Logger
}

// Analyze implements controller.AnalysisController.
func (c *maxMindAsnAnalysisController) Analyze(ctx context.Context, req *runtime.RequestContext) (*controller.AnalysisReport, error) {
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
func (c *maxMindAsnAnalysisController) Name() string {
	return c.name
}

// Kind implements controller.AnalysisController.
func (c *maxMindAsnAnalysisController) Kind() string {
	return ControllerKind
}

// HealthCheck implements controller.AnalysisController.
func (c *maxMindAsnAnalysisController) HealthCheck(ctx context.Context) error {
	// No external dependencies to check
	return nil
}

// ipLookup fetches ASN metadata for the provided IP, using a cache to avoid
// repeated database lookups.
func (c *maxMindAsnAnalysisController) ipLookup(ipAddress netip.Addr) *IpLookupResult {
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

	c.logger.Debug("cached ASN lookup result", zap.String("ip", ipAddressAsString))
	return ipLookupResult
}

// databaseLookup queries the MaxMind database for ASN information.
func (c *maxMindAsnAnalysisController) databaseLookup(ip netip.Addr) *IpLookupResult {
	asnRecord, err := c.asnDb.ASN(ip)
	if err != nil {
		c.logger.Error("could not get ASN data from MaxMind database", zap.String("ip", ip.String()), zap.Error(err))
		return nil
	}

	if !asnRecord.HasData() {
		c.logger.Warn("no ASN data in MaxMind database", zap.String("ip", ip.String()))
		return nil
	}

	result := &IpLookupResult{
		AutonomousSystemOrganization: asnRecord.AutonomousSystemOrganization,
		AutonomousSystemNumber:       asnRecord.AutonomousSystemNumber,
	}

	return result
}

// newMaxMindAsnAnalysisController loads the MaxMind ASN database file and
// returns an analysis controller that caches lookup results.
func newMaxMindAsnAnalysisController(ctx context.Context, logger *zap.Logger, cfg config.ControllerConfig) (controller.AnalysisController, error) {
	var config MaxMindAsnAnalysisConfig
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

	asnDb, err := geoip2.Open(databaseFilePath)
	if err != nil {
		return nil, fmt.Errorf("could not open ASN database at %s: %w", databaseFilePath, err)
	}

	// Setup cleanup when context is canceled
	go func() {
		<-ctx.Done()
		if err := asnDb.Close(); err != nil {
			logger.Error("failed to close ASN database", zap.Error(err))
		}
	}()

	return &maxMindAsnAnalysisController{
		name:   cfg.Name,
		asnDb:  asnDb,
		cache:  make(map[string]*IpLookupResult),
		logger: logger,
	}, nil
}

// makeUpstreamHeaders converts lookup results into headers forwarded upstream.
func makeUpstreamHeaders(result *IpLookupResult) map[string]string {
	if result == nil {
		return nil
	}

	headers := map[string]string{
		"X-ASN-Number":       fmt.Sprintf("%d", result.AutonomousSystemNumber),
		"X-ASN-Organization": result.AutonomousSystemOrganization,
	}

	return headers
}

// makeLogFields turns lookup results into structured log fields.
func makeLogFields(result *IpLookupResult) []zap.Field {
	if result == nil {
		return nil
	}

	return []zap.Field{
		zap.String("asn_organization", result.AutonomousSystemOrganization),
		zap.String("asn_number", fmt.Sprintf("%d", result.AutonomousSystemNumber)),
	}
}
