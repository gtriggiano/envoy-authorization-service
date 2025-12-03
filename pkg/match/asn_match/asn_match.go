package asn_match

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"go.uber.org/zap"
	"google.golang.org/grpc/codes"

	"github.com/gtriggiano/envoy-authorization-service/pkg/analysis/maxmind_asn"
	"github.com/gtriggiano/envoy-authorization-service/pkg/asnlist"
	"github.com/gtriggiano/envoy-authorization-service/pkg/config"
	"github.com/gtriggiano/envoy-authorization-service/pkg/controller"
	"github.com/gtriggiano/envoy-authorization-service/pkg/runtime"
)

const (
	ControllerKind = "asn-match"
)

// init registers the ASN-match match controller so the application can
// create instances from configuration.
func init() {
	controller.RegisterMatchControllerFactory(ControllerKind, newASNMatchController)
}

type ASNMatchConfig struct {
	ASNList string `yaml:"asnList"`
}

type asnMatchController struct {
	name   string
	asnMap map[uint]string
	logger *zap.Logger
}

// Match implements controller.MatchController.
func (c *asnMatchController) Match(ctx context.Context, req *runtime.RequestContext, reports controller.AnalysisReports) (*controller.MatchVerdict, error) {
	isMatch, description := c.deriveMatch(reports)

	return &controller.MatchVerdict{
		Controller:     c.name,
		ControllerType: ControllerKind,
		DenyCode:       codes.PermissionDenied,
		Description:    description,
		IsMatch:        isMatch,
	}, nil
}

// Name implements controller.MatchController.
func (c *asnMatchController) Name() string {
	return c.name
}

// Kind implements controller.MatchController.
func (c *asnMatchController) Kind() string {
	return ControllerKind
}

// HealthCheck implements controller.MatchController.
func (c *asnMatchController) HealthCheck(ctx context.Context) error {
	// No external dependencies to check
	return nil
}

// deriveMatch inspects analyzer reports, determines whether the request ASN
// matches the configured list, and returns the result.
func (c *asnMatchController) deriveMatch(reports controller.AnalysisReports) (bool, string) {
	var ipLookupResult *maxmind_asn.IpLookupResult
	for _, report := range reports {
		if report == nil || report.ControllerKind != maxmind_asn.ControllerKind {
			continue
		}
		ipLookupResult = maxmind_asn.GetIpLookupResultFromReport(report)
	}

	if ipLookupResult == nil {
		return false, "no ASN information available"
	}

	asnComment, asnMatched := c.asnMap[ipLookupResult.AutonomousSystemNumber]

	if asnMatched {
		if asnComment != "" {
			return true, fmt.Sprintf("AS %d %s [%s] matched list", ipLookupResult.AutonomousSystemNumber, ipLookupResult.AutonomousSystemOrganization, asnComment)
		}
		return true, fmt.Sprintf("AS %d %s matched list", ipLookupResult.AutonomousSystemNumber, ipLookupResult.AutonomousSystemOrganization)
	}

	if asnComment != "" {
		return false, fmt.Sprintf("AS %d %s [%s] did not match list", ipLookupResult.AutonomousSystemNumber, ipLookupResult.AutonomousSystemOrganization, asnComment)
	}
	return false, fmt.Sprintf("AS %d %s did not match list", ipLookupResult.AutonomousSystemNumber, ipLookupResult.AutonomousSystemOrganization)
}

// newASNMatchController loads the ASN list from disk and prepares a controller.
func newASNMatchController(_ context.Context, logger *zap.Logger, cfg config.ControllerConfig) (controller.MatchController, error) {
	var config ASNMatchConfig
	if err := controller.DecodeControllerSettings(cfg.Settings, &config); err != nil {
		return nil, err
	}

	if config.ASNList == "" {
		return nil, fmt.Errorf("asnList is required, check your configuration")
	}

	asnListFilePath, err := filepath.Abs(config.ASNList)
	if err != nil {
		return nil, fmt.Errorf("asnList path is not valid: %w", err)
	}

	asnListFileContent, err := os.ReadFile(asnListFilePath)
	if err != nil {
		return nil, fmt.Errorf("could not read asnList file: %w", err)
	}

	asnMap := make(map[uint]string)
	for _, entry := range asnlist.Synthesize(asnlist.Parse(string(asnListFileContent))).NewList {
		asnMap[entry.Number] = entry.Comment
	}

	return &asnMatchController{
		name:   cfg.Name,
		asnMap: asnMap,
		logger: logger,
	}, nil
}
