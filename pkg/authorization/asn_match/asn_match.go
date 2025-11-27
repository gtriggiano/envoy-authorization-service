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

// init registers the ASN-match authorization controller so the application can
// create instances from configuration.
func init() {
	controller.RegisterAuthorization(ControllerKind, newASNMatchAuthorizationController)
}

type ASNMatchAuthorizationConfig struct {
	ASNList string `yaml:"asnList"`
	Action  string `yaml:"action"`
}

type asnMatchAuthorizationController struct {
	name   string
	asnMap map[uint]string
	action string
	logger *zap.Logger
}

// Authorize implements controller.AuthorizationController.
func (c *asnMatchAuthorizationController) Authorize(ctx context.Context, req *runtime.RequestContext, reports controller.AnalysisReports) (*controller.AuthorizationVerdict, error) {
	code, reason, inPolicy := c.deriveVerdict(reports)

	return &controller.AuthorizationVerdict{
		Controller:     c.name,
		ControllerKind: ControllerKind,
		Code:           code,
		Reason:         reason,
		InPolicy:       inPolicy,
	}, nil
}

// Name implements controller.AuthorizationController.
func (c *asnMatchAuthorizationController) Name() string {
	return c.name
}

// Kind implements controller.AuthorizationController.
func (c *asnMatchAuthorizationController) Kind() string {
	return ControllerKind
}

// HealthCheck implements controller.AuthorizationController.
func (c *asnMatchAuthorizationController) HealthCheck(ctx context.Context) error {
	// No external dependencies to check
	return nil
}

// deriveVerdict inspects analyzer reports, determines whether the request ASN
// matches the configured allow/deny list, and returns the resulting status.
func (c *asnMatchAuthorizationController) deriveVerdict(reports controller.AnalysisReports) (codes.Code, string, bool) {
	var ipLookupResult *maxmind_asn.IpLookupResult
	for _, report := range reports {
		if report == nil || report.ControllerKind != maxmind_asn.ControllerKind {
			continue
		}
		ipLookupResult = maxmind_asn.GetIpLookupResultFromReport(report)
	}

	var code codes.Code
	var reason string
	var inPolicy bool

	if ipLookupResult == nil {
		reason = "no ASN information available"

		if c.action == "allow" {
			code = codes.PermissionDenied
			inPolicy = false
		} else { // action == "deny"
			code = codes.OK
			inPolicy = true
		}
	} else {
		asnComment, asnMatched := c.asnMap[ipLookupResult.AutonomousSystemNumber]

		if asnMatched {
			if c.action == "allow" {
				code = codes.OK
				inPolicy = true
				if asnComment != "" {
					reason = fmt.Sprintf("AS %d %s [%s] matched allow-list", ipLookupResult.AutonomousSystemNumber, ipLookupResult.AutonomousSystemOrganization, asnComment)
				} else {
					reason = fmt.Sprintf("AS %d %s matched allow-list", ipLookupResult.AutonomousSystemNumber, ipLookupResult.AutonomousSystemOrganization)
				}
			} else { // action == "deny"
				code = codes.PermissionDenied
				inPolicy = true
				if asnComment != "" {
					reason = fmt.Sprintf("AS %d %s [%s] matched black-list", ipLookupResult.AutonomousSystemNumber, ipLookupResult.AutonomousSystemOrganization, asnComment)
				} else {
					reason = fmt.Sprintf("AS %d %s matched black-list", ipLookupResult.AutonomousSystemNumber, ipLookupResult.AutonomousSystemOrganization)
				}
			}
		} else {
			if c.action == "allow" {
				code = codes.PermissionDenied
				inPolicy = false
				if asnComment != "" {
					reason = fmt.Sprintf("AS %d %s [%s] did not match allow-list", ipLookupResult.AutonomousSystemNumber, ipLookupResult.AutonomousSystemOrganization, asnComment)
				} else {
					reason = fmt.Sprintf("AS %d %s did not match allow-list", ipLookupResult.AutonomousSystemNumber, ipLookupResult.AutonomousSystemOrganization)
				}
			} else { // action == "deny"
				code = codes.OK
				inPolicy = false
				if asnComment != "" {
					reason = fmt.Sprintf("AS %d %s [%s] did not match black-list", ipLookupResult.AutonomousSystemNumber, ipLookupResult.AutonomousSystemOrganization, asnComment)
				} else {
					reason = fmt.Sprintf("AS %d %s did not match black-list", ipLookupResult.AutonomousSystemNumber, ipLookupResult.AutonomousSystemOrganization)
				}
			}
		}
	}

	return code, reason, inPolicy
}

// newASNMatchAuthorizationController loads the ASN allow/deny list from disk
// and prepares a controller that enforces the desired action.
func newASNMatchAuthorizationController(_ context.Context, logger *zap.Logger, cfg config.ControllerConfig) (controller.AuthorizationController, error) {
	var config ASNMatchAuthorizationConfig
	if err := controller.DecodeControllerSettings(cfg.Settings, &config); err != nil {
		return nil, err
	}

	if config.Action != "allow" && config.Action != "deny" {
		return nil, fmt.Errorf("action must be 'allow' or 'deny', check your configuration")
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

	return &asnMatchAuthorizationController{
		name:   cfg.Name,
		asnMap: asnMap,
		action: config.Action,
		logger: logger,
	}, nil
}
