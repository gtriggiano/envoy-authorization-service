package ip_match

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"go.uber.org/zap"
	"google.golang.org/grpc/codes"

	"github.com/gtriggiano/envoy-authorization-service/pkg/cidrlist"
	"github.com/gtriggiano/envoy-authorization-service/pkg/config"
	"github.com/gtriggiano/envoy-authorization-service/pkg/controller"
	"github.com/gtriggiano/envoy-authorization-service/pkg/runtime"
)

const (
	ControllerKind = "ip-match"
)

// init registers the ip-match authorization controller so it can be constructed
// from configuration at runtime.
func init() {
	controller.RegisterAuthorization(ControllerKind, newIpMatchAuthorizationController)
}

type IpMatchAuthorizationConfig struct {
	CIDRList string `yaml:"cidrList"`
	Action   string `yaml:"action"`
}

type ipMatchAuthorizationController struct {
	name     string
	cidrList []cidrlist.CIDR
	action   string
	cache    map[string]*cidrlist.CIDR // nil if IP didn't match any CIDR
	cacheMu  sync.RWMutex
	logger   *zap.Logger
}

// Authorize implements controller.AuthorizationController.
func (c *ipMatchAuthorizationController) Authorize(ctx context.Context, req *runtime.RequestContext, reports controller.AnalysisReports) (*controller.AuthorizationVerdict, error) {
	if !req.IpAddress.IsValid() {
		return &controller.AuthorizationVerdict{
			Controller:     c.name,
			ControllerKind: ControllerKind,
			Code:           codes.PermissionDenied,
			InPolicy:       c.action == "deny",
			Reason:         "unable to determine source IP address",
		}, nil
	}

	// Check cache and compute match result if needed
	ipAddress := req.IpAddress.String()
	matchedCIDR := c.getOrComputeMatch(ipAddress)

	// Derive verdict from matched CIDR and action
	code, reason, inPolicy := c.deriveVerdict(ipAddress, matchedCIDR)

	return &controller.AuthorizationVerdict{
		Controller:     c.name,
		ControllerKind: ControllerKind,
		Code:           code,
		Reason:         reason,
		InPolicy:       inPolicy,
	}, nil
}

// Name implements controller.AuthorizationController.
func (c *ipMatchAuthorizationController) Name() string {
	return c.name
}

// Kind implements controller.AuthorizationController.
func (c *ipMatchAuthorizationController) Kind() string {
	return ControllerKind
}

// HealthCheck implements controller.AuthorizationController.
func (c *ipMatchAuthorizationController) HealthCheck(ctx context.Context) error {
	// No external dependencies to check
	return nil
}

// getOrComputeMatch returns the cached CIDR match for the IP or computes and
// stores it when absent. A nil pointer indicates no CIDR contained the IP.
func (c *ipMatchAuthorizationController) getOrComputeMatch(ipAddress string) *cidrlist.CIDR {
	// Check cache with read lock
	c.cacheMu.RLock()
	if matchedCIDR, ok := c.cache[ipAddress]; ok {
		c.cacheMu.RUnlock()
		c.logger.Debug("cache hit for IP", zap.String("ip", ipAddress))
		return matchedCIDR
	}
	c.cacheMu.RUnlock()

	// Cache miss - compute match
	c.logger.Debug("cache miss for IP", zap.String("ip", ipAddress))
	matchedCIDR, _ := cidrlist.FindContaining(c.cidrList, ipAddress)

	// Store in cache with write lock
	c.cacheMu.Lock()
	c.cache[ipAddress] = matchedCIDR
	c.cacheMu.Unlock()

	c.logger.Debug("cached match result", zap.String("ip", ipAddress), zap.Bool("matched", matchedCIDR != nil))
	return matchedCIDR
}

// deriveVerdict maps the configured action ("allow"/"deny") plus the CIDR match
// outcome into a gRPC status code and human-readable reason.
func (c *ipMatchAuthorizationController) deriveVerdict(ipAddress string, matchedCIDR *cidrlist.CIDR) (codes.Code, string, bool) {
	var code codes.Code
	var reason string
	var inPolicy bool

	if matchedCIDR != nil {
		if c.action == "allow" {
			code = codes.OK
			inPolicy = true
			if matchedCIDR.Comment != "" {
				reason = fmt.Sprintf("IP %s matched allowed CIDR %s [%s]", ipAddress, matchedCIDR.Value, matchedCIDR.Comment)
			} else {
				reason = fmt.Sprintf("IP %s matched allowed CIDR %s", ipAddress, matchedCIDR.Value)
			}
		} else { // action == "deny"
			code = codes.PermissionDenied
			inPolicy = true
			if matchedCIDR.Comment != "" {
				reason = fmt.Sprintf("IP %s matched black-listed CIDR %s [%s]", ipAddress, matchedCIDR.Value, matchedCIDR.Comment)
			} else {
				reason = fmt.Sprintf("IP %s matched black-listed CIDR %s", ipAddress, matchedCIDR.Value)
			}
		}
	} else {
		if c.action == "allow" {
			code = codes.PermissionDenied
			inPolicy = false
			reason = fmt.Sprintf("IP %s not allowed", ipAddress)
		} else { // action == "deny"
			code = codes.OK
			inPolicy = false
			reason = fmt.Sprintf("IP %s is not black-listed", ipAddress)
		}
	}

	return code, reason, inPolicy
}

// newIpMatchAuthorizationController constructs an authorization controller from
// configuration by loading the CIDR list file and preparing the evaluation cache.
func newIpMatchAuthorizationController(_ context.Context, logger *zap.Logger, cfg config.ControllerConfig) (controller.AuthorizationController, error) {
	var config IpMatchAuthorizationConfig
	if err := controller.DecodeControllerSettings(cfg.Settings, &config); err != nil {
		return nil, err
	}

	if config.Action != "allow" && config.Action != "deny" {
		return nil, fmt.Errorf("action must be 'allow' or 'deny', check your configuration")
	}

	if config.CIDRList == "" {
		return nil, fmt.Errorf("cidrList is required, check your configuration")
	}

	cidrListFilePath, err := filepath.Abs(config.CIDRList)
	if err != nil {
		return nil, fmt.Errorf("cidrList path is not valid: %w", err)
	}

	cidrListFileContent, err := os.ReadFile(cidrListFilePath)
	if err != nil {
		return nil, fmt.Errorf("could not read cidrList file: %w", err)
	}

	return &ipMatchAuthorizationController{
		name:     cfg.Name,
		cidrList: cidrlist.Parse(string(cidrListFileContent)),
		action:   config.Action,
		cache:    make(map[string]*cidrlist.CIDR),
		logger:   logger,
	}, nil
}
