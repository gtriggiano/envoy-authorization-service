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

// init registers the ip-match match controller so it can be constructed
// from configuration at runtime.
func init() {
	controller.RegisterMatchControllerFactory(ControllerKind, newIpMatchController)
}

type IpMatchConfig struct {
	CIDRList string `yaml:"cidrList"`
}

type ipMatchController struct {
	name     string
	cidrList []cidrlist.CIDR
	cache    map[string]*cidrlist.CIDR // nil if IP didn't match any CIDR
	cacheMu  sync.RWMutex
	logger   *zap.Logger
}

// Match implements controller.MatchController.
func (c *ipMatchController) Match(ctx context.Context, req *runtime.RequestContext, reports controller.AnalysisReports) (*controller.MatchVerdict, error) {
	if !req.IpAddress.IsValid() {
		return &controller.MatchVerdict{
			Controller:     c.name,
			ControllerType: ControllerKind,
			DenyCode:       codes.PermissionDenied,
			Description:    "unable to determine source IP address",
			IsMatch:        false,
		}, nil
	}

	// Check cache and compute match result if needed
	ipAddress := req.IpAddress.String()
	matchedCIDR := c.getOrComputeMatch(ipAddress)

	// Derive verdict from matched CIDR
	isMatch, description := c.deriveMatch(ipAddress, matchedCIDR)

	return &controller.MatchVerdict{
		Controller:     c.name,
		ControllerType: ControllerKind,
		DenyCode:       codes.PermissionDenied,
		Description:    description,
		IsMatch:        isMatch,
	}, nil
}

// Name implements controller.MatchController.
func (c *ipMatchController) Name() string {
	return c.name
}

// Kind implements controller.MatchController.
func (c *ipMatchController) Kind() string {
	return ControllerKind
}

// HealthCheck implements controller.MatchController.
func (c *ipMatchController) HealthCheck(ctx context.Context) error {
	// No external dependencies to check
	return nil
}

// getOrComputeMatch returns the cached CIDR match for the IP or computes and
// stores it when absent. A nil pointer indicates no CIDR contained the IP.
func (c *ipMatchController) getOrComputeMatch(ipAddress string) *cidrlist.CIDR {
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

// deriveMatch maps the CIDR match outcome into a boolean and human-readable description.
func (c *ipMatchController) deriveMatch(ipAddress string, matchedCIDR *cidrlist.CIDR) (bool, string) {
	if matchedCIDR != nil {
		if matchedCIDR.Comment != "" {
			return true, fmt.Sprintf("IP %s matched CIDR %s [%s]", ipAddress, matchedCIDR.Value, matchedCIDR.Comment)
		}
		return true, fmt.Sprintf("IP %s matched CIDR %s", ipAddress, matchedCIDR.Value)
	} else {
		return false, fmt.Sprintf("IP %s did not match any configured CIDR", ipAddress)
	}
}

// newIpMatchController constructs a match controller from
// configuration by loading the CIDR list file and preparing the evaluation cache.
func newIpMatchController(_ context.Context, logger *zap.Logger, cfg config.ControllerConfig) (controller.MatchController, error) {
	var matchConfig IpMatchConfig
	if err := controller.DecodeControllerSettings(cfg.Settings, &matchConfig); err != nil {
		return nil, err
	}

	if matchConfig.CIDRList == "" {
		return nil, fmt.Errorf("cidrList is required, check your configuration")
	}

	cidrListFilePath, err := filepath.Abs(matchConfig.CIDRList)
	if err != nil {
		return nil, fmt.Errorf("cidrList path is not valid: %w", err)
	}

	cidrListFileContent, err := os.ReadFile(cidrListFilePath)
	if err != nil {
		return nil, fmt.Errorf("could not read cidrList file: %w", err)
	}

	return &ipMatchController{
		name:     cfg.Name,
		cidrList: cidrlist.Parse(string(cidrListFileContent)),
		cache:    make(map[string]*cidrlist.CIDR),
		logger:   logger,
	}, nil
}
