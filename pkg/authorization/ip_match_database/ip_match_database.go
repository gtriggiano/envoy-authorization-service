package ip_match_database

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc/codes"

	"github.com/gtriggiano/envoy-authorization-service/pkg/config"
	"github.com/gtriggiano/envoy-authorization-service/pkg/controller"
	"github.com/gtriggiano/envoy-authorization-service/pkg/runtime"
)

const (
	ControllerKind = "ip-match-database"
)

// init registers the ip-match-database authorization controller
func init() {
	controller.RegisterAuthorization(ControllerKind, newIpMatchDatabaseAuthorizationController)
}

type ipMatchDatabaseAuthorizationController struct {
	name                      string
	action                    string
	alwaysDenyOnDbUnavailable bool
	dataSource                DataSource
	cache                     *Cache
	dbType                    string
	logger                    *zap.Logger
}

// Authorize implements controller.AuthorizationController
func (c *ipMatchDatabaseAuthorizationController) Authorize(ctx context.Context, req *runtime.RequestContext, reports controller.AnalysisReports) (*controller.AuthorizationVerdict, error) {
	// Validate IP address
	if !req.IpAddress.IsValid() {
		code := c.deriveCodeForInvalidIP()
		c.observeRequest(codeToMetricsResult(code))
		return c.createVerdict(
			code,
			"unable to determine source IP address",
		), nil
	}

	ipAddress := req.IpAddress.String()

	// Check cache first
	var matched bool
	var dbError error

	if c.cache != nil {
		if cachedMatch, found := c.cache.Get(ipAddress); found {
			c.observeCacheHit()
			c.logger.Debug("cache hit", zap.String("ip", ipAddress), zap.Bool("matched", cachedMatch))
			matched = cachedMatch
		} else {
			c.observeCacheMiss()
			c.logger.Debug("cache miss", zap.String("ip", ipAddress))
			matched, dbError = c.queryDatabase(ctx, ipAddress)

			// Cache the result if query was successful
			if dbError == nil {
				c.cache.Set(ipAddress, matched)
				c.updateCacheSize()
			}
		}
	} else {
		// No cache, query database directly
		matched, dbError = c.queryDatabase(ctx, ipAddress)
	}

	// Handle database errors
	if dbError != nil {
		c.observeUnavailable(c.dbType)
		c.logger.Warn("database query failed", zap.String("ip", ipAddress), zap.Error(dbError))
		code := c.deriveCodeForDatabaseError()
		c.observeRequest(codeToMetricsResult(code))
		return c.createVerdict(
			code,
			fmt.Sprintf("database unavailable: %v", dbError),
		), nil
	}

	// Derive verdict from match result and action
	code, reason := c.deriveVerdict(ipAddress, matched)
	c.observeRequest(codeToMetricsResult(code))
	return c.createVerdict(code, reason), nil
}

// Name implements controller.AuthorizationController
func (c *ipMatchDatabaseAuthorizationController) Name() string {
	return c.name
}

// Kind implements controller.AuthorizationController
func (c *ipMatchDatabaseAuthorizationController) Kind() string {
	return ControllerKind
}

// HealthCheck implements controller.AuthorizationController
func (c *ipMatchDatabaseAuthorizationController) HealthCheck(ctx context.Context) error {
	return c.dataSource.HealthCheck(ctx)
}

// queryDatabase queries the data source with timeout
func (c *ipMatchDatabaseAuthorizationController) queryDatabase(ctx context.Context, ipAddress string) (bool, error) {
	start := time.Now()
	matched, err := c.dataSource.Contains(ctx, ipAddress)
	duration := time.Since(start)

	logFields := []zap.Field{
		zap.String("ip", ipAddress),
		zap.String("db_type", c.dbType),
		zap.Duration("duration", duration),
	}

	if err != nil {
		logFields = append(logFields, zap.Error(err))
		c.observeQuery(c.dbType, "error", duration)
	} else if matched {
		logFields = append(logFields, zap.Bool("matched", true))
		c.observeQuery(c.dbType, "found", duration)
	} else {
		logFields = append(logFields, zap.Bool("matched", false))
		c.observeQuery(c.dbType, "not_found", duration)
	}

	c.logger.Debug("database query", logFields...)

	return matched, err
}

// codeToMetricsResult converts a gRPC status code to a result label for metrics
func codeToMetricsResult(code codes.Code) string {
	if code == codes.OK {
		return "allow"
	}
	if code == codes.PermissionDenied {
		return "deny"
	}
	return "error"
}

// deriveCodeForInvalidIP returns the appropriate status code when IP is invalid
func (c *ipMatchDatabaseAuthorizationController) deriveCodeForInvalidIP() codes.Code {
	// Invalid IP is treated similar to "not found"
	if c.action == "allow" {
		return codes.PermissionDenied
	}
	return codes.OK
}

// deriveCodeForDatabaseError returns the appropriate status code when database is unavailable
func (c *ipMatchDatabaseAuthorizationController) deriveCodeForDatabaseError() codes.Code {
	if c.alwaysDenyOnDbUnavailable {
		return codes.PermissionDenied
	}

	// Default behavior: fail-closed for allow, fail-open for deny
	if c.action == "allow" {
		return codes.PermissionDenied
	}
	return codes.OK
}

// deriveVerdict maps the action and match result to a status code and reason
func (c *ipMatchDatabaseAuthorizationController) deriveVerdict(ipAddress string, matched bool) (codes.Code, string) {
	var code codes.Code
	var reason string

	if matched {
		if c.action == "allow" {
			code = codes.OK
			reason = fmt.Sprintf("IP %s found in '%s' allow-list", ipAddress, c.dbType)
		} else {
			code = codes.PermissionDenied
			reason = fmt.Sprintf("IP %s found in '%s' black-list", ipAddress, c.dbType)
		}
	} else {
		if c.action == "allow" {
			code = codes.PermissionDenied
			reason = fmt.Sprintf("IP %s not found in '%s' allow-list", ipAddress, c.dbType)
		} else {
			code = codes.OK
			reason = fmt.Sprintf("IP %s not found in '%s' black-list", ipAddress, c.dbType)
		}
	}

	return code, reason
}

// createVerdict constructs an AuthorizationVerdict with the given code and reason
func (c *ipMatchDatabaseAuthorizationController) createVerdict(code codes.Code, reason string) *controller.AuthorizationVerdict {
	return &controller.AuthorizationVerdict{
		Controller:     c.name,
		ControllerKind: ControllerKind,
		Code:           code,
		Reason:         reason,
		InPolicy:       c.inPolicy(code),
	}
}

func (c *ipMatchDatabaseAuthorizationController) inPolicy(code codes.Code) bool {
	if code == codes.OK {
		return c.action == "allow"
	}
	return c.action == "deny"
}

// newIpMatchDatabaseAuthorizationController constructs a controller from configuration
func newIpMatchDatabaseAuthorizationController(ctx context.Context, logger *zap.Logger, cfg config.ControllerConfig) (controller.AuthorizationController, error) {
	// Decode configuration
	var controllerConfig IpMatchDatabaseConfig
	if err := controller.DecodeControllerSettings(cfg.Settings, &controllerConfig); err != nil {
		return nil, fmt.Errorf("failed to decode settings: %w", err)
	}

	// Apply defaults
	controllerConfig.ApplyDefaults()

	// Validate configuration
	if err := controllerConfig.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	// Create context with timeout for initialization
	initCtx, cancel := context.WithTimeout(ctx, controllerConfig.GetDatabaseConnectionTimeout())
	defer cancel()

	// Create data source based on type
	var dataSource DataSource
	var dbType string
	var err error

	switch controllerConfig.Database.Type {
	case "redis":
		dataSource, err = NewRedisDataSource(initCtx, controllerConfig.Database.Redis)
		if err != nil {
			return nil, fmt.Errorf("failed to create Redis data source: %w", err)
		}
		dbType = "redis"
		logger.Info("connected to Redis",
			zap.String("host", controllerConfig.Database.Redis.Host),
			zap.Int("port", controllerConfig.Database.Redis.Port),
			zap.Int("db", controllerConfig.Database.Redis.DB),
		)
	case "postgres":
		dataSource, err = NewPostgresDataSource(initCtx, controllerConfig.Database.Postgres)
		if err != nil {
			return nil, fmt.Errorf("failed to create PostgreSQL data source: %w", err)
		}
		dbType = "postgres"
		logger.Info("connected to PostgreSQL",
			zap.String("host", controllerConfig.Database.Postgres.Host),
			zap.Int("port", controllerConfig.Database.Postgres.Port),
			zap.String("database", controllerConfig.Database.Postgres.DatabaseName),
		)
	default:
		return nil, fmt.Errorf("unsupported database type: %s", controllerConfig.Database.Type)
	}

	// Create cache if configured
	var cache *Cache
	cacheTTL := controllerConfig.GetCacheTTL()
	if cacheTTL > 0 {
		cache = NewCache(cacheTTL)
		logger.Info("caching enabled", zap.Duration("ttl", cacheTTL))
	} else {
		logger.Info("caching disabled")
	}

	logger.Info("controller initialized",
		zap.String("action", controllerConfig.Action),
		zap.String("db_type", dbType),
		zap.Bool("alwaysDenyOnDbUnavailable", controllerConfig.AlwaysDenyOnDbUnavailable),
	)

	// Setup cleanup when context is canceled
	go func() {
		<-ctx.Done()
		if err := dataSource.Close(); err != nil {
			logger.Error("failed to close data source", zap.String("db_type", dbType), zap.Error(err))
		}
	}()

	return &ipMatchDatabaseAuthorizationController{
		name:                      cfg.Name,
		action:                    controllerConfig.Action,
		alwaysDenyOnDbUnavailable: controllerConfig.AlwaysDenyOnDbUnavailable,
		dataSource:                dataSource,
		cache:                     cache,
		dbType:                    dbType,
		logger:                    logger,
	}, nil
}
