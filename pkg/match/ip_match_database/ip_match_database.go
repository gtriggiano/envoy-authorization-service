package ip_match_database

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc/codes"

	"github.com/gtriggiano/envoy-authorization-service/pkg/config"
	"github.com/gtriggiano/envoy-authorization-service/pkg/controller"
	"github.com/gtriggiano/envoy-authorization-service/pkg/metrics"
	"github.com/gtriggiano/envoy-authorization-service/pkg/runtime"
)

const (
	ControllerKind = "ip-match-database"
)

// init registers the ip-match-database match controller
func init() {
	controller.RegisterMatchControllerFactory(ControllerKind, newIpMatchDatabaseController)
}

type ipMatchDatabaseController struct {
	name             string
	matchesOnFailure bool
	dataSource       DataSource
	cache            *Cache
	dbType           string
	instrumentation  *metrics.Instrumentation
	logger           *zap.Logger
}

// SetInstrumentation injects the shared metrics instrumentation.
func (c *ipMatchDatabaseController) SetInstrumentation(inst *metrics.Instrumentation) {
	c.instrumentation = inst
}

// Match implements controller.MatchController
func (c *ipMatchDatabaseController) Match(ctx context.Context, req *runtime.RequestContext, reports controller.AnalysisReports) (*controller.MatchVerdict, error) {
	// Validate IP address
	if !req.IpAddress.IsValid() {
		verdict := c.createVerdict(c.matchesOnFailure, "unable to determine source IP address")
		c.observeMatchDatabaseRequest(req.Authority, verdict.IsMatch, true)
		return verdict, nil
	}

	ipAddress := req.IpAddress.String()

	// Check cache first
	var matched bool
	var dbError error

	if c.cache != nil {
		if cachedMatch, found := c.cache.Get(ipAddress); found {
			c.observeCacheHit(req.Authority)
			c.logger.Debug("cache hit", zap.String("ip", ipAddress), zap.Bool("matched", cachedMatch))
			matched = cachedMatch
		} else {
			c.observeCacheMiss(req.Authority)
			c.logger.Debug("cache miss", zap.String("ip", ipAddress))
			matched, dbError = c.queryDatabase(ctx, req.Authority, ipAddress)

			// Cache the result if query was successful
			if dbError == nil {
				c.cache.Set(ipAddress, matched)
				c.logger.Debug("cache update", zap.String("ip", ipAddress))
				c.observeCacheSize(req.Authority)
			}
		}
	} else {
		// No cache, query database directly
		matched, dbError = c.queryDatabase(ctx, req.Authority, ipAddress)
	}

	success := true
	var verdict *controller.MatchVerdict

	// Handle database errors
	if dbError != nil {
		success = false
		c.observeUnavailable(req.Authority)
		c.logger.Warn("database query failed", zap.String("ip", ipAddress), zap.Error(dbError))
		verdict = c.createVerdict(c.matchesOnFailure, fmt.Sprintf("database unavailable: %v", dbError))
	} else {
		verdict = c.createVerdict(matched, c.getVerdictDescription(ipAddress, matched))
	}

	c.observeMatchDatabaseRequest(req.Authority, verdict.IsMatch, success)
	return verdict, nil
}

// Name implements controller.MatchController
func (c *ipMatchDatabaseController) Name() string {
	return c.name
}

// Kind implements controller.MatchController
func (c *ipMatchDatabaseController) Kind() string {
	return ControllerKind
}

// HealthCheck implements controller.MatchController
func (c *ipMatchDatabaseController) HealthCheck(ctx context.Context) error {
	return c.dataSource.HealthCheck(ctx)
}

// queryDatabase queries the data source with timeout
func (c *ipMatchDatabaseController) queryDatabase(ctx context.Context, authority, ipAddress string) (bool, error) {
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
	} else {
		logFields = append(logFields, zap.Bool("matched", matched))
	}

	c.observeQuery(authority, matched, err, duration)

	c.logger.Debug("database query", logFields...)

	return matched, err
}

// createVerdict constructs a MatchVerdict with the given details
func (c *ipMatchDatabaseController) createVerdict(isMatch bool, description string) *controller.MatchVerdict {
	return &controller.MatchVerdict{
		Controller:     c.name,
		ControllerType: ControllerKind,
		DenyCode:       codes.PermissionDenied,
		Description:    description,
		IsMatch:        isMatch,
	}
}

// getVerdictDescription generates a description for the verdict based on match result
func (c *ipMatchDatabaseController) getVerdictDescription(ipAddress string, matched bool) string {
	if matched {
		return fmt.Sprintf("IP %s found in '%s'", ipAddress, c.dbType)
	}
	return fmt.Sprintf("IP %s not found in '%s'", ipAddress, c.dbType)
}

func (c *ipMatchDatabaseController) observeMatchDatabaseRequest(authority string, matched bool, success bool) {
	c.instrumentation.ObserveMatchDatabaseRequest(authority, c.name, ControllerKind, c.dbType, matched, success)
}

func (c *ipMatchDatabaseController) observeQuery(authority string, matched bool, err error, duration time.Duration) {
	c.instrumentation.ObserveMatchDatabaseQuery(authority, c.name, ControllerKind, c.dbType, matched, err, duration)
}

func (c *ipMatchDatabaseController) observeCacheHit(authority string) {
	c.instrumentation.ObserveMatchDatabaseCacheHit(authority, c.name, ControllerKind, c.dbType)
}

func (c *ipMatchDatabaseController) observeCacheMiss(authority string) {
	c.instrumentation.ObserveMatchDatabaseCacheMiss(authority, c.name, ControllerKind, c.dbType)
}

func (c *ipMatchDatabaseController) observeCacheSize(authority string) {
	if c.cache == nil {
		return
	}
	c.instrumentation.ObserveMatchDatabaseCacheSize(authority, c.name, ControllerKind, c.dbType, c.cache.Size())
}

func (c *ipMatchDatabaseController) observeUnavailable(authority string) {
	c.instrumentation.ObserveMatchDatabaseUnavailable(authority, c.name, ControllerKind, c.dbType)
}

// newIpMatchDatabaseController constructs a controller from configuration
func newIpMatchDatabaseController(ctx context.Context, logger *zap.Logger, cfg config.ControllerConfig) (controller.MatchController, error) {
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
		dbType = metrics.REDIS
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
		dbType = metrics.POSTGRES
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
		zap.String("db_type", dbType),
		zap.Bool("matchesOnFailure", controllerConfig.MatchesOnFailure),
	)

	// Setup cleanup when context is canceled
	go func() {
		<-ctx.Done()
		if err := dataSource.Close(); err != nil {
			logger.Error("failed to close data source", zap.String("db_type", dbType), zap.Error(err))
		}
	}()

	return &ipMatchDatabaseController{
		name:             cfg.Name,
		matchesOnFailure: controllerConfig.MatchesOnFailure,
		dataSource:       dataSource,
		cache:            cache,
		dbType:           dbType,
		logger:           logger,
	}, nil
}
