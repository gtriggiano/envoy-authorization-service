package asn_match_database

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc/codes"

	"github.com/gtriggiano/envoy-authorization-service/pkg/analysis/maxmind_asn"
	"github.com/gtriggiano/envoy-authorization-service/pkg/config"
	"github.com/gtriggiano/envoy-authorization-service/pkg/controller"
	"github.com/gtriggiano/envoy-authorization-service/pkg/metrics"
	"github.com/gtriggiano/envoy-authorization-service/pkg/runtime"
)

const (
	ControllerKind = "asn-match-database"
)

// init registers the asn-match-database match controller
func init() {
	controller.RegisterMatchControllerFactory(ControllerKind, newASNMatchDatabaseController)
}

type asnMatchDatabaseController struct {
	name             string
	matchesOnFailure bool
	dataSource       DataSource
	cache            *Cache
	dbType           string
	instrumentation  *metrics.Instrumentation
	logger           *zap.Logger
}

// SetInstrumentation injects the shared metrics instrumentation.
func (c *asnMatchDatabaseController) SetInstrumentation(inst *metrics.Instrumentation) {
	c.instrumentation = inst
}

// Match implements controller.MatchController
func (c *asnMatchDatabaseController) Match(ctx context.Context, req *runtime.RequestContext, reports controller.AnalysisReports) (*controller.MatchVerdict, error) {
	var lookupResult *maxmind_asn.IpLookupResult
	for _, report := range reports {
		if report == nil || report.ControllerKind != maxmind_asn.ControllerKind {
			continue
		}
		lookupResult = maxmind_asn.GetIpLookupResultFromReport(report)
		if lookupResult != nil {
			break
		}
	}

	success := true

	if lookupResult == nil {
		verdict := c.createVerdict(c.matchesOnFailure, "no ASN information available")
		c.observeMatchDatabaseRequest(req.Authority, verdict.IsMatch, success)
		return verdict, nil
	}

	asn := lookupResult.AutonomousSystemNumber
	asnKey := strconv.FormatUint(uint64(asn), 10)

	// Check cache first
	var matched bool
	var dbError error

	if c.cache != nil {
		if cachedMatch, found := c.cache.Get(asnKey); found {
			c.observeCacheHit(req.Authority)
			c.logger.Debug("cache hit", zap.Uint("asn", asn), zap.Bool("matched", cachedMatch))
			matched = cachedMatch
		} else {
			c.observeCacheMiss(req.Authority)
			c.logger.Debug("cache miss", zap.Uint("asn", asn))
			matched, dbError = c.queryDatabase(ctx, req.Authority, asn)

			// Cache the result if query was successful
			if dbError == nil {
				c.cache.Set(asnKey, matched)
				c.observeCacheSize(req.Authority)
			}
		}
	} else {
		// No cache, query database directly
		matched, dbError = c.queryDatabase(ctx, req.Authority, asn)
	}

	// Handle database errors
	var verdict *controller.MatchVerdict
	if dbError != nil {
		success = false
		c.observeUnavailable(req.Authority)
		c.logger.Warn("database query failed", zap.Uint("asn", asn), zap.Error(dbError))
		verdict = c.createVerdict(c.matchesOnFailure, fmt.Sprintf("database unavailable: %v", dbError))
	} else {
		verdict = c.createVerdict(matched, c.getVerdictDescription(asn, matched))
	}

	c.observeMatchDatabaseRequest(req.Authority, verdict.IsMatch, success)
	return verdict, nil
}

// Name implements controller.MatchController
func (c *asnMatchDatabaseController) Name() string {
	return c.name
}

// Kind implements controller.MatchController
func (c *asnMatchDatabaseController) Kind() string {
	return ControllerKind
}

// HealthCheck implements controller.MatchController
func (c *asnMatchDatabaseController) HealthCheck(ctx context.Context) error {
	return c.dataSource.HealthCheck(ctx)
}

// queryDatabase queries the data source with timeout
func (c *asnMatchDatabaseController) queryDatabase(ctx context.Context, authority string, asn uint) (bool, error) {
	start := time.Now()
	matched, err := c.dataSource.Contains(ctx, asn)
	duration := time.Since(start)

	logFields := []zap.Field{
		zap.Uint("asn", asn),
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
func (c *asnMatchDatabaseController) createVerdict(isMatch bool, description string) *controller.MatchVerdict {
	return &controller.MatchVerdict{
		Controller:     c.name,
		ControllerType: ControllerKind,
		DenyCode:       codes.PermissionDenied,
		Description:    description,
		IsMatch:        isMatch,
	}
}

// getVerdictDescription generates a description for the verdict based on match result
func (c *asnMatchDatabaseController) getVerdictDescription(asn uint, matched bool) string {
	if matched {
		return fmt.Sprintf("ASN %d found in '%s'", asn, c.dbType)
	}
	return fmt.Sprintf("ASN %d not found in '%s'", asn, c.dbType)
}

func (c *asnMatchDatabaseController) observeMatchDatabaseRequest(authority string, matched bool, success bool) {
	c.instrumentation.ObserveMatchDatabaseRequest(authority, c.name, ControllerKind, c.dbType, matched, success)
}

func (c *asnMatchDatabaseController) observeQuery(authority string, matched bool, err error, duration time.Duration) {
	c.instrumentation.ObserveMatchDatabaseQuery(authority, c.name, ControllerKind, c.dbType, matched, err, duration)
}

func (c *asnMatchDatabaseController) observeCacheHit(authority string) {
	c.instrumentation.ObserveMatchDatabaseCacheHit(authority, c.name, ControllerKind, c.dbType)
}

func (c *asnMatchDatabaseController) observeCacheMiss(authority string) {
	c.instrumentation.ObserveMatchDatabaseCacheMiss(authority, c.name, ControllerKind, c.dbType)
}

func (c *asnMatchDatabaseController) observeCacheSize(authority string) {
	if c.cache == nil {
		return
	}
	c.instrumentation.ObserveMatchDatabaseCacheSize(authority, c.name, ControllerKind, c.dbType, c.cache.Size())
}

func (c *asnMatchDatabaseController) observeUnavailable(authority string) {
	c.instrumentation.ObserveMatchDatabaseUnavailable(authority, c.name, ControllerKind, c.dbType)
}

// newASNMatchDatabaseController constructs a controller from configuration
func newASNMatchDatabaseController(ctx context.Context, logger *zap.Logger, cfg config.ControllerConfig) (controller.MatchController, error) {
	// Decode configuration
	var controllerConfig ASNMatchDatabaseConfig
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

	return &asnMatchDatabaseController{
		name:             cfg.Name,
		matchesOnFailure: controllerConfig.MatchesOnFailure,
		dataSource:       dataSource,
		cache:            cache,
		dbType:           dbType,
		logger:           logger,
	}, nil
}
