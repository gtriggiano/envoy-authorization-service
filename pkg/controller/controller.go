package controller

import (
	"context"
	"fmt"
	"sync"

	"go.uber.org/zap"
	"go.yaml.in/yaml/v2"
	"google.golang.org/grpc/codes"

	"github.com/gtriggiano/envoy-authorization-service/pkg/config"
	"github.com/gtriggiano/envoy-authorization-service/pkg/runtime"
)

// AnalysisReport is produced during the identification phase.
type AnalysisReport struct {
	Controller      string
	ControllerKind  string
	UpstreamHeaders map[string]string
	Data            map[string]any
}

// AnalysisReports is the collection of analysis reports indexed by controller name.
type AnalysisReports map[string]*AnalysisReport

// MatchVerdict represents the outcome of a match controller.
type MatchVerdict struct {
	Controller            string
	ControllerKind        string
	DenyCode              codes.Code
	Description           string
	IsMatch               bool
	DenyDownstreamHeaders map[string]string
	AllowUpstreamHeaders  map[string]string
}

// MatchVerdicts collects verdicts indexed by controller name.
type MatchVerdicts map[string]*MatchVerdict

// AnalysisController defines analysis behavior prior to authorization.
type AnalysisController interface {
	Name() string
	Kind() string
	Analyze(ctx context.Context, req *runtime.RequestContext) (*AnalysisReport, error)
	HealthCheck(ctx context.Context) error
}

// MatchController defines how a controller evaluates request matches.
type MatchController interface {
	Name() string
	Kind() string
	Match(ctx context.Context, req *runtime.RequestContext, reports AnalysisReports) (*MatchVerdict, error)
	HealthCheck(ctx context.Context) error
}

// AnalysisControllerFactory builds an analysis controller instance from configuration.
type AnalysisControllerFactory func(ctx context.Context, logger *zap.Logger, cfg config.ControllerConfig) (AnalysisController, error)

// MatchControllerFactory builds a match controller from configuration.
type MatchControllerFactory func(ctx context.Context, logger *zap.Logger, cfg config.ControllerConfig) (MatchController, error)

type registry[T any] struct {
	mu        sync.RWMutex
	factories map[string]T
}

var (
	analysisControllersRegistry = newRegistry[AnalysisControllerFactory]()
	matchControllersRegistry    = newRegistry[MatchControllerFactory]()
)

// newRegistry initializes a typed controller factory registry.
func newRegistry[T any]() *registry[T] {
	return &registry[T]{factories: make(map[string]T)}
}

// RegisterAnalysisControllerFactory associates an analysis controller type with a factory.
func RegisterAnalysisControllerFactory(kind string, factory AnalysisControllerFactory) {
	if err := register(analysisControllersRegistry, kind, factory); err != nil {
		panic(err)
	}
}

// RegisterMatchControllerFactory associates a match controller type with a factory.
func RegisterMatchControllerFactory(kind string, factory MatchControllerFactory) {
	if err := register(matchControllersRegistry, kind, factory); err != nil {
		panic(err)
	}
}

// register stores a factory in the provided registry while enforcing uniqueness.
func register[T any](reg *registry[T], kind string, factory T) error {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	if kind == "" {
		return fmt.Errorf("controller factory kind cannot be empty")
	}
	if _, exists := reg.factories[kind]; exists {
		return fmt.Errorf("controller factory for '%s' is already registered", kind)
	}
	reg.factories[kind] = factory
	return nil
}

// getFactory looks up a factory by kind and reports whether it was found.
func getFactory[T any](reg *registry[T], kind string) (T, bool) {
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	f, ok := reg.factories[kind]
	return f, ok
}

// BuildAnalysisControllers creates analysis controller instances from configuration definitions.
func BuildAnalysisControllers(ctx context.Context, logger *zap.Logger, configurations []config.ControllerConfig) ([]AnalysisController, error) {
	controllers := make([]AnalysisController, 0, len(configurations))
	for _, configuration := range configurations {
		if !configuration.IsEnabled() {
			continue
		}

		factory, ok := getFactory(analysisControllersRegistry, configuration.Type)
		if !ok {
			return nil, fmt.Errorf("analysis controller '%s' is of unknown type '%s'", configuration.Name, configuration.Type)
		}

		controller, err := factory(ctx, logger.With(zap.String("controller_name", configuration.Name), zap.String("controller_type", configuration.Type)), configuration)
		if err != nil {
			return nil, fmt.Errorf("could not build analysis controller '%s' of type '%s': %w", configuration.Name, configuration.Type, err)
		}
		controllers = append(controllers, controller)
	}
	return controllers, nil
}

// BuildMatchControllers creates match controller instances from configuration definitions.
func BuildMatchControllers(ctx context.Context, logger *zap.Logger, configurations []config.ControllerConfig) ([]MatchController, error) {
	controllers := make([]MatchController, 0, len(configurations))
	for _, configuration := range configurations {
		if !configuration.IsEnabled() {
			continue
		}

		factory, ok := getFactory(matchControllersRegistry, configuration.Type)
		if !ok {
			return nil, fmt.Errorf("match controller '%s' is of unknown type '%s'", configuration.Name, configuration.Type)
		}

		controller, err := factory(ctx, logger.With(zap.String("controller_name", configuration.Name), zap.String("controller_type", configuration.Type)), configuration)
		if err != nil {
			return nil, fmt.Errorf("could not build match controller '%s' of type '%s': %w", configuration.Name, configuration.Type, err)
		}
		controllers = append(controllers, controller)
	}
	return controllers, nil
}

// DecodeControllerSettings marshals the untyped settings map into the provided
// struct pointer using YAML for convenience.
func DecodeControllerSettings(settings map[string]any, target any) error {
	if settings == nil {
		return nil
	}
	raw, err := yaml.Marshal(settings)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(raw, target)
}
