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

// AuthorizationVerdict represents the outcome of an authorization controller.
type AuthorizationVerdict struct {
	Controller        string
	ControllerKind    string
	Code              codes.Code
	Reason            string
	InPolicy          bool
	DownstreamHeaders map[string]string
	UpstreamHeaders   map[string]string
}

func (av *AuthorizationVerdict) IsAllow() bool {
	return av.Code == codes.OK
}

func (av *AuthorizationVerdict) IsDeny() bool {
	return av.Code != codes.OK
}

// AuthorizationVerdicts collects verdicts indexed by controller name.
type AuthorizationVerdicts map[string]*AuthorizationVerdict

// AnalysisController defines analysis behavior prior to authorization.
type AnalysisController interface {
	Name() string
	Kind() string
	Analyze(ctx context.Context, req *runtime.RequestContext) (*AnalysisReport, error)
	HealthCheck(ctx context.Context) error
}

// AuthorizationController defines how a controller makes authorization decisions.
type AuthorizationController interface {
	Name() string
	Kind() string
	Authorize(ctx context.Context, req *runtime.RequestContext, reports AnalysisReports) (*AuthorizationVerdict, error)
	HealthCheck(ctx context.Context) error
}

// AnalysisFactory builds an analysis controller instance from configuration.
type AnalysisFactory func(ctx context.Context, logger *zap.Logger, cfg config.ControllerConfig) (AnalysisController, error)

// AuthorizationFactory builds an authorization controller from configuration.
type AuthorizationFactory func(ctx context.Context, logger *zap.Logger, cfg config.ControllerConfig) (AuthorizationController, error)

type registry[T any] struct {
	mu        sync.RWMutex
	factories map[string]T
}

var (
	analysisRegistry      = newRegistry[AnalysisFactory]()
	authorizationRegistry = newRegistry[AuthorizationFactory]()
)

// newRegistry initializes a typed controller factory registry.
func newRegistry[T any]() *registry[T] {
	return &registry[T]{factories: make(map[string]T)}
}

// RegisterAnalysis associates an analysis controller type with a factory.
func RegisterAnalysis(kind string, factory AnalysisFactory) {
	if err := register(analysisRegistry, kind, factory); err != nil {
		panic(err)
	}
}

// RegisterAuthorization associates an authorization controller type with a factory.
func RegisterAuthorization(kind string, factory AuthorizationFactory) {
	if err := register(authorizationRegistry, kind, factory); err != nil {
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

		factory, ok := getFactory(analysisRegistry, configuration.Type)
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

// BuildAuthorizationControllers creates authorization controller instances from configuration definitions.
func BuildAuthorizationControllers(ctx context.Context, logger *zap.Logger, configurations []config.ControllerConfig) ([]AuthorizationController, error) {
	controllers := make([]AuthorizationController, 0, len(configurations))
	for _, configuration := range configurations {
		if !configuration.IsEnabled() {
			continue
		}

		factory, ok := getFactory(authorizationRegistry, configuration.Type)
		if !ok {
			return nil, fmt.Errorf("authorization controller '%s' is of unknown type '%s'", configuration.Name, configuration.Type)
		}

		controller, err := factory(ctx, logger.With(zap.String("controller_name", configuration.Name), zap.String("controller_type", configuration.Type)), configuration)
		if err != nil {
			return nil, fmt.Errorf("could not build authorization controller '%s' of type '%s': %w", configuration.Name, configuration.Type, err)
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
