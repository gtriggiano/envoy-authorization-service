package metrics

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	"github.com/gtriggiano/envoy-authorization-service/pkg/config"
	"github.com/gtriggiano/envoy-authorization-service/pkg/controller"
)

const (
	// Server timeouts
	defaultGracefulShutdownTimeout = 5 * time.Second
)

// Server exposes Prometheus metrics and health probes.
type Server struct {
	cfg                 config.MetricsConfig
	logger              *zap.Logger
	registry            *prometheus.Registry
	instrumentation     *Instrumentation
	httpServer          *http.Server
	analysisControllers []controller.AnalysisController
	matchControllers    []controller.MatchController
	serviceServerReady  atomic.Bool
}

// NewServer builds a metrics server instance.
func NewServer(
	cfg config.MetricsConfig,
	logger *zap.Logger,
	analysisControllers []controller.AnalysisController,
	matchControllers []controller.MatchController,
) *Server {
	reg := prometheus.NewRegistry()
	inst := NewInstrumentation(reg)

	return &Server{
		cfg:                 cfg,
		logger:              logger,
		registry:            reg,
		instrumentation:     inst,
		analysisControllers: analysisControllers,
		matchControllers:    matchControllers,
	}
}

// Instrumentation returns the metrics instrumentation helper.
func (s *Server) Instrumentation() *Instrumentation {
	return s.instrumentation
}

// Registry returns the underlying Prometheus registry.
func (s *Server) Registry() *prometheus.Registry {
	return s.registry
}

// Start launches the HTTP endpoints and blocks until context cancellation.
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.Handle(s.cfg.HealthPath, s.livenessHandler())
	mux.Handle(s.cfg.ReadinessPath, s.readinessHandler())
	gatherer := prometheus.Gatherers{ // include default registry but filter out configured prefixes
		s.registry,
		filteringGatherer{prometheus.DefaultGatherer, s.cfg.DropPrefixes},
	}
	mux.Handle("/metrics", promhttp.HandlerFor(gatherer, promhttp.HandlerOpts{}))

	srv := &http.Server{
		Addr:    s.cfg.Address,
		Handler: mux,
	}
	s.httpServer = srv

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), defaultGracefulShutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			s.logger.Error("metrics server shutdown", zap.Error(err))
		}
	}()

	s.logger.Info("metrics server listening", zap.String("addr", s.cfg.Address))

	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// SetReady toggles readiness probing state.
func (s *Server) SetReady(ready bool) {
	s.serviceServerReady.Store(ready)
}

// livenessHandler exposes a simple OK response for Kubernetes-style health probes.
func (s *Server) livenessHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

// readinessHandler reports readiness based on instrumentation state and controller health checks.
func (s *Server) readinessHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.serviceServerReady.Load() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}

		// Check health of all controllers in parallel
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		var wg sync.WaitGroup
		var mu sync.Mutex
		healthCheckFailed := false

		// Check analysis controllers
		for _, ctrl := range s.analysisControllers {
			wg.Add(1)
			go func(ctrl controller.AnalysisController) {
				defer wg.Done()
				if err := ctrl.HealthCheck(ctx); err != nil {
					s.logger.Warn("analysis controller health check failed",
						zap.String("controller", ctrl.Name()),
						zap.String("controller_type", ctrl.Kind()),
						zap.Error(err),
					)
					mu.Lock()
					healthCheckFailed = true
					mu.Unlock()
				}
			}(ctrl)
		}

		// Check match controllers
		for _, ctrl := range s.matchControllers {
			wg.Add(1)
			go func(ctrl controller.MatchController) {
				defer wg.Done()
				if err := ctrl.HealthCheck(ctx); err != nil {
					s.logger.Warn("match controller health check failed",
						zap.String("controller", ctrl.Name()),
						zap.String("controller_type", ctrl.Kind()),
						zap.Error(err),
					)
					mu.Lock()
					healthCheckFailed = true
					mu.Unlock()
				}
			}(ctrl)
		}

		wg.Wait()

		if healthCheckFailed {
			http.Error(w, "controller health check failed", http.StatusServiceUnavailable)
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})
}
