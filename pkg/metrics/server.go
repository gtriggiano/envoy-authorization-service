package metrics

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	"github.com/gtriggiano/envoy-authorization-service/pkg/config"
)

const (
	// Server timeouts
	defaultGracefulShutdownTimeout = 5 * time.Second
)

// Server exposes Prometheus metrics and health probes.
type Server struct {
	cfg             config.MetricsConfig
	logger          *zap.Logger
	registry        *prometheus.Registry
	instrumentation *Instrumentation
	httpServer      *http.Server
}

// NewServer builds a metrics server instance.
func NewServer(cfg config.MetricsConfig, logger *zap.Logger) *Server {
	reg := prometheus.NewRegistry()
	inst := NewInstrumentation(reg)
	return &Server{cfg: cfg, logger: logger, registry: reg, instrumentation: inst}
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
	mux.Handle("/metrics", promhttp.HandlerFor(s.registry, promhttp.HandlerOpts{}))

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
	s.instrumentation.SetReady(ready)
}

// livenessHandler exposes a simple OK response for Kubernetes-style health probes.
func (s *Server) livenessHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

// readinessHandler reports readiness based on instrumentation state.
func (s *Server) readinessHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !s.instrumentation.Ready() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})
}
