package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/gtriggiano/envoy-authorization-service/pkg/config"
	"github.com/gtriggiano/envoy-authorization-service/pkg/controller"
	"github.com/gtriggiano/envoy-authorization-service/pkg/logging"
	"github.com/gtriggiano/envoy-authorization-service/pkg/metrics"
	"github.com/gtriggiano/envoy-authorization-service/pkg/policy"
	"github.com/gtriggiano/envoy-authorization-service/pkg/service"

	// Register analysis controllers
	_ "github.com/gtriggiano/envoy-authorization-service/pkg/analysis/maxmind_asn"
	_ "github.com/gtriggiano/envoy-authorization-service/pkg/analysis/maxmind_geoip"
	_ "github.com/gtriggiano/envoy-authorization-service/pkg/analysis/ua_detect"

	// Register match controllers
	_ "github.com/gtriggiano/envoy-authorization-service/pkg/match/asn_match"
	_ "github.com/gtriggiano/envoy-authorization-service/pkg/match/asn_match_database"
	_ "github.com/gtriggiano/envoy-authorization-service/pkg/match/ip_match"
	_ "github.com/gtriggiano/envoy-authorization-service/pkg/match/ip_match_database"
)

var (
	cfgFile string
)

// init wires the start subcommand and configuration flag into the CLI.
func init() {
	rootCmd.AddCommand(startCmd)
	startCmd.Flags().StringVar(&cfgFile, "config", "config.yaml", "Path to the configuration file")
}

var startCmd = &cobra.Command{
	Use:           "start",
	Short:         "Start the authorization server",
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		path, err := filepath.Abs(cfgFile)
		if err != nil {
			return fmt.Errorf("resolve config path: %w", err)
		}
		cfg, err := config.Load(path)
		if err != nil {
			return err
		}

		baseLogger, err := logging.New(cfg.Logging)
		if err != nil {
			return err
		}
		defer func() { _ = baseLogger.Sync() }()
		logger := baseLogger.With(zap.String("component", "cli"))

		runCtx, cancelRunCtx := context.WithCancel(context.Background())
		defer cancelRunCtx()

		analysisControllers, err := controller.BuildAnalysisControllers(runCtx, baseLogger.With(zap.String("component", "analysis-controller")), cfg.AnalysisControllers)
		if err != nil {
			logger.Error("could not build analysis controllers", zap.Error(err))
			return err
		}

		matchControllers, err := controller.BuildMatchControllers(runCtx, baseLogger.With(zap.String("component", "match-controller")), cfg.MatchControllers)
		if err != nil {
			logger.Error("could not build match controllers", zap.Error(err))
			return err
		}

		authorizationPolicy, err := policy.Parse(cfg.AuthorizationPolicy, cfg.EnabledMatchControllerNames())
		if err != nil {
			logger.Error("could not parse authorization policy", zap.Error(err))
			return err
		}

		metricsServer := metrics.NewServer(cfg.Metrics, baseLogger.With(zap.String("component", "metrics-server")), analysisControllers, matchControllers)
		metricsServer.SetReady(false)

		serviceServer, err := service.NewServer(
			cfg.Server,
			service.NewManager(
				analysisControllers,
				matchControllers,
				metricsServer.Instrumentation(),
				authorizationPolicy,
				cfg.AuthorizationPolicyBypass,
				baseLogger.With(zap.String("component", "service-manager")),
			),
			baseLogger.With(zap.String("component", "service-server")),
		)
		if err != nil {
			logger.Error("could not create gRPC server", zap.Error(err))
			return err
		}

		serversGroup, serversCtx := errgroup.WithContext(runCtx)

		serversGroup.Go(func() error {
			return metricsServer.Start(serversCtx)
		})

		serversGroup.Go(func() error {
			return serviceServer.Start(serversCtx, func() { metricsServer.SetReady(true) })
		})

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
		defer signal.Stop(sigCh)

		done := make(chan struct{})
		defer close(done)

		go func() {
			select {
			case <-sigCh:
				logger.Info("shutdown signal received")
				cancelRunCtx()
				timeout := cfg.Shutdown.ShutdownTimeout()
				timer := time.NewTimer(timeout)
				defer timer.Stop()
				select {
				case <-done:
				case <-timer.C:
					logger.Error("shutdown timed out", zap.String("timeout", timeout.String()))
					os.Exit(1)
				}
			case <-done:
				return
			}
		}()

		if err := serversGroup.Wait(); err != nil && serversCtx.Err() == nil {
			logger.Error("server exited with error", zap.Error(err))
			return err
		}
		return nil
	},
}
