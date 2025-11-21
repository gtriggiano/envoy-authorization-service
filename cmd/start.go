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

	"github.com/gtriggiano/envoy-authorization-service/pkg/auth"
	"github.com/gtriggiano/envoy-authorization-service/pkg/config"
	"github.com/gtriggiano/envoy-authorization-service/pkg/controller"
	grpcserver "github.com/gtriggiano/envoy-authorization-service/pkg/grpc"
	"github.com/gtriggiano/envoy-authorization-service/pkg/logging"
	"github.com/gtriggiano/envoy-authorization-service/pkg/metrics"
	"github.com/gtriggiano/envoy-authorization-service/pkg/policy"

	// Register analysis controllers
	_ "github.com/gtriggiano/envoy-authorization-service/pkg/analysis/maxmind_asn"
	_ "github.com/gtriggiano/envoy-authorization-service/pkg/analysis/maxmind_geoip"

	// Register authorization controllers
	_ "github.com/gtriggiano/envoy-authorization-service/pkg/authorization/asn_match"
	_ "github.com/gtriggiano/envoy-authorization-service/pkg/authorization/ip_match"
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

		runCtx, cancel := context.WithCancel(context.Background())
		defer cancel()

		metricsServer := metrics.NewServer(cfg.Metrics, baseLogger.With(zap.String("component", "metrics")))
		defer metricsServer.SetReady(false)
		instrumentation := metricsServer.Instrumentation()

		analysisControllers, err := controller.BuildAnalysisControllers(runCtx, baseLogger.With(zap.String("component", "analysis-controller")), cfg.AnalysisControllers)
		if err != nil {
			logger.Error("could not build analysis controllers", zap.Error(err))
			return err
		}

		authorizationControllers, err := controller.BuildAuthorizationControllers(runCtx, baseLogger.With(zap.String("component", "authorization-controller")), cfg.AuthorizationControllers)
		if err != nil {
			logger.Error("could not build authorization controllers", zap.Error(err))
			return err
		}

		authorizationPolicy, err := policy.Parse(cfg.AuthorizationPolicy, cfg.EnabledAuthorizationControllerNames())
		if err != nil {
			logger.Error("could not parse authorization policy", zap.Error(err))
			return err
		}

		manager := auth.NewManager(analysisControllers, authorizationControllers, baseLogger.With(zap.String("component", "auth")), instrumentation, authorizationPolicy, cfg.AuthorizationPolicyBypass)
		grpcSrv, err := grpcserver.NewServer(cfg.Server, baseLogger.With(zap.String("component", "grpc")), manager)
		if err != nil {
			logger.Error("could not create gRPC server", zap.Error(err))
			return err
		}

		g, ctx := errgroup.WithContext(runCtx)

		g.Go(func() error {
			return metricsServer.Start(ctx)
		})

		g.Go(func() error {
			return grpcSrv.Start(ctx, func() { metricsServer.SetReady(true) })
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
				cancel()
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

		if err := g.Wait(); err != nil && ctx.Err() == nil {
			logger.Error("server exited with error", zap.Error(err))
			return err
		}
		return nil
	},
}
