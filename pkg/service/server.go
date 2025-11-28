package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"

	"github.com/gtriggiano/envoy-authorization-service/pkg/config"
)

const (
	// Server timeouts
	defaultGracefulShutdownTimeout = 5 * time.Second
)

// Server wraps the Envoy authorization gRPC server.
type Server struct {
	cfg        config.ServerConfig
	manager    *Manager
	grpcServer *grpc.Server
	logger     *zap.Logger
}

// NewServer constructs the gRPC server and registers handlers.
func NewServer(cfg config.ServerConfig, manager *Manager, logger *zap.Logger) (*Server, error) {
	opts := []grpc.ServerOption{}
	if cfg.TLS != nil {
		tlsConfig, err := buildTLSConfig(cfg)
		if err != nil {
			return nil, err
		}
		opts = append(opts, grpc.Creds(credentials.NewTLS(tlsConfig)))
	}

	grpcServer := grpc.NewServer(opts...)
	reflection.Register(grpcServer)
	authv3Server := &authorizationService{manager: manager, logger: logger}
	registerService(grpcServer, authv3Server)

	return &Server{cfg: cfg, manager: manager, grpcServer: grpcServer, logger: logger}, nil
}

// Start begins serving and blocks until context cancellation or server error.
func (s *Server) Start(ctx context.Context, onReady func()) error {
	listener, err := net.Listen("tcp", s.cfg.Address)
	if err != nil {
		return fmt.Errorf("failed to listen on address '%s': %w", s.cfg.Address, err)
	}

	if onReady != nil {
		onReady()
	}

	go func() {
		<-ctx.Done()
		done := make(chan struct{})
		go func() {
			s.grpcServer.GracefulStop()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(defaultGracefulShutdownTimeout):
			s.grpcServer.Stop()
		}
	}()

	s.logger.Info("gRPC server listening", zap.String("addr", s.cfg.Address))
	err = s.grpcServer.Serve(listener)
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		return nil
	}
	return err
}

// buildTLSConfig loads TLS assets and returns a server TLS configuration.
func buildTLSConfig(cfg config.ServerConfig) (*tls.Config, error) {
	tlsCfg := &tls.Config{}
	if cfg.TLS == nil {
		return tlsCfg, nil
	}

	cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("could not load server certificate: %w", err)
	}
	tlsCfg.Certificates = []tls.Certificate{cert}

	if cfg.TLS.CAFile != "" {
		caData, err := os.ReadFile(cfg.TLS.CAFile)
		if err != nil {
			return nil, fmt.Errorf("could not load CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caData) {
			return nil, fmt.Errorf("CA certificates addition failed")
		}
		tlsCfg.ClientCAs = pool
	}

	if cfg.TLS.RequireClientCert {
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return tlsCfg, nil
}

type authorizationService struct {
	authv3.UnimplementedAuthorizationServer
	manager *Manager
	logger  *zap.Logger
}

// registerService wires up the Envoy authorization service with the gRPC server.
func registerService(server *grpc.Server, svc *authorizationService) {
	authv3.RegisterAuthorizationServer(server, svc)
}

// Check proxies Envoy authorization requests to the manager and logs failures.
func (s *authorizationService) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	resp, err := s.manager.Check(ctx, req)
	if err != nil {
		s.logger.Error("authorization error", zap.Error(err))
		return nil, err
	}
	return resp, nil
}
