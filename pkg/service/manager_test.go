package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap/zaptest"
	"google.golang.org/grpc/codes"

	"github.com/gtriggiano/envoy-authorization-service/pkg/config"
	"github.com/gtriggiano/envoy-authorization-service/pkg/controller"
	"github.com/gtriggiano/envoy-authorization-service/pkg/metrics"
	"github.com/gtriggiano/envoy-authorization-service/pkg/policy"
	"github.com/gtriggiano/envoy-authorization-service/pkg/runtime"
)

// --- Manager helpers --------------------------------------------------------

type stubAnalysisController struct {
	name   string
	kind   string
	report *controller.AnalysisReport
	err    error
}

func (s stubAnalysisController) Name() string { return s.name }
func (s stubAnalysisController) Kind() string { return s.kind }
func (s stubAnalysisController) Analyze(ctx context.Context, _ *runtime.RequestContext) (*controller.AnalysisReport, error) {
	return s.report, s.err
}
func (s stubAnalysisController) HealthCheck(context.Context) error { return nil }

type stubMatchController struct {
	name    string
	kind    string
	verdict *controller.MatchVerdict
	err     error
}

func (s stubMatchController) Name() string { return s.name }
func (s stubMatchController) Kind() string { return s.kind }
func (s stubMatchController) Match(ctx context.Context, _ *runtime.RequestContext, _ controller.AnalysisReports) (*controller.MatchVerdict, error) {
	return s.verdict, s.err
}
func (s stubMatchController) HealthCheck(context.Context) error { return nil }

func minimalCheckRequestUnit(ip string) *authv3.CheckRequest {
	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Source: &authv3.AttributeContext_Peer{
				Address: &corev3.Address{
					Address: &corev3.Address_SocketAddress{
						SocketAddress: &corev3.SocketAddress{Address: ip},
					},
				},
			},
		},
	}
}

// --- runAnalysis / runAuthorization ----------------------------------------

func TestRunAnalysisCollectsReports(t *testing.T) {
	logger := zaptest.NewLogger(t)
	inst := metrics.NewInstrumentation(prometheus.NewRegistry())
	mgr := &Manager{
		analysisControllers: []controller.AnalysisController{
			stubAnalysisController{name: "b", kind: "analysis", report: &controller.AnalysisReport{UpstreamHeaders: map[string]string{"X-B": "b"}}},
			stubAnalysisController{name: "a", kind: "analysis", report: &controller.AnalysisReport{UpstreamHeaders: map[string]string{"X-A": "a"}}},
		},
		instrumentation: inst,
		logger:          logger,
	}

	reports := mgr.runAnalysis(context.Background(), runtime.NewRequestContext(minimalCheckRequestUnit("203.0.113.1")))

	if len(reports) != 2 {
		t.Fatalf("expected 2 reports, got %d", len(reports))
	}
	if reports["a"].Controller != "a" || reports["a"].ControllerKind != "analysis" {
		t.Fatalf("controller metadata not populated: %+v", reports["a"])
	}
}

func TestRunMatchPopulatesVerdicts(t *testing.T) {
	logger := zaptest.NewLogger(t)
	inst := metrics.NewInstrumentation(prometheus.NewRegistry())
	mgr := &Manager{
		matchControllers: []controller.MatchController{
			stubMatchController{
				name: "auth",
				kind: "auth-kind",
				verdict: &controller.MatchVerdict{
					DenyCode:    codes.PermissionDenied,
					Description: "ok",
					IsMatch:     true,
				},
			},
		},
		instrumentation: inst,
		logger:          logger,
	}

	verdicts := mgr.runMatch(context.Background(), runtime.NewRequestContext(minimalCheckRequestUnit("203.0.113.3")), nil)

	verdict, ok := verdicts["auth"]
	if !ok {
		t.Fatalf("expected verdict from controller")
	}
	if verdict.Controller != "auth" || verdict.ControllerType != "auth-kind" {
		t.Fatalf("controller metadata not populated: %+v", verdict)
	}
}

// --- policy evaluation ------------------------------------------------------

func TestEvaluatePolicyNilPolicyAllows(t *testing.T) {
	mgr := &Manager{authorizationPolicy: nil}

	allowed, verdict := mgr.evaluatePolicy(nil)
	if !allowed || verdict == nil || verdict.DenyCode != codes.OK {
		t.Fatalf("expected default allow verdict, got allowed=%v verdict=%+v", allowed, verdict)
	}
}

func TestEvaluatePolicyDeniesWithControllerVerdict(t *testing.T) {
	pol, err := policy.Parse("auth", []string{"auth"})
	if err != nil {
		t.Fatalf("policy parse failed: %v", err)
	}
	mgr := &Manager{authorizationPolicy: pol}

	expected := &controller.MatchVerdict{
		Controller:  "auth",
		DenyCode:    codes.PermissionDenied,
		Description: "blocked",
		IsMatch:     false,
	}
	allowed, verdict := mgr.evaluatePolicy(controller.MatchVerdicts{
		"auth": expected,
	})

	if allowed || verdict != expected {
		t.Fatalf("expected controller verdict to be returned")
	}
}

func TestEvaluatePolicyMissingController(t *testing.T) {
	pol, err := policy.Parse("missing", []string{"missing"})
	if err != nil {
		t.Fatalf("policy parse failed: %v", err)
	}
	mgr := &Manager{authorizationPolicy: pol}

	allowed, verdict := mgr.evaluatePolicy(nil)

	if allowed || verdict.Controller != "policy" || verdict.DenyCode != codes.PermissionDenied {
		t.Fatalf("expected policy fallback verdict, got %+v", verdict)
	}
}

// --- header helpers --------------------------------------------------------

func TestHeaderOptionsFromAnalysisReportsIsDeterministic(t *testing.T) {
	reports := controller.AnalysisReports{
		"b": {UpstreamHeaders: map[string]string{"X-B": "b"}},
		"a": {UpstreamHeaders: map[string]string{"X-A": "a"}},
	}

	headers := upstreamHeadersFromAnalysisReports(reports)
	if len(headers) != 2 {
		t.Fatalf("expected 2 headers, got %d", len(headers))
	}
	if headers[0].Header.GetKey() != "X-A" {
		t.Fatalf("expected headers ordered by controller name, got %s first", headers[0].Header.GetKey())
	}
}

func TestHeaderOptionsFromMapFiltersUnsafe(t *testing.T) {
	headers := sanitizedHeaders(map[string]string{
		" Good ":         " value ",
		"Bad Header":     "x",
		"X-Evil\nInject": "y",
	})

	if len(headers) != 1 {
		t.Fatalf("expected only safe header to remain, got %d", len(headers))
	}
	if headers[0].Header.Key != "Good" || headers[0].Header.Value != "value" {
		t.Fatalf("header not trimmed/sanitized: %+v", headers[0].Header)
	}
}

// --- misc helpers ----------------------------------------------------------

func TestCodeToHTTPMapping(t *testing.T) {
	if got := codeToHTTP(codes.OK); got != typev3.StatusCode_OK {
		t.Fatalf("expected OK, got %v", got)
	}
	if got := codeToHTTP(codes.Unauthenticated); got != typev3.StatusCode_Unauthorized {
		t.Fatalf("expected Unauthorized, got %v", got)
	}
	if got := codeToHTTP(codes.PermissionDenied); got != typev3.StatusCode_Forbidden {
		t.Fatalf("expected Forbidden fallback, got %v", got)
	}
}

// --- Check flow ------------------------------------------------------------

func TestManagerCheckAllowsAndPropagatesHeaders(t *testing.T) {
	logger := zaptest.NewLogger(t)
	inst := metrics.NewInstrumentation(prometheus.NewRegistry())
	mgr := &Manager{
		analysisControllers: []controller.AnalysisController{
			stubAnalysisController{
				name:   "analysis-one",
				kind:   "analysis",
				report: &controller.AnalysisReport{UpstreamHeaders: map[string]string{"X-From-Analysis": "a"}},
			},
		},
		matchControllers: []controller.MatchController{
			stubMatchController{
				name: "auth-one",
				kind: "auth",
				verdict: &controller.MatchVerdict{
					IsMatch:              true,
					DenyCode:             codes.PermissionDenied,
					Description:          "ok",
					AllowUpstreamHeaders: map[string]string{"X-From-Auth": "b"},
				},
			},
		},
		instrumentation:     inst,
		authorizationPolicy: nil,
		policyBypass:        false,
		logger:              logger,
	}

	resp, err := mgr.Check(context.Background(), minimalCheckRequestUnit("192.0.2.5"))
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}

	if resp.GetStatus().GetCode() != int32(codes.OK) {
		t.Fatalf("expected OK status, got %d", resp.GetStatus().GetCode())
	}
	headers := resp.GetOkResponse().GetHeaders()
	if len(headers) != 2 {
		t.Fatalf("expected 2 propagated headers, got %d", len(headers))
	}
}

func TestManagerCheckDeniesViaPolicy(t *testing.T) {
	pol, err := policy.Parse("auth-one", []string{"auth-one"})
	if err != nil {
		t.Fatalf("policy parse failed: %v", err)
	}

	logger := zaptest.NewLogger(t)
	inst := metrics.NewInstrumentation(prometheus.NewRegistry())
	mgr := &Manager{
		matchControllers: []controller.MatchController{
			stubMatchController{
				name: "auth-one",
				kind: "auth",
				verdict: &controller.MatchVerdict{
					DenyCode:    codes.PermissionDenied,
					Description: "blocked",
					IsMatch:     false,
				},
			},
		},
		instrumentation:     inst,
		authorizationPolicy: pol,
		policyBypass:        false,
		logger:              logger,
	}

	resp, err := mgr.Check(context.Background(), minimalCheckRequestUnit("198.51.100.99"))
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}
	denied := resp.GetDeniedResponse()
	if denied == nil {
		t.Fatalf("expected denied response")
	}
	if denied.GetStatus().GetCode() != typev3.StatusCode_Forbidden {
		t.Fatalf("unexpected HTTP status: %v", denied.GetStatus().GetCode())
	}
	if resp.GetStatus().GetCode() != int32(codes.PermissionDenied) {
		t.Fatalf("unexpected gRPC status: %d", resp.GetStatus().GetCode())
	}
	if !strings.Contains(denied.GetBody(), "blocked") {
		t.Fatalf("deny reason missing, got %s", denied.GetBody())
	}
}

func TestManagerCheckPolicyBypassReturnsOK(t *testing.T) {
	pol, err := policy.Parse("auth-one", []string{"auth-one"})
	if err != nil {
		t.Fatalf("policy parse failed: %v", err)
	}

	logger := zaptest.NewLogger(t)
	inst := metrics.NewInstrumentation(prometheus.NewRegistry())
	mgr := &Manager{
		matchControllers: []controller.MatchController{
			stubMatchController{
				name: "auth-one",
				kind: "auth",
				verdict: &controller.MatchVerdict{
					DenyCode:    codes.PermissionDenied,
					Description: "blocked",
					IsMatch:     false,
				},
			},
		},
		instrumentation:     inst,
		authorizationPolicy: pol,
		policyBypass:        true,
		logger:              logger,
	}

	resp, err := mgr.Check(context.Background(), minimalCheckRequestUnit("198.51.100.99"))
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}
	if resp.GetStatus().GetCode() != int32(codes.OK) {
		t.Fatalf("expected OK status due to policy bypass, got %d", resp.GetStatus().GetCode())
	}
}

// --- Server helpers --------------------------------------------------------

func TestBuildTLSConfigWithoutTLSReturnsEmptyConfig(t *testing.T) {
	cfg := config.ServerConfig{TLS: nil}
	tlsCfg, err := buildTLSConfig(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tlsCfg.Certificates) != 0 {
		t.Fatalf("expected no certificates when TLS is nil")
	}
}

func TestBuildTLSConfigLoadsCertificates(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, dir)

	cfg := config.ServerConfig{
		TLS: &config.TLSConfig{
			CertFile: certPath,
			KeyFile:  keyPath,
		},
	}

	tlsCfg, err := buildTLSConfig(cfg)
	if err != nil {
		t.Fatalf("unexpected error loading TLS config: %v", err)
	}
	if len(tlsCfg.Certificates) != 1 {
		t.Fatalf("expected one certificate to be loaded")
	}
}

func TestBuildTLSConfigErrorsOnMissingFiles(t *testing.T) {
	cfg := config.ServerConfig{
		TLS: &config.TLSConfig{
			CertFile: "missing.pem",
			KeyFile:  "missing.key",
		},
	}
	if _, err := buildTLSConfig(cfg); err == nil {
		t.Fatalf("expected error when certificate files are missing")
	}
}

func TestServerStartFailsOnBadAddress(t *testing.T) {
	logger := zaptest.NewLogger(t)
	inst := metrics.NewInstrumentation(prometheus.NewRegistry())
	mgr := &Manager{
		instrumentation: inst,
		logger:          logger,
	}

	srv, err := NewServer(config.ServerConfig{Address: "bad::addr"}, mgr, logger)
	if err != nil {
		t.Fatalf("unexpected error constructing server: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if err := srv.Start(ctx, nil); err == nil {
		t.Fatalf("expected start to fail with invalid address")
	}
}

// --- test helpers ----------------------------------------------------------

func writeSelfSignedCert(t *testing.T, dir string) (string, string) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	certOut, err := os.Create(certPath)
	if err != nil {
		t.Fatalf("failed to create cert file: %v", err)
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatalf("failed to write cert: %v", err)
	}

	keyOut, err := os.Create(keyPath)
	if err != nil {
		t.Fatalf("failed to create key file: %v", err)
	}
	defer keyOut.Close()
	keyBytes := x509.MarshalPKCS1PrivateKey(priv)
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}

	return certPath, keyPath
}
