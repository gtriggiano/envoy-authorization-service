package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
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

type stubAuthorizationController struct {
	name    string
	kind    string
	verdict *controller.AuthorizationVerdict
	err     error
}

func (s stubAuthorizationController) Name() string { return s.name }
func (s stubAuthorizationController) Kind() string { return s.kind }
func (s stubAuthorizationController) Authorize(ctx context.Context, _ *runtime.RequestContext, _ controller.AnalysisReports) (*controller.AuthorizationVerdict, error) {
	return s.verdict, s.err
}
func (s stubAuthorizationController) HealthCheck(context.Context) error { return nil }

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

	reports, err := mgr.runAnalysis(context.Background(), runtime.NewRequestContext(minimalCheckRequestUnit("203.0.113.1")))
	if err != nil {
		t.Fatalf("runAnalysis returned error: %v", err)
	}
	if len(reports) != 2 {
		t.Fatalf("expected 2 reports, got %d", len(reports))
	}
	if reports["a"].Controller != "a" || reports["a"].ControllerKind != "analysis" {
		t.Fatalf("controller metadata not populated: %+v", reports["a"])
	}
}

func TestRunAnalysisReturnsError(t *testing.T) {
	logger := zaptest.NewLogger(t)
	inst := metrics.NewInstrumentation(prometheus.NewRegistry())
	mgr := &Manager{
		analysisControllers: []controller.AnalysisController{
			stubAnalysisController{name: "bad", kind: "analysis", err: errors.New("boom")},
		},
		instrumentation: inst,
		logger:          logger,
	}

	_, err := mgr.runAnalysis(context.Background(), runtime.NewRequestContext(minimalCheckRequestUnit("198.51.100.9")))
	if err == nil || !strings.Contains(err.Error(), "analysis controller 'bad'") {
		t.Fatalf("expected wrapped error, got %v", err)
	}
}

func TestRunAuthorizationPopulatesVerdicts(t *testing.T) {
	logger := zaptest.NewLogger(t)
	inst := metrics.NewInstrumentation(prometheus.NewRegistry())
	mgr := &Manager{
		authorizationControllers: []controller.AuthorizationController{
			stubAuthorizationController{
				name: "auth",
				kind: "auth-kind",
				verdict: &controller.AuthorizationVerdict{
					Code:     codes.OK,
					Reason:   "ok",
					InPolicy: true,
				},
			},
		},
		instrumentation: inst,
		logger:          logger,
	}

	verdicts, err := mgr.runAuthorization(context.Background(), runtime.NewRequestContext(minimalCheckRequestUnit("203.0.113.3")), nil)
	if err != nil {
		t.Fatalf("runAuthorization returned error: %v", err)
	}
	verdict, ok := verdicts["auth"]
	if !ok {
		t.Fatalf("expected verdict from controller")
	}
	if verdict.Controller != "auth" || verdict.ControllerKind != "auth-kind" {
		t.Fatalf("controller metadata not populated: %+v", verdict)
	}
}

func TestRunAuthorizationErrorsOnNilVerdict(t *testing.T) {
	logger := zaptest.NewLogger(t)
	inst := metrics.NewInstrumentation(prometheus.NewRegistry())
	mgr := &Manager{
		authorizationControllers: []controller.AuthorizationController{
			stubAuthorizationController{name: "nilverdict", kind: "auth"},
		},
		instrumentation: inst,
		logger:          logger,
	}

	_, err := mgr.runAuthorization(context.Background(), runtime.NewRequestContext(minimalCheckRequestUnit("198.51.100.2")), nil)
	if err == nil || !strings.Contains(err.Error(), "returned no verdict") {
		t.Fatalf("expected error about nil verdict, got %v", err)
	}
}

// --- policy evaluation ------------------------------------------------------

func TestEvaluatePolicyForFinalVerdictNilPolicyAllows(t *testing.T) {
	mgr := &Manager{policy: nil}

	verdict := mgr.evaluatePolicyForFinalVerdict(nil)
	if verdict.Code != codes.OK || verdict.Reason == "" || verdict.IsDeny() {
		t.Fatalf("expected default allow verdict, got %+v", verdict)
	}
}

func TestEvaluatePolicyForFinalVerdictDeniesWithControllerVerdict(t *testing.T) {
	pol, err := policy.Parse("auth", []string{"auth"})
	if err != nil {
		t.Fatalf("policy parse failed: %v", err)
	}
	mgr := &Manager{policy: pol}

	expected := &controller.AuthorizationVerdict{
		Controller: "auth",
		Code:       codes.PermissionDenied,
		Reason:     "blocked",
		InPolicy:   false,
	}
	verdict := mgr.evaluatePolicyForFinalVerdict(controller.AuthorizationVerdicts{
		"auth": expected,
	})

	if verdict != expected {
		t.Fatalf("expected controller verdict to be returned")
	}
}

func TestEvaluatePolicyForFinalVerdictMissingController(t *testing.T) {
	pol, err := policy.Parse("missing", []string{"missing"})
	if err != nil {
		t.Fatalf("policy parse failed: %v", err)
	}
	mgr := &Manager{policy: pol}

	verdict := mgr.evaluatePolicyForFinalVerdict(nil)

	if verdict.Controller != "policy" || verdict.Code != codes.PermissionDenied {
		t.Fatalf("expected policy fallback verdict, got %+v", verdict)
	}
}

// --- header helpers --------------------------------------------------------

func TestHeaderOptionsFromAnalysisReportsIsDeterministic(t *testing.T) {
	reports := controller.AnalysisReports{
		"b": {UpstreamHeaders: map[string]string{"X-B": "b"}},
		"a": {UpstreamHeaders: map[string]string{"X-A": "a"}},
	}

	headers := headerOptionsFromAnalysisReports(reports)
	if len(headers) != 2 {
		t.Fatalf("expected 2 headers, got %d", len(headers))
	}
	if headers[0].Header.GetKey() != "X-A" {
		t.Fatalf("expected headers ordered by controller name, got %s first", headers[0].Header.GetKey())
	}
}

func TestHeaderOptionsFromMapFiltersUnsafe(t *testing.T) {
	headers := headerOptionsFromMap(map[string]string{
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

func TestPhaseResult(t *testing.T) {
	if res := phaseResult(nil); res != "ok" {
		t.Fatalf("expected ok, got %s", res)
	}
	if res := phaseResult(errors.New("boom")); res != "error" {
		t.Fatalf("expected error, got %s", res)
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
		authorizationControllers: []controller.AuthorizationController{
			stubAuthorizationController{
				name: "auth-one",
				kind: "auth",
				verdict: &controller.AuthorizationVerdict{
					Code:            codes.OK,
					Reason:          "ok",
					InPolicy:        true,
					UpstreamHeaders: map[string]string{"X-From-Auth": "b"},
				},
			},
		},
		instrumentation: inst,
		policy:          nil,
		policyBypass:    false,
		logger:          logger,
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
		authorizationControllers: []controller.AuthorizationController{
			stubAuthorizationController{
				name: "auth-one",
				kind: "auth",
				verdict: &controller.AuthorizationVerdict{
					Code:     codes.PermissionDenied,
					Reason:   "blocked",
					InPolicy: false,
				},
			},
		},
		instrumentation: inst,
		policy:          pol,
		policyBypass:    false,
		logger:          logger,
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
		authorizationControllers: []controller.AuthorizationController{
			stubAuthorizationController{
				name: "auth-one",
				kind: "auth",
				verdict: &controller.AuthorizationVerdict{
					Code:     codes.PermissionDenied,
					Reason:   "blocked",
					InPolicy: false,
				},
			},
		},
		instrumentation: inst,
		policy:          pol,
		policyBypass:    true,
		logger:          logger,
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
