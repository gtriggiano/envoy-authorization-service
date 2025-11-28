package service

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/gtriggiano/envoy-authorization-service/pkg/controller"
	"github.com/gtriggiano/envoy-authorization-service/pkg/metrics"
	"github.com/gtriggiano/envoy-authorization-service/pkg/policy"
	"github.com/gtriggiano/envoy-authorization-service/pkg/runtime"
)

// Manager coordinates controllers through the Envoy authorization lifecycle.
type Manager struct {
	analysisControllers      []controller.AnalysisController
	authorizationControllers []controller.AuthorizationController
	instrumentation          *metrics.Instrumentation
	policy                   *policy.Policy
	policyBypass             bool
	logger                   *zap.Logger
}

// NewManager instantiates a controller manager.
func NewManager(
	analysisControllers []controller.AnalysisController,
	authorizationControllers []controller.AuthorizationController,
	instrumentation *metrics.Instrumentation,
	policy *policy.Policy,
	policyBypass bool,
	logger *zap.Logger,
) *Manager {
	return &Manager{
		analysisControllers:      analysisControllers,
		authorizationControllers: authorizationControllers,
		instrumentation:          instrumentation,
		policy:                   policy,
		policyBypass:             policyBypass,
		logger:                   logger,
	}
}

// Check executes analysis + authorization phases and evaluates the configured policy.
func (m *Manager) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	reqCtx := runtime.NewRequestContext(req)
	start := time.Now()
	m.instrumentation.InFlight(1)
	defer m.instrumentation.InFlight(-1)

	// Run analysis phase
	analysisReports, err := m.runAnalysis(ctx, reqCtx)
	if err != nil {
		m.logger.Error("analysis phase failed", append(reqCtx.LogFields(), zap.Error(err))...)
		m.instrumentation.ObserveDenyDecision(time.Since(start))
		return m.denyResponse(codes.PermissionDenied, err.Error(), nil), nil
	}

	// Run authorization phase
	authorizationVerdicts, err := m.runAuthorization(ctx, reqCtx, analysisReports)
	if err != nil {
		m.logger.Warn("authorization phase failed", append(reqCtx.LogFields(), zap.Error(err))...)
		m.instrumentation.ObserveDenyDecision(time.Since(start))
		return m.denyResponse(codes.PermissionDenied, err.Error(), nil), nil
	}

	// Evaluate policy
	finalVerdict := m.evaluatePolicyForFinalVerdict(authorizationVerdicts)

	logFields := reqCtx.LogFields()

	if finalVerdict.IsDeny() {
		// Log requests denied by policy
		logFields := append(
			logFields,
			zap.String("decision", metrics.DENY_DECISION),
			zap.String("culprit_controller_name", finalVerdict.Controller),
			zap.String("culprit_controller_type", finalVerdict.ControllerKind),
			zap.String("deny_reason", finalVerdict.Reason),
			zap.Bool("policy_bypass", m.policyBypass),
		)
		if m.policyBypass {
			m.logger.Warn("request would be denied but policy bypass is enabled", logFields...)
		} else {
			m.logger.Warn("request denied by policy", logFields...)
		}
	} else {
		// Log requests allowed by policy
		logFields := append(
			logFields,
			zap.String("decision", metrics.ALLOW_DECISION),
		)
		m.logger.Debug("request allowed by policy", logFields...)
	}

	if finalVerdict.IsDeny() && !m.policyBypass {
		// Deny the request
		m.instrumentation.ObserveDenyDecision(time.Since(start))
		return m.denyResponse(
			finalVerdict.Code,
			finalVerdict.Reason,
			headerOptionsFromMap(finalVerdict.DownstreamHeaders),
		), nil
	}

	upstreamHeaders := headerOptionsFromAnalysisReports(analysisReports)

	for _, authorizationVerdict := range authorizationVerdicts {
		if authorizationVerdict.IsAllow() {
			upstreamHeaders = append(
				upstreamHeaders,
				headerOptionsFromMap(authorizationVerdict.UpstreamHeaders)...,
			)
		}
	}

	m.instrumentation.ObserveAllowDecision(time.Since(start))
	return m.okResponse(upstreamHeaders), nil
}

// runAnalysis executes all analysis controllers concurrently and collects their
// reports keyed by controller name.
func (m *Manager) runAnalysis(ctx context.Context, req *runtime.RequestContext) (controller.AnalysisReports, error) {
	reports := make(controller.AnalysisReports)

	if len(m.analysisControllers) == 0 {
		return reports, nil
	}

	var mu sync.Mutex

	g, ctx := errgroup.WithContext(ctx)
	for _, analysisController := range m.analysisControllers {
		g.Go(func() error {
			phaseStart := time.Now()
			report, err := analysisController.Analyze(ctx, req)
			result := phaseResult(err)
			m.instrumentation.ObservePhase(analysisController.Name(), analysisController.Kind(), "analysis", result, time.Since(phaseStart))
			if err != nil {
				return fmt.Errorf("analysis controller '%s' of type '%s' failed: %w", analysisController.Name(), analysisController.Kind(), err)
			}
			if report != nil {
				report.Controller = analysisController.Name()
				report.ControllerKind = analysisController.Kind()
				mu.Lock()
				reports[analysisController.Name()] = report
				mu.Unlock()
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	return reports, nil
}

// runAuthorization runs every authorization controller and accumulates their
// verdicts for subsequent policy evaluation.
func (m *Manager) runAuthorization(ctx context.Context, req *runtime.RequestContext, reports controller.AnalysisReports) (controller.AuthorizationVerdicts, error) {
	verdicts := make(controller.AuthorizationVerdicts)

	if len(m.authorizationControllers) == 0 {
		return verdicts, nil
	}

	var mu sync.Mutex

	g, ctx := errgroup.WithContext(ctx)
	for _, authorizationController := range m.authorizationControllers {
		g.Go(func() error {
			phaseStart := time.Now()
			verdict, err := authorizationController.Authorize(ctx, req, reports)
			result := phaseResult(err)
			m.instrumentation.ObservePhase(authorizationController.Name(), authorizationController.Kind(), "authorization", result, time.Since(phaseStart))
			if err != nil {
				return fmt.Errorf("authorization controller '%s' of type '%s' failed: %w", authorizationController.Name(), authorizationController.Kind(), err)
			}
			if verdict == nil {
				return fmt.Errorf("authorization controller '%s' of type '%s' returned no verdict", authorizationController.Name(), authorizationController.Kind())
			}
			verdict.Controller = authorizationController.Name()
			verdict.ControllerKind = authorizationController.Kind()
			mu.Lock()
			verdicts[authorizationController.Name()] = verdict
			mu.Unlock()
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	return verdicts, nil
}

// evaluatePolicyForFinalVerdict converts verdicts to boolean inputs and feeds them to the policy
// engine, returning both the allow decision and the blocking controller name.
func (m *Manager) evaluatePolicyForFinalVerdict(authorizationVerdicts controller.AuthorizationVerdicts) *controller.AuthorizationVerdict {
	if m.policy == nil {
		return &controller.AuthorizationVerdict{
			Controller:     "policy",
			ControllerKind: "policy",
			Code:           codes.OK,
			Reason:         "no policy configured, allowing by default",
		}
	}

	verdictsPredicates := make(map[string]bool, len(authorizationVerdicts))
	for controllerName, verdict := range authorizationVerdicts {
		verdictsPredicates[controllerName] = verdict.InPolicy
	}

	if allowed, denyerControllerName := m.policy.Evaluate(verdictsPredicates); allowed {
		return &controller.AuthorizationVerdict{
			Controller:     "policy",
			ControllerKind: "policy",
			Code:           codes.OK,
			Reason:         "request allowed by policy",
		}
	} else {
		if denyerControllerVerdict, ok := authorizationVerdicts[denyerControllerName]; ok {
			return denyerControllerVerdict
		}
		return &controller.AuthorizationVerdict{
			Controller:     "policy",
			ControllerKind: "policy",
			Code:           codes.PermissionDenied,
			Reason:         fmt.Sprintf("request denied by controller '%s'", denyerControllerName),
		}
	}
}

// okResponse wraps an OK authorization result with optional upstream headers.
func (m *Manager) okResponse(headers []*corev3.HeaderValueOption) *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: status.New(codes.OK, "ok").Proto(),
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{Headers: headers},
		},
	}
}

// denyResponse wraps a denied authorization result with headers suitable for Envoy.
func (m *Manager) denyResponse(code codes.Code, message string, headers []*corev3.HeaderValueOption) *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: status.New(code, message).Proto(),
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status:  &typev3.HttpStatus{Code: codeToHTTP(code)},
				Body:    message,
				Headers: headers,
			},
		},
	}
}

// codeToHTTP maps a gRPC status code to the HTTP status Envoy expects.
func codeToHTTP(code codes.Code) typev3.StatusCode {
	switch code {
	case codes.OK:
		return typev3.StatusCode_OK
	case codes.Unauthenticated:
		return typev3.StatusCode_Unauthorized
	default:
		return typev3.StatusCode_Forbidden
	}
}

var headerPattern = regexp.MustCompile(`^[A-Za-z0-9-]+$`)

// headerOptionsFromAnalysisReports flattens the analysis phase upstream headers into Envoy
// header options. The function keeps ordering deterministic for easier testing.
func headerOptionsFromAnalysisReports(analysisReports controller.AnalysisReports) []*corev3.HeaderValueOption {
	if len(analysisReports) == 0 {
		return nil
	}
	names := make([]string, 0, len(analysisReports))
	for name := range analysisReports {
		names = append(names, name)
	}
	sort.Strings(names)
	var headers []*corev3.HeaderValueOption
	for _, name := range names {
		report := analysisReports[name]
		headers = append(headers, headerOptionsFromMap(report.UpstreamHeaders)...)
	}
	return headers
}

// headerOptionsFromMap converts a map representation into Envoy header values while
// filtering unsafe header names and trimming whitespace from values.
func headerOptionsFromMap(values map[string]string) []*corev3.HeaderValueOption {
	if len(values) == 0 {
		return nil
	}

	var headers []*corev3.HeaderValueOption
	for key, value := range values {
		if !isSafeHeader(key) {
			continue
		}
		headers = append(headers, &corev3.HeaderValueOption{
			AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
			Header: &corev3.HeaderValue{
				Key:   strings.TrimSpace(key),
				Value: strings.TrimSpace(value),
			},
		})
	}

	return headers
}

// isSafeHeader constrains header names to alphanumeric and dash characters to avoid
// propagating malformed headers upstream or downstream.
func isSafeHeader(name string) bool {
	return headerPattern.MatchString(strings.TrimSpace(name))
}

// phaseResult normalizes an error into a label-friendly string for metrics.
func phaseResult(err error) string {
	if err != nil {
		return "error"
	}
	return "ok"
}
