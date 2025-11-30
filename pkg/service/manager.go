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
	analysisControllers  []controller.AnalysisController
	matchControllers     []controller.MatchController
	instrumentation      *metrics.Instrumentation
	aouthorizationPolicy *policy.Policy
	policyBypass         bool
	logger               *zap.Logger
}

// NewManager instantiates a controller manager.
func NewManager(
	analysisControllers []controller.AnalysisController,
	matchControllers []controller.MatchController,
	instrumentation *metrics.Instrumentation,
	policy *policy.Policy,
	policyBypass bool,
	logger *zap.Logger,
) *Manager {
	return &Manager{
		analysisControllers:  analysisControllers,
		matchControllers:     matchControllers,
		instrumentation:      instrumentation,
		aouthorizationPolicy: policy,
		policyBypass:         policyBypass,
		logger:               logger,
	}
}

// Check executes analysis + match phases and evaluates the configured authorization policy.
func (m *Manager) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	reqCtx := runtime.NewRequestContext(req)
	start := time.Now()

	// Track in-flight requests
	m.instrumentation.InFlight(reqCtx.Authority, 1)
	defer m.instrumentation.InFlight(reqCtx.Authority, -1)

	// Run analysis phase
	analysisReports, err := m.runAnalysis(ctx, reqCtx)
	if err != nil {
		m.logger.Error("analysis phase failed", append(reqCtx.LogFields(), zap.Error(err))...)
		m.instrumentation.ObserveDenyDecision(reqCtx.Authority, time.Since(start))
		return m.denyResponse(codes.PermissionDenied, err.Error(), nil), nil
	}

	// Run match phase
	matchVerdicts, err := m.runMatch(ctx, reqCtx, analysisReports)
	if err != nil {
		m.logger.Warn("match phase failed", append(reqCtx.LogFields(), zap.Error(err))...)
		m.instrumentation.ObserveDenyDecision(reqCtx.Authority, time.Since(start))
		return m.denyResponse(codes.PermissionDenied, err.Error(), nil), nil
	}

	// Evaluate policy
	allowed, denyVerdict := m.evaluatePolicy(matchVerdicts)

	logFields := reqCtx.LogFields()

	if !allowed {
		// Log requests denied by policy (or bypassed)
		logFields := append(
			logFields,
			zap.String("decision", metrics.DENY),
			zap.String("culprit_controller_name", denyVerdict.Controller),
			zap.String("culprit_controller_type", denyVerdict.ControllerKind),
			zap.String("culprit_description", denyVerdict.Description),
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
			zap.String("decision", metrics.ALLOW),
		)
		m.logger.Debug("request allowed by policy", logFields...)
	}

	if !allowed && !m.policyBypass {
		// Deny the request
		m.instrumentation.ObserveDenyDecision(reqCtx.Authority, time.Since(start))
		return m.denyResponse(
			denyVerdict.DenyCode,
			denyVerdict.Description,
			sanitizedHeaders(denyVerdict.DenyDownstreamHeaders),
		), nil
	}

	upstreamHeaders := upstreamHeadersFromAnalysisReports(analysisReports)

	for _, matchVerdict := range matchVerdicts {
		upstreamHeaders = append(
			upstreamHeaders,
			sanitizedHeaders(matchVerdict.AllowUpstreamHeaders)...,
		)
	}

	m.instrumentation.ObserveAllowDecision(reqCtx.Authority, time.Since(start))
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
			m.instrumentation.ObserveAnalysisControllerDuration(
				req.Authority,
				analysisController.Name(),
				analysisController.Kind(),
				err != nil,
				time.Since(phaseStart),
			)
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

// runMatch runs every match controller and accumulates their
// verdicts for subsequent policy evaluation.
func (m *Manager) runMatch(ctx context.Context, req *runtime.RequestContext, reports controller.AnalysisReports) (controller.MatchVerdicts, error) {
	verdicts := make(controller.MatchVerdicts)

	if len(m.matchControllers) == 0 {
		return verdicts, nil
	}

	var mu sync.Mutex

	g, ctx := errgroup.WithContext(ctx)
	for _, matchController := range m.matchControllers {
		g.Go(func() error {
			phaseStart := time.Now()
			verdict, err := matchController.Match(ctx, req, reports)
			m.instrumentation.ObserveMatchControllerDuration(
				req.Authority,
				matchController.Name(),
				matchController.Kind(),
				err != nil,
				time.Since(phaseStart),
			)
			if err != nil {
				return fmt.Errorf("match controller '%s' of type '%s' failed: %w", matchController.Name(), matchController.Kind(), err)
			}
			if verdict == nil {
				return fmt.Errorf("match controller '%s' of type '%s' returned no verdict", matchController.Name(), matchController.Kind())
			}
			verdict.Controller = matchController.Name()
			verdict.ControllerKind = matchController.Kind()
			mu.Lock()
			verdicts[matchController.Name()] = verdict
			mu.Unlock()
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	return verdicts, nil
}

// evaluatePolicy converts verdicts to boolean inputs and feeds them to the policy
// engine, returning whether the request is allowed and, when denied, the offending verdict.
func (m *Manager) evaluatePolicy(matchVerdicts controller.MatchVerdicts) (bool, *controller.MatchVerdict) {
	if m.aouthorizationPolicy == nil {
		return true, &controller.MatchVerdict{
			Controller:     "policy",
			ControllerKind: "policy",
			IsMatch:        true,
			DenyCode:       codes.OK,
			Description:    "no policy configured, allowing by default",
		}
	}

	verdictsPredicates := make(map[string]bool, len(matchVerdicts))
	for controllerName, verdict := range matchVerdicts {
		verdictsPredicates[controllerName] = verdict.IsMatch
	}

	if allowed, denyerControllerName := m.aouthorizationPolicy.Evaluate(verdictsPredicates); allowed {
		return true, &controller.MatchVerdict{
			Controller:     "policy",
			ControllerKind: "policy",
			IsMatch:        true,
			DenyCode:       codes.OK,
			Description:    "request allowed by policy",
		}
	} else {
		if denyerControllerVerdict, ok := matchVerdicts[denyerControllerName]; ok {
			// ensure a sensible default code
			if denyerControllerVerdict.DenyCode == codes.OK {
				denyerControllerVerdict.DenyCode = codes.PermissionDenied
			}
			return false, denyerControllerVerdict
		}
		return false, &controller.MatchVerdict{
			Controller:     "policy",
			ControllerKind: "policy",
			DenyCode:       codes.PermissionDenied,
			Description:    fmt.Sprintf("request denied by controller '%s'", denyerControllerName),
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
	sanitizedCode := code
	if sanitizedCode == codes.OK {
		sanitizedCode = codes.PermissionDenied
	}

	return &authv3.CheckResponse{
		Status: status.New(sanitizedCode, message).Proto(),
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status:  &typev3.HttpStatus{Code: codeToHTTP(sanitizedCode)},
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

// upstreamHeadersFromAnalysisReports flattens the analysis phase upstream headers into Envoy
// header options. The function keeps ordering deterministic for easier testing.
func upstreamHeadersFromAnalysisReports(analysisReports controller.AnalysisReports) []*corev3.HeaderValueOption {
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
		headers = append(headers, sanitizedHeaders(report.UpstreamHeaders)...)
	}
	return headers
}

// sanitizedHeaders converts a map representation into Envoy header values while
// filtering unsafe header names and trimming whitespace from values.
func sanitizedHeaders(values map[string]string) []*corev3.HeaderValueOption {
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
