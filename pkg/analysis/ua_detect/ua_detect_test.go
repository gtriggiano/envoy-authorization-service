package ua_detect

import (
	"context"
	"testing"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"go.uber.org/zap"

	"github.com/gtriggiano/envoy-authorization-service/pkg/config"
	"github.com/gtriggiano/envoy-authorization-service/pkg/runtime"
)

func TestExtractUserAgentFromRequest(t *testing.T) {
	t.Run("missing headers returns empty string", func(t *testing.T) {
		req := runtime.NewRequestContext(&authv3.CheckRequest{})
		if got := extractUserAgentFromRequest(req); got != "" {
			t.Fatalf("expected empty string, got %q", got)
		}
	})

	t.Run("finds header case-insensitively", func(t *testing.T) {
		const ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
		req := runtime.NewRequestContext(newCheckRequestWithHeader("User-Agent", ua))
		if got := extractUserAgentFromRequest(req); got != ua {
			t.Fatalf("expected %q, got %q", ua, got)
		}
	})

	t.Run("nil request handled gracefully", func(t *testing.T) {
		if got := extractUserAgentFromRequest(nil); got != "" {
			t.Fatalf("expected empty string, got %q", got)
		}
	})
}

func TestUADetectAnalysisController_Analyze(t *testing.T) {
	ctrl := newTestController(t)

	tests := []struct {
		name        string
		userAgent   string
		deviceType  string
		expectBot   bool
		expectModel string
	}{
		{
			name:       "Chrome Desktop",
			userAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
			deviceType: "desktop",
		},
		{
			name:        "iPhone Safari",
			userAgent:   "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
			deviceType:  "mobile",
			expectModel: "iPhone",
		},
		{
			name:       "Googlebot",
			userAgent:  "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
			deviceType: "bot",
			expectBot:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := runtime.NewRequestContext(newCheckRequestWithHeader("user-agent", tt.userAgent))
			report, err := ctrl.Analyze(context.Background(), req)
			if err != nil {
				t.Fatalf("Analyze returned error: %v", err)
			}
			if report == nil {
				t.Fatalf("expected report, got nil")
			}

			result := GetUADetectionResultFromReport(report)
			if result == nil {
				t.Fatalf("expected typed result in report")
			}

			if result.Device.Type != tt.deviceType {
				t.Errorf("device type: expected %q, got %q", tt.deviceType, result.Device.Type)
			}

			if result.Bot.Detected != tt.expectBot {
				t.Errorf("isBot: expected %v, got %v", tt.expectBot, result.Bot.Detected)
			}

			if tt.expectModel != "" && result.Device.Model != tt.expectModel {
				t.Errorf("device model: expected %q, got %q", tt.expectModel, result.Device.Model)
			}

			if report.UpstreamHeaders["X-UA-Browser"] == "" {
				t.Errorf("expected X-UA-Browser header to be set")
			}
			if report.UpstreamHeaders["X-UA-Device-Type"] != tt.deviceType {
				t.Errorf("upstream device type header: expected %q, got %q", tt.deviceType, report.UpstreamHeaders["X-UA-Device-Type"])
			}

			fields := req.LogFields()
			if len(fields) == 0 {
				t.Fatalf("expected log fields to be populated")
			}
		})
	}
}

func TestUADetectAnalysisController_Analyze_NoUserAgent(t *testing.T) {
	ctrl := newTestController(t)
	req := runtime.NewRequestContext(&authv3.CheckRequest{})

	report, err := ctrl.Analyze(context.Background(), req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if report != nil {
		t.Fatalf("expected nil report when no user agent is present")
	}
}

func TestUADetectAnalysisController_Cache(t *testing.T) {
	ctrl := newTestController(t)
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"

	first := ctrl.detect(ua)
	second := ctrl.detect(ua)

	if first != second {
		t.Fatalf("expected cached result to be reused")
	}
}

func TestUADetectAnalysisController_CacheDisabledReturnsDistinctResults(t *testing.T) {
	ctrlAny, err := newUADetectAnalysisController(context.Background(), zap.NewNop(), config.ControllerConfig{
		Name: "no-cache",
		Type: ControllerKind,
		Settings: map[string]any{
			"cacheEnabled": false,
		},
	})
	if err != nil {
		t.Fatalf("failed to create controller: %v", err)
	}
	ctrl := ctrlAny.(*uaDetectAnalysisController)
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"
	first := ctrl.detect(ua)
	second := ctrl.detect(ua)
	if first == second {
		t.Fatalf("expected distinct instances when cache is disabled")
	}
}

func TestNewUADetectAnalysisController_WithFallback(t *testing.T) {
	ctrl, err := newUADetectAnalysisController(context.Background(), zap.NewNop(), config.ControllerConfig{
		Name: "test-controller-fallback",
		Type: ControllerKind,
		Settings: map[string]any{
			"enableFallback": true,
			"cacheEnabled":   false,
		},
	})
	if err != nil {
		t.Fatalf("failed to create controller with fallback: %v", err)
	}

	internal := ctrl.(*uaDetectAnalysisController)
	if internal.fallbackParser == nil {
		t.Fatalf("expected fallback parser to be initialized")
	}
}

func TestApplyFallbackParserPopulatesUnknownResult(t *testing.T) {
	ctrlAny, err := newUADetectAnalysisController(context.Background(), zap.NewNop(), config.ControllerConfig{
		Name: "fallback-populate",
		Type: ControllerKind,
		Settings: map[string]any{
			"enableFallback": true,
		},
	})
	if err != nil {
		t.Fatalf("failed to create controller: %v", err)
	}
	ctrl := ctrlAny.(*uaDetectAnalysisController)

	rawUA := "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/117.0"
	result := &UADetectionResult{IsUnknown: true}
	updated := ctrl.applyFallbackParser(result, rawUA)

	if updated.IsUnknown {
		t.Fatalf("expected fallback to clear unknown flag")
	}
	if updated.Browser.Name == "" || updated.OS.Name == "" {
		t.Fatalf("expected fallback to populate browser and os fields")
	}
}

func TestHelperFunctionsNilSafety(t *testing.T) {
	if headers := makeUpstreamHeaders(nil); headers != nil {
		t.Fatalf("expected nil headers for nil result")
	}
	if fields := makeLogFields(nil); len(fields) != 0 {
		t.Fatalf("expected empty log fields for nil result")
	}
}

func TestDetermineDeviceType(t *testing.T) {
	tests := []struct {
		name         string
		isBot        bool
		isMobile     bool
		isTablet     bool
		isDesktop    bool
		expectedType string
	}{
		{"bot detected", true, false, false, false, "bot"},
		{"mobile device", false, true, false, false, "mobile"},
		{"tablet device", false, false, true, false, "tablet"},
		{"desktop device", false, false, false, true, "desktop"},
		{"mobile takes priority over tablet", false, true, true, false, "mobile"},
		{"unknown device", false, false, false, false, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &UADetectionResult{
				Bot:    BotInfo{Detected: tt.isBot},
				Device: DeviceInfo{Mobile: tt.isMobile, Tablet: tt.isTablet, Desktop: tt.isDesktop},
			}
			deviceType := determineDeviceType(result)
			if deviceType != tt.expectedType {
				t.Errorf("expected %q, got %q", tt.expectedType, deviceType)
			}
		})
	}
}

func TestFormatBool(t *testing.T) {
	tests := []struct {
		input    bool
		expected string
	}{
		{true, "true"},
		{false, "false"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := formatBool(tt.input)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestParseInt(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"123", 123},
		{"0", 0},
		{"-1", -1},
		{"invalid", 0},
		{"", 0},
		{"999999", 999999},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := parseInt(tt.input)
			if result != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, result)
			}
		})
	}
}

func TestJoinVersionParts(t *testing.T) {
	tests := []struct {
		name     string
		major    string
		minor    string
		patch    string
		expected string
	}{
		{"all parts", "1", "2", "3", "1.2.3"},
		{"major and minor", "1", "2", "", "1.2"},
		{"major only", "1", "", "", "1"},
		{"empty", "", "", "", ""},
		{"zero values", "0", "0", "0", "0.0.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := joinVersionParts(tt.major, tt.minor, tt.patch)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestUADetectController_Name(t *testing.T) {
	ctrl := &uaDetectAnalysisController{name: "test-name"}
	if ctrl.Name() != "test-name" {
		t.Errorf("expected 'test-name', got '%s'", ctrl.Name())
	}
}

func TestUADetectController_Kind(t *testing.T) {
	ctrl := &uaDetectAnalysisController{}
	if ctrl.Kind() != ControllerKind {
		t.Errorf("expected '%s', got '%s'", ControllerKind, ctrl.Kind())
	}
}

func TestUADetectController_HealthCheck(t *testing.T) {
	ctrl := &uaDetectAnalysisController{}
	err := ctrl.HealthCheck(context.Background())
	if err != nil {
		t.Errorf("HealthCheck should always return nil, got %v", err)
	}
}

func BenchmarkUADetect_Parse(b *testing.B) {
	ctrl := newTestController(b)
	const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctrl.userAgentDetection(ua)
	}
}

func newTestController(tb testing.TB) *uaDetectAnalysisController {
	tb.Helper()

	ctrl, err := newUADetectAnalysisController(context.Background(), zap.NewNop(), config.ControllerConfig{
		Name: "test-controller",
		Type: ControllerKind,
	})
	if err != nil {
		tb.Fatalf("failed to create test controller: %v", err)
	}

	return ctrl.(*uaDetectAnalysisController)
}

func newCheckRequestWithHeader(key, value string) *authv3.CheckRequest {
	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Headers: map[string]string{key: value},
				},
			},
		},
	}
}
