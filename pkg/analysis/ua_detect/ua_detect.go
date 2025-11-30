package ua_detect

import (
	"context"
	"strconv"
	"strings"
	"sync"

	"github.com/mileusna/useragent"
	"github.com/ua-parser/uap-go/uaparser"
	"go.uber.org/zap"

	"github.com/gtriggiano/envoy-authorization-service/pkg/config"
	"github.com/gtriggiano/envoy-authorization-service/pkg/controller"
	"github.com/gtriggiano/envoy-authorization-service/pkg/runtime"
)

const (
	ControllerKind = "ua-detect"
)

// init registers the UA detection analysis controller factory.
func init() {
	controller.RegisterAnalysisContollerFactory(ControllerKind, newUADetectAnalysisController)
}

// UADetectAnalysisConfig captures optional settings for the UA detection controller.
type UADetectAnalysisConfig struct {
	EnableFallback bool `yaml:"enableFallback"` // Parse with ua-parser when primary parser reports unknown.
	CacheEnabled   bool `yaml:"cacheEnabled"`   // Toggle result caching; defaults to true when unset.
}

// UADetectionResult represents the parsed User-Agent metadata extracted from requests.
type UADetectionResult struct {
	Browser BrowserInfo
	OS      OSInfo
	Device  DeviceInfo
	Bot     BotInfo

	// Metadata
	IsUnknown    bool
	RawUserAgent string
}

// BrowserInfo captures browser metadata.
type BrowserInfo struct {
	Name    string
	Version string

	VersionMajor int
	VersionMinor int
	VersionPatch string
}

// OSInfo captures operating system metadata.
type OSInfo struct {
	Name    string
	Version string

	VersionMajor int
	VersionMinor int
	Platform     string
}

// DeviceInfo captures device classification.
type DeviceInfo struct {
	Type    string
	Model   string
	Mobile  bool
	Tablet  bool
	Desktop bool
	TV      bool
}

// BotInfo captures bot details, when applicable.
type BotInfo struct {
	Detected bool
	Name     string
	URL      string
}

// GetUADetectionResultFromReport extracts the typed detection result from an analysis report.
func GetUADetectionResultFromReport(report *controller.AnalysisReport) *UADetectionResult {
	if report == nil {
		return nil
	}

	data, ok := report.Data["result"]
	if !ok {
		return nil
	}

	result, ok := data.(*UADetectionResult)
	if !ok {
		return nil
	}

	return result
}

// uaDetectAnalysisController implements the AnalysisController interface for UA parsing.
type uaDetectAnalysisController struct {
	name           string
	logger         *zap.Logger
	config         UADetectAnalysisConfig
	fallbackParser *uaparser.Parser
	cache          map[string]*UADetectionResult
	cacheMu        sync.RWMutex
}

// Analyze extracts the User-Agent header, parses it, and returns a report with
// upstream headers and structured data. The controller is intentionally noop
// when the header is missing.
func (c *uaDetectAnalysisController) Analyze(ctx context.Context, req *runtime.RequestContext) (*controller.AnalysisReport, error) {
	userAgentHeader := extractUserAgentFromRequest(req)
	if userAgentHeader == "" {
		return nil, nil
	}

	data := map[string]any{}

	detectionResult := c.detect(userAgentHeader)
	if detectionResult != nil {
		data["result"] = detectionResult
	}

	req.AddLogFields(makeLogFields(detectionResult)...)

	return &controller.AnalysisReport{
		Controller:      c.name,
		ControllerKind:  ControllerKind,
		UpstreamHeaders: makeUpstreamHeaders(detectionResult),
		Data:            data,
	}, nil
}

// Name implements controller.AnalysisController.
func (c *uaDetectAnalysisController) Name() string {
	return c.name
}

// Kind implements controller.AnalysisController.
func (c *uaDetectAnalysisController) Kind() string {
	return ControllerKind
}

// HealthCheck implements controller.AnalysisController and is trivially healthy
// because the controller has no external dependencies.
func (c *uaDetectAnalysisController) HealthCheck(ctx context.Context) error {
	// No external dependencies to validate.
	return nil
}

// detect parses the user agent string, applying caching and fallback parsing when configured.
func (c *uaDetectAnalysisController) detect(uaString string) *UADetectionResult {
	if c.config.CacheEnabled {
		if cached := c.getCached(uaString); cached != nil {
			c.logger.Debug("ua-detect cache hit", zap.String("ua", uaString))
			return cached
		}
		c.logger.Debug("ua-detect cache miss", zap.String("ua", uaString))
	}

	result := c.userAgentDetection(uaString)

	if c.config.CacheEnabled && c.cache != nil {
		c.cacheMu.Lock()
		c.cache[uaString] = result
		c.cacheMu.Unlock()
	}

	return result
}

// userAgentDetection parses the user agent string into a normalized result structure
// using the primary mileusna/useragent parser.
func (c *uaDetectAnalysisController) userAgentDetection(uaString string) *UADetectionResult {
	ua := useragent.Parse(uaString)

	result := &UADetectionResult{
		Browser: BrowserInfo{
			Name:         ua.Name,
			Version:      ua.Version,
			VersionMajor: ua.VersionNo.Major,
			VersionMinor: ua.VersionNo.Minor,
			VersionPatch: strconv.Itoa(ua.VersionNo.Patch),
		},
		OS: OSInfo{
			Name:         ua.OS,
			Version:      ua.OSVersion,
			VersionMajor: ua.OSVersionNo.Major,
			VersionMinor: ua.OSVersionNo.Minor,
			Platform:     ua.OS,
		},
		Device: DeviceInfo{
			Model:   ua.Device,
			Mobile:  ua.Mobile,
			Tablet:  ua.Tablet,
			Desktop: ua.Desktop,
			TV:      false,
		},
		Bot: BotInfo{
			Detected: ua.Bot,
			URL:      ua.URL,
		},
		RawUserAgent: uaString,
		IsUnknown:    ua.IsUnknown(),
	}

	result.Device.Type = determineDeviceType(result)

	if result.Bot.Detected {
		result.Bot.Name = ua.Name
	}

	if result.IsUnknown && c.fallbackParser != nil {
		result = c.applyFallbackParser(result, uaString)
	}

	return result
}

// getCached returns a previously parsed result for the given UA string.
func (c *uaDetectAnalysisController) getCached(ua string) *UADetectionResult {
	c.cacheMu.RLock()
	defer c.cacheMu.RUnlock()
	return c.cache[ua]
}

// newUADetectAnalysisController builds a UA detection controller instance.
// newUADetectAnalysisController constructs a controller instance, wiring optional
// caching and fallback parsing according to settings.
func newUADetectAnalysisController(ctx context.Context, logger *zap.Logger, cfg config.ControllerConfig) (controller.AnalysisController, error) {
	var settings UADetectAnalysisConfig
	if err := controller.DecodeControllerSettings(cfg.Settings, &settings); err != nil {
		return nil, err
	}
	if _, ok := cfg.Settings["cacheEnabled"]; !ok {
		settings.CacheEnabled = true
	}

	var fallbackParser *uaparser.Parser
	if settings.EnableFallback {
		fallbackParser = uaparser.NewFromSaved()
	}

	var cache map[string]*UADetectionResult
	if settings.CacheEnabled {
		cache = make(map[string]*UADetectionResult)
	}

	return &uaDetectAnalysisController{
		name:           cfg.Name,
		logger:         logger,
		config:         settings,
		fallbackParser: fallbackParser,
		cache:          cache,
	}, nil
}

// extractUserAgentFromRequest navigates the Envoy CheckRequest and returns the
// User-Agent header value, handling case-insensitive header names.
func extractUserAgentFromRequest(req *runtime.RequestContext) string {
	if req == nil || req.Request == nil {
		return ""
	}

	attrs := req.Request.GetAttributes()
	if attrs == nil {
		return ""
	}

	httpReq := attrs.GetRequest()
	if httpReq == nil {
		return ""
	}

	httpHeaders := httpReq.GetHttp()
	if httpHeaders == nil {
		return ""
	}

	headers := httpHeaders.GetHeaders()
	if headers == nil {
		return ""
	}

	for key, value := range headers {
		if strings.ToLower(key) == "user-agent" {
			return value
		}
	}

	return ""
}

// determineDeviceType derives a human-friendly device type label.
func determineDeviceType(detectionResult *UADetectionResult) string {
	switch {
	case detectionResult == nil:
		return "unknown"
	case detectionResult.Bot.Detected:
		return "bot"
	case detectionResult.Device.Mobile:
		return "mobile"
	case detectionResult.Device.Tablet:
		return "tablet"
	case detectionResult.Device.Desktop:
		return "desktop"
	case detectionResult.Device.TV:
		return "tv"
	default:
		return "unknown"
	}
}

// makeUpstreamHeaders converts detection results into headers forwarded to upstream services.
func makeUpstreamHeaders(detectionResult *UADetectionResult) map[string]string {
	if detectionResult == nil {
		return nil
	}

	headers := map[string]string{
		"X-UA-Browser":         detectionResult.Browser.Name,
		"X-UA-Browser-Version": detectionResult.Browser.Version,
		"X-UA-Browser-Major":   strconv.Itoa(detectionResult.Browser.VersionMajor),
		"X-UA-Browser-Minor":   strconv.Itoa(detectionResult.Browser.VersionMinor),
		"X-UA-Browser-Patch":   detectionResult.Browser.VersionPatch,

		"X-UA-OS-Name":     detectionResult.OS.Name,
		"X-UA-OS-Version":  detectionResult.OS.Version,
		"X-UA-OS-Major":    strconv.Itoa(detectionResult.OS.VersionMajor),
		"X-UA-OS-Minor":    strconv.Itoa(detectionResult.OS.VersionMinor),
		"X-UA-OS-Platform": detectionResult.OS.Platform,

		"X-UA-Device-Type":    detectionResult.Device.Type,
		"X-UA-Device-Mobile":  formatBool(detectionResult.Device.Mobile),
		"X-UA-Device-Tablet":  formatBool(detectionResult.Device.Tablet),
		"X-UA-Device-Desktop": formatBool(detectionResult.Device.Desktop),
		"X-UA-Device-TV":      formatBool(detectionResult.Device.TV),
	}

	if detectionResult.Device.Model != "" {
		headers["X-UA-Device-Model"] = detectionResult.Device.Model
	}

	if detectionResult.Bot.Detected && detectionResult.Bot.Name != "" {
		headers["X-UA-Bot-Name"] = detectionResult.Bot.Name
	}

	if detectionResult.Bot.Detected && detectionResult.Bot.URL != "" {
		headers["X-UA-Bot-URL"] = detectionResult.Bot.URL
	}

	return headers
}

// makeLogFields converts detection results to structured log fields.
func makeLogFields(detectionResult *UADetectionResult) []zap.Field {
	if detectionResult == nil {
		return make([]zap.Field, 0)
	}

	fields := []zap.Field{
		zap.String("browser", detectionResult.Browser.Name),
		zap.String("browser_version", detectionResult.Browser.Version),
		zap.String("os", detectionResult.OS.Name),
		zap.String("device_type", detectionResult.Device.Type),
		zap.Bool("is_mobile", detectionResult.Device.Mobile),
		zap.Bool("is_bot", detectionResult.Bot.Detected),
	}

	if detectionResult.Bot.Detected {
		fields = append(fields, zap.String("bot_name", detectionResult.Bot.Name))
	}

	if detectionResult.IsUnknown {
		fields = append(fields, zap.Bool("ua_unknown", true))
	}

	return fields
}

// formatBool renders a boolean as a lowercase string suitable for headers.
func formatBool(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// applyFallbackParser enriches detection results using regex-based parsing when
// the primary parser cannot classify the User-Agent string.
func (c *uaDetectAnalysisController) applyFallbackParser(result *UADetectionResult, uaString string) *UADetectionResult {
	if c.fallbackParser == nil {
		return result
	}

	client := c.fallbackParser.Parse(uaString)
	if client == nil {
		return result
	}

	if client.UserAgent != nil {
		if client.UserAgent.Family != "" {
			result.Browser.Name = client.UserAgent.Family
		}
		result.Browser.Version = joinVersionParts(client.UserAgent.Major, client.UserAgent.Minor, client.UserAgent.Patch)
		result.Browser.VersionMajor = parseInt(client.UserAgent.Major)
		result.Browser.VersionMinor = parseInt(client.UserAgent.Minor)
		result.Browser.VersionPatch = client.UserAgent.Patch
	}

	if client.Os != nil {
		if client.Os.Family != "" {
			result.OS.Name = client.Os.Family
			result.OS.Platform = client.Os.Family
		}
		result.OS.Version = joinVersionParts(client.Os.Major, client.Os.Minor, client.Os.Patch)
		result.OS.VersionMajor = parseInt(client.Os.Major)
		result.OS.VersionMinor = parseInt(client.Os.Minor)
	}

	if client.Device != nil {
		switch {
		case client.Device.Model != "":
			result.Device.Model = client.Device.Model
		case client.Device.Family != "":
			result.Device.Model = client.Device.Family
		}
	}

	if result.Browser.Name != "" || result.OS.Name != "" || result.Device.Model != "" {
		result.IsUnknown = false
	}

	return result
}

// parseInt safely converts a numeric string to int, returning zero on failure.
func parseInt(v string) int {
	i, _ := strconv.Atoi(v)
	return i
}

// joinVersionParts joins version components while skipping empty parts.
func joinVersionParts(parts ...string) string {
	trimmed := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			trimmed = append(trimmed, p)
		}
	}
	return strings.Join(trimmed, ".")
}
