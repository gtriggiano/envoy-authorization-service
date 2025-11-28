package maxmind_geoip

import (
	"net/netip"
	"testing"

	"github.com/gtriggiano/envoy-authorization-service/pkg/controller"
	"go.uber.org/zap"
)

func TestGetIpLookupResultFromReport_NilReport(t *testing.T) {
	result := GetIpLookupResultFromReport(nil)
	if result != nil {
		t.Errorf("expected nil result for nil report, got %v", result)
	}
}

func TestGetIpLookupResultFromReport_MissingData(t *testing.T) {
	report := &controller.AnalysisReport{
		Data: map[string]any{},
	}
	result := GetIpLookupResultFromReport(report)
	if result != nil {
		t.Errorf("expected nil result for report without result data, got %v", result)
	}
}

func TestGetIpLookupResultFromReport_WrongType(t *testing.T) {
	report := &controller.AnalysisReport{
		Data: map[string]any{
			"result": 12345,
		},
	}
	result := GetIpLookupResultFromReport(report)
	if result != nil {
		t.Errorf("expected nil result for report with wrong type, got %v", result)
	}
}

func TestGetIpLookupResultFromReport_ValidResult(t *testing.T) {
	expectedResult := &IpLookupResult{
		City:          "Mountain View",
		PostalCode:    "94043",
		Region:        "California",
		CountryName:   "United States",
		CountryISO:    "US",
		ContinentName: "North America",
		TimeZone:      "America/Los_Angeles",
		Latitude:      37.386,
		Longitude:     -122.0838,
	}
	report := &controller.AnalysisReport{
		Data: map[string]any{
			"result": expectedResult,
		},
	}
	result := GetIpLookupResultFromReport(report)
	if result == nil {
		t.Fatal("expected valid result, got nil")
	}
	if result.City != expectedResult.City {
		t.Errorf("expected city %s, got %s", expectedResult.City, result.City)
	}
	if result.CountryISO != expectedResult.CountryISO {
		t.Errorf("expected country ISO %s, got %s", expectedResult.CountryISO, result.CountryISO)
	}
	if result.Latitude != expectedResult.Latitude {
		t.Errorf("expected latitude %f, got %f", expectedResult.Latitude, result.Latitude)
	}
}

func TestMakeUpstreamHeaders_NilResult(t *testing.T) {
	headers := makeUpstreamHeaders(nil)
	if headers != nil {
		t.Errorf("expected nil headers for nil result, got %v", headers)
	}
}

func TestMakeUpstreamHeaders_ValidResult(t *testing.T) {
	result := &IpLookupResult{
		City:          "London",
		PostalCode:    "EC1A",
		Region:        "England",
		CountryName:   "United Kingdom",
		CountryISO:    "GB",
		ContinentName: "Europe",
		TimeZone:      "Europe/London",
		Latitude:      51.5074,
		Longitude:     -0.1278,
	}
	headers := makeUpstreamHeaders(result)
	if headers == nil {
		t.Fatal("expected headers, got nil")
	}

	expectedHeaders := map[string]string{
		"X-GeoIP-City":       "London",
		"X-GeoIP-PostalCode": "EC1A",
		"X-GeoIP-Region":     "England",
		"X-GeoIP-Country":    "United Kingdom",
		"X-GeoIP-CountryISO": "GB",
		"X-GeoIP-Continent":  "Europe",
		"X-GeoIP-TimeZone":   "Europe/London",
		"X-GeoIP-Latitude":   "51.507400",
		"X-GeoIP-Longitude":  "-0.127800",
	}

	for key, expectedValue := range expectedHeaders {
		if headers[key] != expectedValue {
			t.Errorf("expected %s=%s, got %s", key, expectedValue, headers[key])
		}
	}
}

func TestMakeUpstreamHeaders_EmptyFields(t *testing.T) {
	result := &IpLookupResult{
		City:          "",
		PostalCode:    "",
		Region:        "",
		CountryName:   "",
		CountryISO:    "",
		ContinentName: "",
		TimeZone:      "",
		Latitude:      0.0,
		Longitude:     0.0,
	}
	headers := makeUpstreamHeaders(result)
	if headers == nil {
		t.Fatal("expected headers, got nil")
	}
	if len(headers) != 9 {
		t.Errorf("expected 9 headers, got %d", len(headers))
	}
}

func TestMakeLogFields_NilResult(t *testing.T) {
	fields := makeLogFields(nil)
	if fields != nil {
		t.Errorf("expected nil fields for nil result, got %v", fields)
	}
}

func TestMakeLogFields_ValidResult(t *testing.T) {
	result := &IpLookupResult{
		City:          "Tokyo",
		PostalCode:    "100-0001",
		Region:        "Tokyo",
		CountryName:   "Japan",
		CountryISO:    "JP",
		ContinentName: "Asia",
		TimeZone:      "Asia/Tokyo",
		Latitude:      35.6762,
		Longitude:     139.6503,
	}
	fields := makeLogFields(result)
	if fields == nil {
		t.Fatal("expected fields, got nil")
	}
	if len(fields) != 9 {
		t.Errorf("expected 9 fields, got %d", len(fields))
	}
}

func TestControllerName(t *testing.T) {
	controller := &maxMindCityAnalysisController{
		name:   "test-geoip-controller",
		logger: zap.NewNop(),
		cache:  make(map[string]*IpLookupResult),
	}
	if controller.Name() != "test-geoip-controller" {
		t.Errorf("expected name test-geoip-controller, got %s", controller.Name())
	}
}

func TestControllerKind(t *testing.T) {
	controller := &maxMindCityAnalysisController{
		name:   "test-geoip-controller",
		logger: zap.NewNop(),
		cache:  make(map[string]*IpLookupResult),
	}
	if controller.Kind() != ControllerKind {
		t.Errorf("expected kind %s, got %s", ControllerKind, controller.Kind())
	}
	if ControllerKind != "maxmind-geoip" {
		t.Errorf("expected ControllerKind constant to be maxmind-geoip, got %s", ControllerKind)
	}
}

func TestIpLookup_CacheHit(t *testing.T) {
	cachedResult := &IpLookupResult{
		City:        "Cached City",
		CountryISO:  "CC",
		CountryName: "Cached Country",
	}
	controller := &maxMindCityAnalysisController{
		name:   "test",
		logger: zap.NewNop(),
		cache: map[string]*IpLookupResult{
			"8.8.8.8": cachedResult,
		},
	}

	ip := netip.MustParseAddr("8.8.8.8")
	result := controller.ipLookup(ip)

	if result == nil {
		t.Fatal("expected cached result, got nil")
	}
	if result.City != "Cached City" {
		t.Errorf("expected cached city, got %s", result.City)
	}
	if result.CountryISO != "CC" {
		t.Errorf("expected cached country ISO, got %s", result.CountryISO)
	}
}

func TestMakeUpstreamHeaders_NegativeCoordinates(t *testing.T) {
	result := &IpLookupResult{
		City:          "Sydney",
		CountryName:   "Australia",
		CountryISO:    "AU",
		ContinentName: "Oceania",
		TimeZone:      "Australia/Sydney",
		Latitude:      -33.8688,
		Longitude:     151.2093,
	}
	headers := makeUpstreamHeaders(result)
	if headers == nil {
		t.Fatal("expected headers, got nil")
	}
	if headers["X-GeoIP-Latitude"] != "-33.868800" {
		t.Errorf("expected negative latitude, got %s", headers["X-GeoIP-Latitude"])
	}
	if headers["X-GeoIP-Longitude"] != "151.209300" {
		t.Errorf("expected positive longitude, got %s", headers["X-GeoIP-Longitude"])
	}
}

func TestMakeUpstreamHeaders_ExtremeCoordinates(t *testing.T) {
	result := &IpLookupResult{
		City:       "North Pole Research Station",
		Latitude:   90.0,
		Longitude:  0.0,
		CountryISO: "XX",
	}
	headers := makeUpstreamHeaders(result)
	if headers == nil {
		t.Fatal("expected headers, got nil")
	}
	if headers["X-GeoIP-Latitude"] != "90.000000" {
		t.Errorf("expected latitude 90.000000, got %s", headers["X-GeoIP-Latitude"])
	}
}

func TestMakeLogFields_AllFieldsPopulated(t *testing.T) {
	result := &IpLookupResult{
		City:          "Berlin",
		PostalCode:    "10115",
		Region:        "Berlin",
		CountryName:   "Germany",
		CountryISO:    "DE",
		ContinentName: "Europe",
		TimeZone:      "Europe/Berlin",
		Latitude:      52.5200,
		Longitude:     13.4050,
	}
	fields := makeLogFields(result)
	if fields == nil {
		t.Fatal("expected fields, got nil")
	}
	expectedFieldCount := 9
	if len(fields) != expectedFieldCount {
		t.Errorf("expected %d fields, got %d", expectedFieldCount, len(fields))
	}
}

func TestMakeLogFields_EmptyStrings(t *testing.T) {
	result := &IpLookupResult{
		City:          "",
		PostalCode:    "",
		Region:        "",
		CountryName:   "",
		CountryISO:    "",
		ContinentName: "",
		TimeZone:      "",
		Latitude:      0.0,
		Longitude:     0.0,
	}
	fields := makeLogFields(result)
	if fields == nil {
		t.Fatal("expected fields, got nil")
	}
	if len(fields) != 9 {
		t.Errorf("expected 9 fields even with empty values, got %d", len(fields))
	}
}

func TestIpLookupResult_StructFields(t *testing.T) {
	result := IpLookupResult{
		City:          "Test City",
		PostalCode:    "12345",
		Region:        "Test Region",
		CountryName:   "Test Country",
		CountryISO:    "TC",
		ContinentName: "Test Continent",
		TimeZone:      "Test/Timezone",
		Latitude:      12.34,
		Longitude:     56.78,
	}

	if result.City != "Test City" {
		t.Errorf("City field mismatch")
	}
	if result.PostalCode != "12345" {
		t.Errorf("PostalCode field mismatch")
	}
	if result.Region != "Test Region" {
		t.Errorf("Region field mismatch")
	}
	if result.CountryName != "Test Country" {
		t.Errorf("CountryName field mismatch")
	}
	if result.CountryISO != "TC" {
		t.Errorf("CountryISO field mismatch")
	}
	if result.ContinentName != "Test Continent" {
		t.Errorf("ContinentName field mismatch")
	}
	if result.TimeZone != "Test/Timezone" {
		t.Errorf("TimeZone field mismatch")
	}
	if result.Latitude != 12.34 {
		t.Errorf("Latitude field mismatch")
	}
	if result.Longitude != 56.78 {
		t.Errorf("Longitude field mismatch")
	}
}
