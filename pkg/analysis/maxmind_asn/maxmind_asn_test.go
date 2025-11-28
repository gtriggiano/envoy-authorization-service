package maxmind_asn

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
			"result": "wrong-type",
		},
	}
	result := GetIpLookupResultFromReport(report)
	if result != nil {
		t.Errorf("expected nil result for report with wrong type, got %v", result)
	}
}

func TestGetIpLookupResultFromReport_ValidResult(t *testing.T) {
	expectedResult := &IpLookupResult{
		AutonomousSystemOrganization: "Test Org",
		AutonomousSystemNumber:       12345,
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
	if result.AutonomousSystemOrganization != expectedResult.AutonomousSystemOrganization {
		t.Errorf("expected org %s, got %s", expectedResult.AutonomousSystemOrganization, result.AutonomousSystemOrganization)
	}
	if result.AutonomousSystemNumber != expectedResult.AutonomousSystemNumber {
		t.Errorf("expected ASN %d, got %d", expectedResult.AutonomousSystemNumber, result.AutonomousSystemNumber)
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
		AutonomousSystemOrganization: "Cloudflare, Inc.",
		AutonomousSystemNumber:       13335,
	}
	headers := makeUpstreamHeaders(result)
	if headers == nil {
		t.Fatal("expected headers, got nil")
	}
	if headers["X-ASN-Number"] != "13335" {
		t.Errorf("expected X-ASN-Number=13335, got %s", headers["X-ASN-Number"])
	}
	if headers["X-ASN-Organization"] != "Cloudflare, Inc." {
		t.Errorf("expected X-ASN-Organization=Cloudflare, Inc., got %s", headers["X-ASN-Organization"])
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
		AutonomousSystemOrganization: "Google LLC",
		AutonomousSystemNumber:       15169,
	}
	fields := makeLogFields(result)
	if fields == nil {
		t.Fatal("expected fields, got nil")
	}
	if len(fields) != 2 {
		t.Errorf("expected 2 fields, got %d", len(fields))
	}
}

func TestControllerName(t *testing.T) {
	controller := &maxMindAsnAnalysisController{
		name:   "test-asn-controller",
		logger: zap.NewNop(),
		cache:  make(map[string]*IpLookupResult),
	}
	if controller.Name() != "test-asn-controller" {
		t.Errorf("expected name test-asn-controller, got %s", controller.Name())
	}
}

func TestControllerKind(t *testing.T) {
	controller := &maxMindAsnAnalysisController{
		name:   "test-asn-controller",
		logger: zap.NewNop(),
		cache:  make(map[string]*IpLookupResult),
	}
	if controller.Kind() != ControllerKind {
		t.Errorf("expected kind %s, got %s", ControllerKind, controller.Kind())
	}
	if ControllerKind != "maxmind-asn" {
		t.Errorf("expected ControllerKind constant to be maxmind-asn, got %s", ControllerKind)
	}
}

func TestIpLookup_CacheHit(t *testing.T) {
	cachedResult := &IpLookupResult{
		AutonomousSystemOrganization: "Cached Org",
		AutonomousSystemNumber:       99999,
	}
	controller := &maxMindAsnAnalysisController{
		name:   "test",
		logger: zap.NewNop(),
		cache: map[string]*IpLookupResult{
			"1.1.1.1": cachedResult,
		},
	}

	ip := netip.MustParseAddr("1.1.1.1")
	result := controller.ipLookup(ip)

	if result == nil {
		t.Fatal("expected cached result, got nil")
	}
	if result.AutonomousSystemNumber != 99999 {
		t.Errorf("expected cached ASN 99999, got %d", result.AutonomousSystemNumber)
	}
	if result.AutonomousSystemOrganization != "Cached Org" {
		t.Errorf("expected cached org, got %s", result.AutonomousSystemOrganization)
	}
}

func TestMakeUpstreamHeaders_ZeroASN(t *testing.T) {
	result := &IpLookupResult{
		AutonomousSystemOrganization: "",
		AutonomousSystemNumber:       0,
	}
	headers := makeUpstreamHeaders(result)
	if headers == nil {
		t.Fatal("expected headers, got nil")
	}
	if headers["X-ASN-Number"] != "0" {
		t.Errorf("expected X-ASN-Number=0, got %s", headers["X-ASN-Number"])
	}
	if headers["X-ASN-Organization"] != "" {
		t.Errorf("expected empty X-ASN-Organization, got %s", headers["X-ASN-Organization"])
	}
}

func TestMakeUpstreamHeaders_LargeASN(t *testing.T) {
	result := &IpLookupResult{
		AutonomousSystemOrganization: "Large ASN Test",
		AutonomousSystemNumber:       4294967295, // max uint32
	}
	headers := makeUpstreamHeaders(result)
	if headers == nil {
		t.Fatal("expected headers, got nil")
	}
	if headers["X-ASN-Number"] != "4294967295" {
		t.Errorf("expected X-ASN-Number=4294967295, got %s", headers["X-ASN-Number"])
	}
}

func TestMakeLogFields_EmptyOrganization(t *testing.T) {
	result := &IpLookupResult{
		AutonomousSystemOrganization: "",
		AutonomousSystemNumber:       12345,
	}
	fields := makeLogFields(result)
	if fields == nil {
		t.Fatal("expected fields, got nil")
	}
	// Should still create fields even with empty organization
	if len(fields) != 2 {
		t.Errorf("expected 2 fields, got %d", len(fields))
	}
}
