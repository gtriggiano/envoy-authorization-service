package runtime

import (
	"net/netip"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/gtriggiano/envoy-authorization-service/pkg/config"
)

// checkRequest builds a CheckRequest with the given Envoy source address and headers.
func checkRequest(sourceAddress string, headers map[string]string) *authv3.CheckRequest {
	req := &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{Headers: headers},
			},
		},
	}
	if sourceAddress != "" {
		req.Attributes.Source = &authv3.AttributeContext_Peer{
			Address: &corev3.Address{
				Address: &corev3.Address_SocketAddress{
					SocketAddress: &corev3.SocketAddress{Address: sourceAddress},
				},
			},
		}
	}
	return req
}

func envoySource() config.ClientIPSource { return config.ClientIPSource{EnvoySource: true} }
func headerSource(name string) config.ClientIPSource {
	return config.ClientIPSource{Header: name}
}
func xffSource(hops int) config.ClientIPSource {
	return config.ClientIPSource{XFF: &config.XFFSource{TrustedHops: hops}}
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestDefaultResolverIgnoresEveryHeader(t *testing.T) {
	// Every header commonly used to carry a client address, all pointing at an allow-listed
	// partner address, while the connection really comes from the attacker.
	spoofed := map[string]string{
		"x-client-ip":              "203.0.113.10",
		"x-forwarded-for":          "203.0.113.10",
		"cf-connecting-ip":         "203.0.113.10",
		"fastly-client-ip":         "203.0.113.10",
		"true-client-ip":           "203.0.113.10",
		"x-real-ip":                "203.0.113.10",
		"x-cluster-client-ip":      "203.0.113.10",
		"x-forwarded":              "203.0.113.10",
		"forwarded-for":            "203.0.113.10",
		"forwarded":                "for=203.0.113.10",
		"x-envoy-external-address": "203.0.113.10",
	}

	for _, resolver := range []*ClientIPResolver{nil, DefaultClientIPResolver(), NewClientIPResolver(config.ClientIPConfig{})} {
		addr, source := resolver.Resolve(checkRequest("198.51.100.7", spoofed))
		if addr != mustAddr("198.51.100.7") {
			t.Fatalf("expected the connection peer 198.51.100.7, got %v (source %s)", addr, source)
		}
		if source != IPSourceEnvoy {
			t.Fatalf("expected source %q, got %q", IPSourceEnvoy, source)
		}
	}
}

func TestResolverNilAndEmptyRequests(t *testing.T) {
	r := NewClientIPResolver(config.ClientIPConfig{Sources: []config.ClientIPSource{headerSource("x-real-ip"), xffSource(0), envoySource()}})

	for name, req := range map[string]*authv3.CheckRequest{
		"nil request":        nil,
		"empty request":      {},
		"no source, no hdrs": checkRequest("", nil),
		"invalid source":     checkRequest("not-an-ip", nil),
		"unspecified source": checkRequest("0.0.0.0", nil),
	} {
		t.Run(name, func(t *testing.T) {
			addr, source := r.Resolve(req)
			if addr.IsValid() {
				t.Fatalf("expected no address, got %v", addr)
			}
			if source != IPSourceNone {
				t.Fatalf("expected source %q, got %q", IPSourceNone, source)
			}
		})
	}
}

func TestResolverSourceOrder(t *testing.T) {
	tests := []struct {
		name       string
		sources    []config.ClientIPSource
		source     string
		headers    map[string]string
		wantAddr   string
		wantSource string
	}{
		{
			name:       "header wins when present and valid",
			sources:    []config.ClientIPSource{headerSource("x-envoy-external-address"), envoySource()},
			source:     "10.0.0.5",
			headers:    map[string]string{"x-envoy-external-address": "203.0.113.10"},
			wantAddr:   "203.0.113.10",
			wantSource: "header:x-envoy-external-address",
		},
		{
			name:       "header names are matched case-insensitively",
			sources:    []config.ClientIPSource{headerSource("x-envoy-external-address"), envoySource()},
			source:     "10.0.0.5",
			headers:    map[string]string{"X-Envoy-External-Address": "203.0.113.10"},
			wantAddr:   "203.0.113.10",
			wantSource: "header:x-envoy-external-address",
		},
		{
			name:       "missing header falls through to envoy source",
			sources:    []config.ClientIPSource{headerSource("x-envoy-external-address"), envoySource()},
			source:     "10.0.0.5",
			headers:    map[string]string{},
			wantAddr:   "10.0.0.5",
			wantSource: IPSourceEnvoy,
		},
		{
			name:       "garbage header falls through to envoy source",
			sources:    []config.ClientIPSource{headerSource("x-envoy-external-address"), envoySource()},
			source:     "10.0.0.5",
			headers:    map[string]string{"x-envoy-external-address": "203.0.113.10, 198.51.100.1"},
			wantAddr:   "10.0.0.5",
			wantSource: IPSourceEnvoy,
		},
		{
			name:       "only configured headers are consulted",
			sources:    []config.ClientIPSource{headerSource("x-envoy-external-address"), envoySource()},
			source:     "10.0.0.5",
			headers:    map[string]string{"x-real-ip": "203.0.113.10", "x-forwarded-for": "203.0.113.10"},
			wantAddr:   "10.0.0.5",
			wantSource: IPSourceEnvoy,
		},
		{
			name:       "envoy source first short-circuits headers",
			sources:    []config.ClientIPSource{envoySource(), headerSource("x-real-ip")},
			source:     "10.0.0.5",
			headers:    map[string]string{"x-real-ip": "203.0.113.10"},
			wantAddr:   "10.0.0.5",
			wantSource: IPSourceEnvoy,
		},
		{
			name:       "no valid source at all",
			sources:    []config.ClientIPSource{headerSource("x-real-ip"), xffSource(0)},
			source:     "10.0.0.5",
			headers:    map[string]string{},
			wantAddr:   "",
			wantSource: IPSourceNone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewClientIPResolver(config.ClientIPConfig{Sources: tt.sources})
			addr, source := r.Resolve(checkRequest(tt.source, tt.headers))
			if tt.wantAddr == "" {
				if addr.IsValid() {
					t.Fatalf("expected no address, got %v", addr)
				}
			} else if addr != mustAddr(tt.wantAddr) {
				t.Fatalf("expected %s, got %v", tt.wantAddr, addr)
			}
			if source != tt.wantSource {
				t.Fatalf("expected source %q, got %q", tt.wantSource, source)
			}
		})
	}
}

func TestResolverXFFRightToLeft(t *testing.T) {
	tests := []struct {
		name     string
		hops     int
		xff      string
		wantAddr string // empty means fall through to the envoy source (10.0.0.5)
	}{
		{name: "hops 0 takes right-most", hops: 0, xff: "203.0.113.10, 198.51.100.1", wantAddr: "198.51.100.1"},
		{name: "hops 1 skips one proxy", hops: 1, xff: "203.0.113.10, 198.51.100.1", wantAddr: "203.0.113.10"},
		{name: "hops 1 with envoy-appended peer", hops: 1, xff: "203.0.113.10,172.17.0.1", wantAddr: "203.0.113.10"},
		{name: "hops 2 skips two proxies", hops: 2, xff: "203.0.113.10, 198.51.100.1, 192.0.2.1", wantAddr: "203.0.113.10"},
		{name: "client-prepended junk is ignored", hops: 1, xff: "1.2.3.4, 5.6.7.8, 203.0.113.10, 198.51.100.1", wantAddr: "203.0.113.10"},
		{name: "single entry with hops 0", hops: 0, xff: "203.0.113.10", wantAddr: "203.0.113.10"},
		{name: "too few entries falls through", hops: 1, xff: "203.0.113.10", wantAddr: ""},
		{name: "too few entries (hops 3) falls through", hops: 3, xff: "203.0.113.10, 198.51.100.1", wantAddr: ""},
		{name: "empty header falls through", hops: 0, xff: "", wantAddr: ""},
		{name: "obfuscated identifier falls through", hops: 0, xff: "203.0.113.10, _hidden", wantAddr: ""},
		{name: "unknown falls through", hops: 0, xff: "unknown", wantAddr: ""},
		{name: "rfc7239 syntax is not parsed", hops: 0, xff: "for=203.0.113.10;proto=https", wantAddr: ""},
		{name: "ipv4 with port", hops: 0, xff: "203.0.113.10:4711", wantAddr: "203.0.113.10"},
		{name: "ipv6 plain", hops: 0, xff: "2001:db8::1", wantAddr: "2001:db8::1"},
		{name: "ipv6 bracketed", hops: 0, xff: "[2001:db8::1]", wantAddr: "2001:db8::1"},
		{name: "ipv6 bracketed with port", hops: 0, xff: "[2001:db8::1]:443", wantAddr: "2001:db8::1"},
		{name: "ipv6 mixed list", hops: 1, xff: "2001:db8::1, 203.0.113.10", wantAddr: "2001:db8::1"},
		{name: "ipv4-mapped ipv6 is unmapped", hops: 0, xff: "::ffff:203.0.113.10", wantAddr: "203.0.113.10"},
		{name: "ipv6 zone is stripped", hops: 0, xff: "fe80::1%eth0", wantAddr: "fe80::1"},
		{name: "unspecified is rejected", hops: 0, xff: "0.0.0.0", wantAddr: ""},
		{name: "whitespace is tolerated", hops: 1, xff: "  203.0.113.10 ,   198.51.100.1  ", wantAddr: "203.0.113.10"},
		{name: "trailing comma yields empty entry", hops: 0, xff: "203.0.113.10,", wantAddr: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewClientIPResolver(config.ClientIPConfig{Sources: []config.ClientIPSource{xffSource(tt.hops), envoySource()}})
			headers := map[string]string{}
			if tt.xff != "" {
				headers["x-forwarded-for"] = tt.xff
			}
			addr, source := r.Resolve(checkRequest("10.0.0.5", headers))
			if tt.wantAddr == "" {
				if addr != mustAddr("10.0.0.5") || source != IPSourceEnvoy {
					t.Fatalf("expected fall through to envoy source, got %v (%s)", addr, source)
				}
				return
			}
			if addr != mustAddr(tt.wantAddr) || source != IPSourceXFF {
				t.Fatalf("expected %s from xff, got %v (%s)", tt.wantAddr, addr, source)
			}
		})
	}
}

func TestResolverXFFOnlyNeverUsesLeftMostImplicitly(t *testing.T) {
	// Without an envoy fallback, an attacker who prepends entries cannot move the
	// selected address: the selection is anchored on the right end.
	r := NewClientIPResolver(config.ClientIPConfig{Sources: []config.ClientIPSource{xffSource(1)}})

	legit := map[string]string{"x-forwarded-for": "203.0.113.10, 198.51.100.1"}
	addr, _ := r.Resolve(checkRequest("10.0.0.5", legit))
	if addr != mustAddr("203.0.113.10") {
		t.Fatalf("baseline: expected 203.0.113.10, got %v", addr)
	}

	attack := map[string]string{"x-forwarded-for": "192.0.2.99, 203.0.113.10, 198.51.100.1"}
	addr, _ = r.Resolve(checkRequest("10.0.0.5", attack))
	if addr != mustAddr("203.0.113.10") {
		t.Fatalf("attack: expected 203.0.113.10, got %v", addr)
	}
}

func TestParseClientAddr(t *testing.T) {
	tests := map[string]string{
		"203.0.113.10":          "203.0.113.10",
		" 203.0.113.10 ":        "203.0.113.10",
		"203.0.113.10:8080":     "203.0.113.10",
		"2001:db8::1":           "2001:db8::1",
		"[2001:db8::1]":         "2001:db8::1",
		"[2001:db8::1]:8080":    "2001:db8::1",
		"::ffff:198.51.100.1":   "198.51.100.1",
		"[::ffff:198.51.100.1]": "198.51.100.1",
		"fe80::1%en0":           "fe80::1",
		"":                      "",
		"0.0.0.0":               "",
		"::":                    "",
		"[::]:80":               "",
		"not-an-ip":             "",
		"for=203.0.113.10":      "",
		"203.0.113.10, 1.1.1.1": "",
		"[2001:db8::1":          "",
		"2001:db8::1]":          "",
		"203.0.113.10:notaport": "",
	}
	for in, want := range tests {
		t.Run(in, func(t *testing.T) {
			addr, ok := parseClientAddr(in)
			if want == "" {
				if ok {
					t.Fatalf("expected %q to be rejected, got %v", in, addr)
				}
				return
			}
			if !ok || addr != mustAddr(want) {
				t.Fatalf("expected %s, got %v (ok=%v)", want, addr, ok)
			}
		})
	}
}

func TestResolverSourcesAndRequireValid(t *testing.T) {
	var nilResolver *ClientIPResolver
	if nilResolver.RequireValid() {
		t.Fatalf("nil resolver must not require a valid IP")
	}
	if got := nilResolver.Sources(); len(got) != 1 || got[0] != IPSourceEnvoy {
		t.Fatalf("unexpected nil resolver sources: %v", got)
	}

	r := NewClientIPResolver(config.ClientIPConfig{
		Sources:      []config.ClientIPSource{headerSource("x-envoy-external-address"), xffSource(2), envoySource()},
		RequireValid: true,
	})
	if !r.RequireValid() {
		t.Fatalf("expected requireValid to be honoured")
	}
	want := []string{"header:x-envoy-external-address", "xff:trustedHops=2", "envoySource"}
	got := r.Sources()
	if len(got) != len(want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("expected %v, got %v", want, got)
		}
	}
}

func TestNewRequestContextWithResolverReportsSource(t *testing.T) {
	r := NewClientIPResolver(config.ClientIPConfig{Sources: []config.ClientIPSource{xffSource(0)}})
	ctx := NewRequestContext(checkRequest("10.0.0.5", map[string]string{"x-forwarded-for": "203.0.113.10"}), r)
	if ctx.IpAddress != mustAddr("203.0.113.10") || ctx.IpSource != IPSourceXFF {
		t.Fatalf("unexpected context ip %v / source %s", ctx.IpAddress, ctx.IpSource)
	}

	ctx = NewRequestContext(checkRequest("10.0.0.5", nil), r)
	if ctx.IpAddress.IsValid() || ctx.IpSource != IPSourceNone {
		t.Fatalf("expected unresolved ip, got %v / %s", ctx.IpAddress, ctx.IpSource)
	}
	for _, f := range ctx.LogFields() {
		if f.Key == "ip" && f.String != "invalid IP" {
			t.Fatalf("unexpected ip log field %q", f.String)
		}
	}
}

func FuzzParseClientAddr(f *testing.F) {
	for _, seed := range []string{"203.0.113.10", "[2001:db8::1]:443", "::ffff:1.2.3.4", "fe80::1%eth0", "unknown", "for=1.2.3.4", "", "[", "]", "1.2.3.4:"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		addr, ok := parseClientAddr(raw)
		if ok && (!addr.IsValid() || addr.IsUnspecified() || addr.Zone() != "" || addr.Is4In6()) {
			t.Fatalf("parseClientAddr(%q) accepted a non-normalised address %v", raw, addr)
		}
		if !ok && addr.IsValid() {
			t.Fatalf("parseClientAddr(%q) returned a valid address with ok=false", raw)
		}
	})
}

func FuzzAddrFromXFF(f *testing.F) {
	for _, seed := range []string{"1.1.1.1, 2.2.2.2", ",,,", "a,b,c", "[::1]:80,1.1.1.1", " 1.1.1.1 ,2.2.2.2,"} {
		f.Add(seed, 0)
		f.Add(seed, 1)
		f.Add(seed, 5)
	}
	f.Fuzz(func(t *testing.T, value string, hops int) {
		addr, ok := addrFromXFF(value, hops)
		if hops < 0 && ok {
			t.Fatalf("negative hops must never resolve, got %v", addr)
		}
		if ok && !addr.IsValid() {
			t.Fatalf("ok without a valid address for %q/%d", value, hops)
		}
	})
}
