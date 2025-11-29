package runtime

import (
	"net/netip"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"go.uber.org/zap"
)

func TestNewRequestContextInitializesFields(t *testing.T) {
	ip := "203.0.113.10"
	req := &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Host: "example.com",
				},
			},
			Source: &authv3.AttributeContext_Peer{
				Address: &corev3.Address{
					Address: &corev3.Address_SocketAddress{
						SocketAddress: &corev3.SocketAddress{Address: ip},
					},
				},
			},
		},
	}

	ctx := NewRequestContext(req)

	if ctx.Request != req {
		t.Fatalf("request should be preserved on context")
	}
	if ctx.Authority != "example.com" {
		t.Fatalf("expected authority to be populated, got %q", ctx.Authority)
	}
	if ctx.ReceivedAt.IsZero() {
		t.Fatalf("expected ReceivedAt to be set")
	}
	if time.Since(ctx.ReceivedAt) > time.Second {
		t.Fatalf("ReceivedAt looks stale: %s", ctx.ReceivedAt)
	}
	if ctx.IpAddress.String() != ip {
		t.Fatalf("expected ip %s, got %s", ip, ctx.IpAddress.String())
	}

	fields := ctx.LogFields()
	if len(fields) != 2 {
		t.Fatalf("expected 2 log fields, got %d", len(fields))
	}
	want := map[string]string{"authority": "example.com", "ip": ip}
	for _, f := range fields {
		if want[f.Key] != f.String {
			t.Fatalf("unexpected log field %q -> %q", f.Key, f.String)
		}
	}
}

func TestAddLogFieldsSkipsIPAndCopies(t *testing.T) {
	req := &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Source: &authv3.AttributeContext_Peer{
				Address: &corev3.Address{
					Address: &corev3.Address_SocketAddress{
						SocketAddress: &corev3.SocketAddress{Address: "198.51.100.1"},
					},
				},
			},
		},
	}
	ctx := NewRequestContext(req)

	ctx.AddLogFields(zap.String("user", "alice"), zap.String("ip", "ignored"))

	fields := ctx.LogFields()
	if len(fields) != 3 {
		t.Fatalf("expected 3 log fields, got %d", len(fields))
	}
	if fields[2].Key != "user" || fields[2].String != "alice" {
		t.Fatalf("unexpected user field: %+v", fields[2])
	}

	// Mutating the returned slice must not affect internal storage.
	fields[0].Key = "mutated"
	if ctx.LogFields()[0].Key != "authority" {
		t.Fatalf("log fields slice was not copied")
	}
}

func TestAddLogFieldsNilReceiverDoesNotPanic(t *testing.T) {
	var ctx *RequestContext
	ctx.AddLogFields(zap.String("foo", "bar"))
}

func TestRequestIpAddressExtraction(t *testing.T) {
	tests := []struct {
		name string
		req  *authv3.CheckRequest
		want netip.Addr
	}{
		{
			name: "nil request",
			req:  nil,
			want: netip.Addr{},
		},
		{
			name: "missing attributes",
			req:  &authv3.CheckRequest{},
			want: netip.Addr{},
		},
		{
			name: "invalid ip string",
			req: &authv3.CheckRequest{
				Attributes: &authv3.AttributeContext{
					Source: &authv3.AttributeContext_Peer{
						Address: &corev3.Address{
							Address: &corev3.Address_SocketAddress{
								SocketAddress: &corev3.SocketAddress{Address: "not-an-ip"},
							},
						},
					},
				},
			},
			want: netip.Addr{},
		},
		{
			name: "valid ip",
			req: &authv3.CheckRequest{
				Attributes: &authv3.AttributeContext{
					Source: &authv3.AttributeContext_Peer{
						Address: &corev3.Address{
							Address: &corev3.Address_SocketAddress{
								SocketAddress: &corev3.SocketAddress{Address: "192.0.2.7"},
							},
						},
					},
				},
			},
			want: netip.MustParseAddr("192.0.2.7"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := requestIpAddress(tt.req)
			if got != tt.want {
				t.Fatalf("expected %v, got %v", tt.want, got)
			}
		})
	}
}

func TestRequestAuthorityExtraction(t *testing.T) {
	tests := []struct {
		name string
		req  *authv3.CheckRequest
		want string
	}{
		{name: "nil request", want: "-"},
		{name: "missing attributes", req: &authv3.CheckRequest{}, want: "-"},
		{
			name: "host field preferred",
			req: &authv3.CheckRequest{
				Attributes: &authv3.AttributeContext{
					Request: &authv3.AttributeContext_Request{
						Http: &authv3.AttributeContext_HttpRequest{
							Host:    "api.service.local",
							Headers: map[string]string{"host": "should-not-be-used"},
						},
					},
				},
			},
			want: "api.service.local",
		},
		{
			name: "host header fallback",
			req: &authv3.CheckRequest{
				Attributes: &authv3.AttributeContext{
					Request: &authv3.AttributeContext_Request{
						Http: &authv3.AttributeContext_HttpRequest{
							Headers: map[string]string{"HOST": "header.local"},
						},
					},
				},
			},
			want: "header.local",
		},
		{
			name: "missing authority and host",
			req: &authv3.CheckRequest{
				Attributes: &authv3.AttributeContext{
					Request: &authv3.AttributeContext_Request{
						Http: &authv3.AttributeContext_HttpRequest{},
					},
				},
			},
			want: "-",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := requestAuthority(tt.req); got != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, got)
			}
		})
	}
}
