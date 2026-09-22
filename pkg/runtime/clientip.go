package runtime

import (
	"net/netip"
	"strings"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/gtriggiano/envoy-authorization-service/pkg/config"
)

// Labels reported as the IP source in logs.
const (
	// IPSourceNone is reported when no configured source yielded a valid address.
	IPSourceNone = "none"
	// IPSourceEnvoy is reported when the address came from AttributeContext.source.address.
	IPSourceEnvoy = config.ClientIPSourceEnvoy
	// IPSourceXFF is reported when the address came from X-Forwarded-For.
	IPSourceXFF = config.ClientIPSourceXFF
)

const xForwardedForHeader = "x-forwarded-for"

// ClientIPResolver determines the client IP address of a CheckRequest by consulting
// an ordered list of trusted sources. It is safe for concurrent use.
//
// Request headers are consulted only when explicitly configured. The default resolver
// reads AttributeContext.source.address exclusively: that is the address of the peer
// that opened the connection to Envoy and cannot be influenced by request headers.
type ClientIPResolver struct {
	sources      []config.ClientIPSource
	requireValid bool
	needsHeaders bool
}

// NewClientIPResolver builds a resolver from configuration. An empty source list
// resolves to the default (AttributeContext.source.address only).
func NewClientIPResolver(cfg config.ClientIPConfig) *ClientIPResolver {
	sources := cfg.Sources
	if len(sources) == 0 {
		sources = config.DefaultClientIPSources()
	}

	r := &ClientIPResolver{
		sources:      make([]config.ClientIPSource, len(sources)),
		requireValid: cfg.RequireValid,
	}
	copy(r.sources, sources)
	for _, src := range r.sources {
		if src.Header != "" || src.XFF != nil {
			r.needsHeaders = true
		}
	}
	return r
}

// DefaultClientIPResolver returns a resolver that only trusts AttributeContext.source.address.
func DefaultClientIPResolver() *ClientIPResolver {
	return NewClientIPResolver(config.ClientIPConfig{})
}

// RequireValid reports whether requests without a resolvable client address must be denied.
func (r *ClientIPResolver) RequireValid() bool {
	if r == nil {
		return false
	}
	return r.requireValid
}

// Sources returns a human readable description of the configured sources, in order.
func (r *ClientIPResolver) Sources() []string {
	if r == nil {
		return []string{IPSourceEnvoy}
	}
	out := make([]string, 0, len(r.sources))
	for _, src := range r.sources {
		out = append(out, src.String())
	}
	return out
}

// Resolve walks the configured sources in order and returns the first valid address
// together with a label identifying the source that produced it. When nothing matches
// the returned address is the zero value (IsValid() == false) and the label is IPSourceNone.
func (r *ClientIPResolver) Resolve(req *authv3.CheckRequest) (netip.Addr, string) {
	if r == nil {
		return DefaultClientIPResolver().Resolve(req)
	}
	if req == nil {
		return netip.Addr{}, IPSourceNone
	}

	var headers map[string]string
	if r.needsHeaders {
		headers = lowerCaseHeaders(req)
	}

	for _, src := range r.sources {
		switch {
		case src.EnvoySource:
			if addr, ok := envoySourceAddress(req); ok {
				return addr, IPSourceEnvoy
			}
		case src.Header != "":
			if value, ok := headers[src.Header]; ok {
				if addr, ok := parseClientAddr(value); ok {
					return addr, config.ClientIPSourceHeader + ":" + src.Header
				}
			}
		case src.XFF != nil:
			if value, ok := headers[xForwardedForHeader]; ok {
				if addr, ok := addrFromXFF(value, src.XFF.TrustedHops); ok {
					return addr, IPSourceXFF
				}
			}
		}
	}

	return netip.Addr{}, IPSourceNone
}

// envoySourceAddress reads AttributeContext.source.address.
func envoySourceAddress(req *authv3.CheckRequest) (netip.Addr, bool) {
	socketAddr := req.GetAttributes().GetSource().GetAddress().GetSocketAddress()
	if socketAddr == nil {
		return netip.Addr{}, false
	}
	return parseClientAddr(socketAddr.GetAddress())
}

// addrFromXFF picks the client entry out of an X-Forwarded-For value.
//
// Proxies append the address they received the request from, so the list reads
// "client, proxy1, proxy2" and the right-most entries are the ones written by proxies
// the operator controls. The right-most trustedHops entries are skipped and the next
// entry to the left is returned. The left-most entry is never chosen implicitly because
// it is whatever the client decided to send.
func addrFromXFF(value string, trustedHops int) (netip.Addr, bool) {
	if trustedHops < 0 {
		return netip.Addr{}, false
	}
	entries := strings.Split(value, ",")
	idx := len(entries) - 1 - trustedHops
	if idx < 0 {
		return netip.Addr{}, false
	}
	return parseClientAddr(entries[idx])
}

// parseClientAddr parses a textual address as found in headers or socket addresses.
// It accepts plain IPv4/IPv6, "ip:port", "[ipv6]" and "[ipv6]:port"; it strips IPv6
// zones and unmaps IPv4-mapped IPv6 addresses. Unspecified addresses are rejected.
func parseClientAddr(raw string) (netip.Addr, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return netip.Addr{}, false
	}

	if strings.HasPrefix(value, "[") {
		if addrPort, err := netip.ParseAddrPort(value); err == nil {
			return normalizeAddr(addrPort.Addr())
		}
		if end := strings.IndexByte(value, ']'); end == len(value)-1 {
			value = value[1:end]
		}
	}

	if addr, err := netip.ParseAddr(value); err == nil {
		return normalizeAddr(addr)
	}
	if addrPort, err := netip.ParseAddrPort(value); err == nil {
		return normalizeAddr(addrPort.Addr())
	}
	return netip.Addr{}, false
}

func normalizeAddr(addr netip.Addr) (netip.Addr, bool) {
	addr = addr.Unmap().WithZone("")
	if !addr.IsValid() || addr.IsUnspecified() {
		return netip.Addr{}, false
	}
	return addr, true
}

// lowerCaseHeaders returns the request headers keyed by lower-cased name.
func lowerCaseHeaders(req *authv3.CheckRequest) map[string]string {
	src := req.GetAttributes().GetRequest().GetHttp().GetHeaders()
	out := make(map[string]string, len(src))
	for k, v := range src {
		out[strings.ToLower(k)] = v
	}
	return out
}
