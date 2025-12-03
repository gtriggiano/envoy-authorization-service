// Package runtime provides request-scoped context and utilities for the authorization flow.
// It extracts and manages metadata from Envoy CheckRequest objects, including client IP
// addresses and structured logging fields.
package runtime

import (
	"net/netip"
	"strings"
	"sync"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"go.uber.org/zap"
)

// RequestContext captures metadata used throughout the authorization flow.
// It provides thread-safe access to logging fields that can be accumulated
// by controllers during request processing.
type RequestContext struct {
	// Request is the original Envoy CheckRequest received from the external auth filter.
	Request *authv3.CheckRequest
	// ReceivedAt records the timestamp when the request was first processed.
	ReceivedAt time.Time
	// Authority is the Host/:authority value extracted from the incoming request.
	Authority string
	// IpAddress contains the parsed downstream client IP address extracted from the request.
	IpAddress netip.Addr

	// mu protects concurrent access to logFields.
	mu sync.RWMutex
	// logFields accumulates structured logging fields throughout request processing.
	logFields []zap.Field
}

// NewRequestContext constructs a RequestContext with the provided values.
func NewRequestContext(req *authv3.CheckRequest) *RequestContext {
	authority := requestAuthority(req)
	ipAddress := requestIpAddress(req)

	return &RequestContext{
		Request:    req,
		ReceivedAt: time.Now(),
		Authority:  authority,
		IpAddress:  ipAddress,
		logFields: []zap.Field{
			zap.String("authority", authority),
			zap.String("ip", ipAddress.String()),
		},
	}
}

// AddLogFields attaches structured fields that should accompany request logging.
func (r *RequestContext) AddLogFields(fields ...zap.Field) {
	if r == nil {
		return
	}

	sanitizedFields := make([]zap.Field, 0, len(fields))
	for _, f := range fields {
		if f.Key == "ip" || f.Key == "authority" {
			continue
		}
		// Here you could add logic to sanitize fields if necessary.
		sanitizedFields = append(sanitizedFields, f)
	}

	r.mu.Lock()
	r.logFields = append(r.logFields, sanitizedFields...)
	r.mu.Unlock()
}

// LogFields returns a snapshot of the accumulated log fields.
func (r *RequestContext) LogFields() []zap.Field {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]zap.Field, len(r.logFields))
	copy(out, r.logFields)
	return out
}

// Standard HTTP headers that may contain the client IP address.
var ipAddressHeadersCandidates = []string{"x-client-ip", "x-forwarded-for", "cf-connecting-ip", "fastly-client-ip", "true-client-ip", "x-real-ip", "x-cluster-client-ip", "x-forwarded", "forwarded-for", "forwarded"}

// requestIpAddress extracts the downstream client IP address from the CheckRequest.
// It navigates through the Envoy AttributeContext to retrieve the source address
// and returns the zero-value netip.Addr when the IP cannot be determined.
func requestIpAddress(req *authv3.CheckRequest) netip.Addr {
	defaultIp := netip.Addr{}

	if req == nil {
		return defaultIp
	}

	// Collect request headers in a case-insensitive map
	requestHeaders := map[string]string{}
	for k, v := range req.GetAttributes().GetRequest().GetHttp().GetHeaders() {
		requestHeaders[strings.ToLower(k)] = v
	}

	for _, candidateHeader := range ipAddressHeadersCandidates {
		switch candidateHeader {
		case "x-forwarded-for": // Load-balancers (AWS ELB) or proxies.
			if headerValue, ok := requestHeaders[candidateHeader]; ok {
				if clientIP, ok := getClientIPFromXForwardedFor(headerValue); ok {
					return clientIP
				}
			}

		default:
			if headerValue, ok := requestHeaders[candidateHeader]; ok {
				if clientIP, err := netip.ParseAddr(headerValue); err == nil {
					return clientIP
				}
			}
		}
	}

	// Fallback to Envoy AttributeContext source address
	attr := req.GetAttributes()
	if attr == nil {
		return netip.Addr{}
	}
	source := attr.GetSource()
	if source == nil {
		return netip.Addr{}
	}
	address := source.GetAddress()
	if address == nil {
		return netip.Addr{}
	}
	socketAddr := address.GetSocketAddress()
	if socketAddr == nil {
		return netip.Addr{}
	}

	ip, _ := netip.ParseAddr(socketAddr.Address)

	return ip
}

// getClientIPFromXForwardedFor  - returns first known ip address else return empty string
func getClientIPFromXForwardedFor(headerValue string) (clientIP netip.Addr, validIP bool) {
	if headerValue == "" {
		return netip.Addr{}, false
	}
	// x-forwarded-for may return multiple IP addresses in the format: "client IP, proxy 1 IP, proxy 2 IP"
	// Therefore, the right-most IP address is the IP address of the most recent proxy
	// and the left-most IP address is the IP address of the originating client.
	forwardedIps := strings.Split(headerValue, ",")
	if len(forwardedIps) > 0 {
		ip := strings.TrimSpace(forwardedIps[0])
		if splitted := strings.Split(ip, ":"); len(splitted) == 2 {
			ip = splitted[0]
		}
		clientIP, err := netip.ParseAddr(ip)
		return clientIP, err == nil
	}

	return netip.Addr{}, false
}

// requestAuthority extracts the :authority/Host value from the CheckRequest.
// It first tries the dedicated Authority field and falls back to the Host
// header, returning "unknown" when no value is present.
func requestAuthority(req *authv3.CheckRequest) string {
	if req == nil {
		return "-"
	}
	attr := req.GetAttributes()
	if attr == nil {
		return "-"
	}

	httpReq := attr.GetRequest()
	if httpReq == nil {
		return "-"
	}

	http := httpReq.GetHttp()
	if http == nil {
		return "-"
	}

	authority := http.GetHost()
	if authority == "" {
		for k, v := range http.GetHeaders() {
			if strings.ToLower(k) == "host" {
				authority = v
				break
			}
		}
	}

	if authority == "" {
		return "-"
	}

	return authority
}
