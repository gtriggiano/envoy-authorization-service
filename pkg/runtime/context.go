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

// requestIpAddress extracts the downstream client IP address from the CheckRequest.
// It navigates through the Envoy AttributeContext to retrieve the source address
// and returns the zero-value netip.Addr when the IP cannot be determined.
func requestIpAddress(req *authv3.CheckRequest) netip.Addr {
	if req == nil {
		return netip.Addr{}
	}
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
