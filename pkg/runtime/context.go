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
	// IpAddress contains the client IP address resolved by the configured ClientIPResolver.
	// It is the zero value (IsValid() == false) when no trusted source yielded an address.
	IpAddress netip.Addr
	// IpSource names the source the IP address was taken from (see ClientIPResolver.Resolve).
	IpSource string

	// mu protects concurrent access to logFields.
	mu sync.RWMutex
	// logFields accumulates structured logging fields throughout request processing.
	logFields []zap.Field
}

// NewRequestContext constructs a RequestContext resolving the client IP
// address through the provided resolver. A nil resolver behaves like the default one.
func NewRequestContext(req *authv3.CheckRequest, resolver *ClientIPResolver) *RequestContext {
	authority := requestAuthority(req)
	ipAddress, ipSource := resolver.Resolve(req)

	return &RequestContext{
		Request:    req,
		ReceivedAt: time.Now(),
		Authority:  authority,
		IpAddress:  ipAddress,
		IpSource:   ipSource,
		logFields: []zap.Field{
			zap.String("authority", authority),
			zap.String("ip", ipAddress.String()),
			zap.String("ip_source", ipSource),
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
		if f.Key == "ip" || f.Key == "ip_source" || f.Key == "authority" {
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
				authority = strings.ToLower(v)
				break
			}
		}
	}

	if authority == "" {
		return "-"
	}

	return authority
}
