package config

import (
	"os"
	"strings"
	"testing"
)

func loadYAML(t *testing.T, body string) (*Config, error) {
	t.Helper()
	tmpFile := createTempFile(t, "server:\n  address: \":9001\"\nmetrics:\n  address: \":9090\"\n"+body)
	defer os.Remove(tmpFile)
	return Load(tmpFile)
}

func TestClientIPDefaults(t *testing.T) {
	cfg, err := loadYAML(t, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.ClientIP.Sources) != 1 || !cfg.ClientIP.Sources[0].EnvoySource {
		t.Fatalf("expected default [envoySource], got %+v", cfg.ClientIP.Sources)
	}
	if cfg.ClientIP.RequireValid {
		t.Fatalf("requireValid must default to false")
	}
	if got := cfg.ClientIP.Sources[0].String(); got != "envoySource" {
		t.Fatalf("unexpected String(): %q", got)
	}
}

func TestClientIPSourcesParsing(t *testing.T) {
	cfg, err := loadYAML(t, `
clientIp:
  requireValid: true
  sources:
    - header: X-Envoy-External-Address
    - xff:
        trustedHops: 2
    - xff:
    - envoySource
`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.ClientIP.RequireValid {
		t.Fatalf("expected requireValid true")
	}
	src := cfg.ClientIP.Sources
	if len(src) != 4 {
		t.Fatalf("expected 4 sources, got %d", len(src))
	}
	if src[0].Header != "x-envoy-external-address" || src[0].EnvoySource || src[0].XFF != nil {
		t.Fatalf("unexpected header source (name must be lower-cased): %+v", src[0])
	}
	if src[1].XFF == nil || src[1].XFF.TrustedHops != 2 {
		t.Fatalf("unexpected xff source: %+v", src[1])
	}
	if src[2].XFF == nil || src[2].XFF.TrustedHops != 0 {
		t.Fatalf("'xff:' without settings should default trustedHops to 0: %+v", src[2])
	}
	if !src[3].EnvoySource {
		t.Fatalf("expected envoySource: %+v", src[3])
	}
	want := []string{"header:x-envoy-external-address", "xff:trustedHops=2", "xff:trustedHops=0", "envoySource"}
	for i, s := range src {
		if s.String() != want[i] {
			t.Fatalf("source %d: expected %q, got %q", i, want[i], s.String())
		}
	}
}

func TestClientIPSourcesRejectInvalid(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "unknown scalar",
			yaml: "clientIp:\n  sources:\n    - remoteAddress\n",
			want: `unknown clientIp source "remoteAddress"`,
		},
		{
			name: "bare xff scalar",
			yaml: "clientIp:\n  sources:\n    - xff\n",
			want: `unknown clientIp source "xff"`,
		},
		{
			name: "unknown mapping key",
			yaml: "clientIp:\n  sources:\n    - forwarded: true\n",
			want: `unknown clientIp source "forwarded"`,
		},
		{
			name: "two keys in one mapping",
			yaml: "clientIp:\n  sources:\n    - header: x-real-ip\n      xff: {}\n",
			want: "exactly one key",
		},
		{
			name: "sequence instead of source",
			yaml: "clientIp:\n  sources:\n    - [envoySource]\n",
			want: "must be the scalar",
		},
		{
			name: "empty header name",
			yaml: "clientIp:\n  sources:\n    - header: \"\"\n",
			want: "must define exactly one source",
		},
		{
			name: "header name with spaces",
			yaml: "clientIp:\n  sources:\n    - header: \"x real ip\"\n",
			want: "is not a valid header name",
		},
		{
			name: "x-forwarded-for as header source",
			yaml: "clientIp:\n  sources:\n    - header: X-Forwarded-For\n",
			want: "use the 'xff' source",
		},
		{
			name: "negative trusted hops",
			yaml: "clientIp:\n  sources:\n    - xff:\n        trustedHops: -1\n",
			want: "trustedHops' must be >= 0",
		},
		{
			name: "non-numeric trusted hops",
			yaml: "clientIp:\n  sources:\n    - xff:\n        trustedHops: many\n",
			want: "settings are invalid",
		},
		{
			name: "duplicate source",
			yaml: "clientIp:\n  sources:\n    - envoySource\n    - header: x-real-ip\n    - envoySource\n",
			want: "duplicate source envoySource",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := loadYAML(t, tt.yaml)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestClientIPConfigValidateProgrammatic(t *testing.T) {
	// Struct literals bypass UnmarshalYAML, so validate() must catch malformed sources too.
	bad := ClientIPConfig{Sources: []ClientIPSource{{EnvoySource: true, Header: "x-real-ip"}}}
	if err := bad.validate(); err == nil || !strings.Contains(err.Error(), "exactly one source") {
		t.Fatalf("expected exactly-one-source error, got %v", err)
	}
	empty := ClientIPConfig{Sources: []ClientIPSource{{}}}
	if err := empty.validate(); err == nil {
		t.Fatalf("expected error for empty source")
	}
	if (ClientIPSource{}).String() != "invalid" {
		t.Fatalf("empty source should render as invalid")
	}
	ok := ClientIPConfig{Sources: DefaultClientIPSources()}
	if err := ok.validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
