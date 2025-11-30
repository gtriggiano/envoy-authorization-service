package policy

import (
	"strings"
	"testing"
)

// TestParseValidation exercises Parse edge cases and validation errors.
func TestParseValidation(t *testing.T) {
	t.Run("empty expression yields nil policy", func(t *testing.T) {
		p, err := Parse("   ", []string{"a"})
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if p != nil {
			t.Fatalf("expected nil policy, got %#v", p)
		}
	})

	t.Run("valid expression with punctuation identifiers", func(t *testing.T) {
		p, err := Parse("ldap-membership && (ip.whitelist || !v2_client)", []string{"ldap-membership", "ip.whitelist", "v2_client"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if p == nil {
			t.Fatal("expected non-nil policy")
		}
	})

	t.Run("unknown controller produces validation error", func(t *testing.T) {
		_, err := Parse("foo && bar", []string{"foo"})
		if err == nil || !strings.Contains(err.Error(), "authorization policy references an unknown controller: bar") {
			t.Fatalf("expected authorization policy references an unknown controller: bar, got %v", err)
		}
	})

	t.Run("syntax error reported with position", func(t *testing.T) {
		_, err := Parse("(foo && bar", []string{"foo", "bar"})
		if err == nil || !strings.Contains(err.Error(), "expected )") {
			t.Fatalf("expected syntax error, got %v", err)
		}
	})
}

// TestPolicyEvaluate ensures Evaluate returns expected boolean decisions and causes.
func TestPolicyEvaluate(t *testing.T) {
	p, err := Parse("a && (!b || c)", []string{"a", "b", "c"})
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	tests := []struct {
		name      string
		values    map[string]bool
		wantAllow bool
		wantCause string
	}{
		{
			name:      "all true",
			values:    map[string]bool{"a": true, "b": false, "c": true},
			wantAllow: true,
			wantCause: "",
		},
		{
			name:      "left clause false",
			values:    map[string]bool{"a": false, "b": true, "c": true},
			wantAllow: false,
			wantCause: "a",
		},
		{
			name:      "right nested clause true via c",
			values:    map[string]bool{"a": true, "b": true, "c": true},
			wantAllow: true,
			wantCause: "",
		},
		{
			name:      "right nested clause false via c",
			values:    map[string]bool{"a": true, "b": true, "c": false},
			wantAllow: false,
			wantCause: "c",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAllow, gotCause := p.Evaluate(tt.values)
			if gotAllow != tt.wantAllow {
				t.Fatalf("expected allow=%v, got %v", tt.wantAllow, gotAllow)
			}
			if gotCause != tt.wantCause {
				t.Fatalf("expected cause %q, got %q", tt.wantCause, gotCause)
			}
		})
	}

	t.Run("nil policy allows everything", func(t *testing.T) {
		allow, cause := (*Policy)(nil).Evaluate(map[string]bool{"a": false})
		if !allow || cause != "" {
			t.Fatalf("expected allow=true for nil policy, got allow=%v cause=%q", allow, cause)
		}
	})

	t.Run("negation surfaces underlying controller", func(t *testing.T) {
		notPolicy, err := Parse("!b", []string{"b"})
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		allow, cause := notPolicy.Evaluate(map[string]bool{"b": true})
		if allow {
			t.Fatalf("expected denial when !b with b=true")
		}
		if cause != "b" {
			t.Fatalf("expected cause b, got %q", cause)
		}
	})
}

// TestPolicyShortCircuiting confirms the AST honors AND/OR short-circuit semantics.
func TestPolicyShortCircuiting(t *testing.T) {
	t.Run("AND short-circuits on false left operand", func(t *testing.T) {
		// Expression: a && b
		// If 'a' is false, 'b' should never be evaluated
		p, err := Parse("a && b", []string{"a", "b"})
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}

		// Only provide 'a' (false); 'b' is intentionally missing
		// If short-circuiting works, the missing 'b' won't cause issues
		values := map[string]bool{"a": false}
		allow, cause := p.Evaluate(values)

		if allow {
			t.Fatalf("expected denial when a=false in 'a && b'")
		}
		if cause != "a" {
			t.Fatalf("expected cause 'a', got %q", cause)
		}
	})

	t.Run("OR short-circuits on true left operand", func(t *testing.T) {
		// Expression: a || b
		// If 'a' is true, 'b' should never be evaluated
		p, err := Parse("a || b", []string{"a", "b"})
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}

		// Only provide 'a' (true); 'b' is intentionally missing
		// If short-circuiting works, the missing 'b' won't cause issues
		values := map[string]bool{"a": true}
		allow, cause := p.Evaluate(values)

		if !allow {
			t.Fatalf("expected allow when a=true in 'a || b'")
		}
		if cause != "" {
			t.Fatalf("expected empty cause, got %q", cause)
		}
	})

	t.Run("nested short-circuiting in complex expression", func(t *testing.T) {
		// Expression: (a && b) || c
		// If 'a' is false, 'b' won't be evaluated
		// Then 'c' will be evaluated for the OR
		p, err := Parse("(a && b) || c", []string{"a", "b", "c"})
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}

		// Provide 'a' (false) and 'c' (true), but omit 'b'
		// 'b' should not be evaluated due to short-circuiting in 'a && b'
		values := map[string]bool{"a": false, "c": true}
		allow, cause := p.Evaluate(values)

		if !allow {
			t.Fatalf("expected allow when c=true in '(a && b) || c'")
		}
		if cause != "" {
			t.Fatalf("expected empty cause, got %q", cause)
		}
	})

	t.Run("AND does not short-circuit when left is true", func(t *testing.T) {
		// Expression: a && b
		// If 'a' is true, 'b' must be evaluated
		p, err := Parse("a && b", []string{"a", "b"})
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}

		// Provide both values
		values := map[string]bool{"a": true, "b": false}
		allow, cause := p.Evaluate(values)

		if allow {
			t.Fatalf("expected denial when b=false in 'a && b'")
		}
		if cause != "b" {
			t.Fatalf("expected cause 'b', got %q", cause)
		}
	})

	t.Run("OR does not short-circuit when left is false", func(t *testing.T) {
		// Expression: a || b
		// If 'a' is false, 'b' must be evaluated
		p, err := Parse("a || b", []string{"a", "b"})
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}

		// Provide both values
		values := map[string]bool{"a": false, "b": true}
		allow, cause := p.Evaluate(values)

		if !allow {
			t.Fatalf("expected allow when b=true in 'a || b'")
		}
		if cause != "" {
			t.Fatalf("expected empty cause, got %q", cause)
		}
	})

	t.Run("deeply nested short-circuiting", func(t *testing.T) {
		// Expression: a && (b || (c && d))
		// If 'a' is false, nothing else should be evaluated
		p, err := Parse("a && (b || (c && d))", []string{"a", "b", "c", "d"})
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}

		// Only provide 'a' (false); all others are missing
		values := map[string]bool{"a": false}
		allow, cause := p.Evaluate(values)

		if allow {
			t.Fatalf("expected denial when a=false")
		}
		if cause != "a" {
			t.Fatalf("expected cause 'a', got %q", cause)
		}
	})
}
