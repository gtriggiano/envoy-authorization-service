package config

import (
	"fmt"
	"time"

	"go.yaml.in/yaml/v3"
)

// Duration is a time.Duration that is parsed from its Go string form ("500ms", "10m", "1h30m")
// when it appears in YAML. Parsing happens once, at load time, so an invalid value is a
// configuration error rather than a silent fallback.
type Duration time.Duration

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode {
		return fmt.Errorf("a duration must be a string such as \"500ms\", \"10m\" or \"1h30m\"")
	}
	parsed, err := time.ParseDuration(node.Value)
	if err != nil {
		return fmt.Errorf("invalid duration %q (expected a value such as \"500ms\", \"10m\" or \"1h30m\")", node.Value)
	}
	*d = Duration(parsed)
	return nil
}

// MarshalYAML implements yaml.Marshaler so a Duration round-trips as its string form.
func (d Duration) MarshalYAML() (any, error) {
	return time.Duration(d).String(), nil
}

// Std returns the value as a time.Duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

// String returns the Go string form of the duration.
func (d Duration) String() string { return time.Duration(d).String() }

// Or returns the duration when set, the fallback otherwise. It is meant for optional
// *Duration fields whose nil value means "use the default".
func (d *Duration) Or(fallback time.Duration) time.Duration {
	if d == nil {
		return fallback
	}
	return time.Duration(*d)
}

// validatePositive returns an error mentioning name when an optional duration is set to a
// non-positive value.
func (d *Duration) validatePositive(name string) error {
	if d != nil && *d <= 0 {
		return fmt.Errorf("configuration '%s' must be greater than 0, got %s", name, d.String())
	}
	return nil
}
