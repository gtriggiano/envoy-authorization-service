package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// CredentialSource is a secret given either inline (typically through a "${VAR}" environment
// reference expanded at load time) or as the path of a file whose content is the value
// (typically a Kubernetes Secret mounted as a volume). Exactly one of the two may be set.
type CredentialSource struct {
	// Value is the secret itself.
	Value string
	// File is the path of a file whose content is the value; a single trailing newline is dropped.
	File string
}

// IsSet reports whether either source is configured.
func (c CredentialSource) IsSet() bool { return c.Value != "" || c.File != "" }

// Validate ensures at most one source is configured. name is the inline key
// (e.g. "database.postgres.username"); the file key is "<name>File".
func (c CredentialSource) Validate(name string) error {
	if c.Value != "" && c.File != "" {
		return fmt.Errorf("%s and %sFile are mutually exclusive", name, name)
	}
	return nil
}

// ErrCredentialUnavailable is matched (errors.Is) by the errors Check returns when the file
// that should hold the secret does not exist. Callers validating a configuration outside of
// the deployment environment can treat it as a warning.
var ErrCredentialUnavailable = errors.New("credential source unavailable")

// credentialUnavailableError carries an operator-facing message while matching ErrCredentialUnavailable.
type credentialUnavailableError struct{ msg string }

func (e credentialUnavailableError) Error() string        { return e.msg }
func (e credentialUnavailableError) Is(target error) bool { return target == ErrCredentialUnavailable }

// Check verifies that a file-based source exists. An inline value needs no check.
func (c CredentialSource) Check(name string) error {
	if c.File != "" {
		if _, err := os.Stat(c.File); err != nil {
			return credentialUnavailableError{fmt.Sprintf("%sFile: %v", name, err)}
		}
	}
	return nil
}

// Resolve returns the secret value. It is an error when the source is not set, the file is
// missing, or the value is empty.
func (c CredentialSource) Resolve(name string) (string, error) {
	switch {
	case c.Value != "":
		return c.Value, nil
	case c.File != "":
		data, err := os.ReadFile(c.File)
		if err != nil {
			return "", fmt.Errorf("%sFile: %w", name, err)
		}
		value := strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
		if value == "" {
			return "", fmt.Errorf("%sFile: file '%s' is empty", name, c.File)
		}
		return value, nil
	default:
		return "", fmt.Errorf("%s: no credential source configured", name)
	}
}
