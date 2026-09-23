package config

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

// envReferencePattern matches "${NAME}", "${NAME:-default}" and the escape "$${".
var envReferencePattern = regexp.MustCompile(`\$\$\{|\$\{([A-Za-z_][A-Za-z0-9_]*)(:-([^}]*))?\}`)

// ExpandEnv replaces "${NAME}" references in a configuration document with the value of the
// environment variable NAME, as returned by lookup. "${NAME:-default}" uses default when the
// variable is unset or empty. "$${" produces a literal "${". Any other "$" is left untouched,
// so "$1" placeholders in SQL queries are unaffected. Referencing an unset variable without a
// default is an error.
func ExpandEnv(data []byte, lookup func(string) (string, bool)) ([]byte, error) {
	if lookup == nil {
		lookup = os.LookupEnv
	}

	missing := map[string]struct{}{}
	expanded := envReferencePattern.ReplaceAllFunc(data, func(match []byte) []byte {
		if string(match) == "$${" {
			return []byte("${")
		}
		groups := envReferencePattern.FindSubmatch(match)
		name := string(groups[1])
		hasDefault := len(groups[2]) > 0
		value, ok := lookup(name)
		if (!ok || value == "") && hasDefault {
			return groups[3]
		}
		if !ok {
			missing[name] = struct{}{}
			return match
		}
		return []byte(value)
	})

	if len(missing) > 0 {
		names := make([]string, 0, len(missing))
		for name := range missing {
			names = append(names, name)
		}
		sort.Strings(names)
		return nil, fmt.Errorf("the configuration references environment variables that are not set: %s (use ${NAME:-default} to provide a fallback)", strings.Join(names, ", "))
	}
	return expanded, nil
}
