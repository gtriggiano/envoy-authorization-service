package config

import (
	"errors"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
)

var (
	unknownFieldPattern = regexp.MustCompile(`^(line \d+: )?field (\S+) not found in type \S+$`)
	linePrefixPattern   = regexp.MustCompile(`^line \d+: `)
)

// FormatYAMLError rewrites the messages produced by the YAML decoder into operator-facing
// wording: "field x not found in type pkg.T" becomes `unknown key "x"`. When keepLines is
// false the "line N:" prefixes are dropped, which is appropriate when the decoded document
// is not the file the operator wrote (controller settings are re-encoded before decoding).
func FormatYAMLError(err error, keepLines bool) error {
	if err == nil {
		return nil
	}
	var typeErr *yaml.TypeError
	if !errors.As(err, &typeErr) {
		return err
	}
	messages := make([]string, 0, len(typeErr.Errors))
	for _, msg := range typeErr.Errors {
		if m := unknownFieldPattern.FindStringSubmatch(msg); m != nil {
			msg = m[1] + `unknown key "` + m[2] + `"`
		}
		if !keepLines {
			msg = linePrefixPattern.ReplaceAllString(msg, "")
		}
		messages = append(messages, msg)
	}
	return errors.New(strings.Join(messages, "; "))
}
