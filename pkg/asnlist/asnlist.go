package asnlist

import (
	"fmt"
	"strconv"
	"strings"
)

// AS represents an autonomous system number optionally annotated with a comment.
type AS struct {
	Number  uint
	Comment string
}

// SynthesisResult carries the outcome of deduplicating AS numbers.
type SynthesisResult struct {
	NewList        []AS
	RemovedEntries []AS
}

// Parse converts a textual AS list into structured entries. Invalid lines are ignored.
func Parse(text string) []AS {
	var result []AS
	var currentComment string

	for rawLine := range strings.SplitSeq(text, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			currentComment = ""
			continue
		}
		if after, ok := strings.CutPrefix(line, "#"); ok {
			currentComment = strings.TrimSpace(after)
			continue
		}
		if number, ok := parseASNumber(line); ok {
			result = append(result, AS{Number: number, Comment: currentComment})
		}
	}

	return result
}

// Format converts an AS slice back to the textual representation used by Parse.
func Format(list []AS) string {
	if len(list) == 0 {
		return ""
	}

	lines := make([]string, 0, len(list)*2)
	lastComment := ""

	addBlankLine := func() {
		if len(lines) > 0 && lines[len(lines)-1] != "" {
			lines = append(lines, "")
		}
	}

	for _, entry := range list {
		comment := strings.TrimSpace(entry.Comment)
		if comment != "" {
			if comment != lastComment {
				addBlankLine()
				lines = append(lines, "# "+comment)
				lastComment = comment
			}
		} else if lastComment != "" {
			addBlankLine()
			lastComment = ""
		}
		lines = append(lines, fmt.Sprintf("AS %d", entry.Number))
	}

	return strings.Join(lines, "\n")
}

// Synthesize removes duplicate AS numbers, keeping the first occurrence.
func Synthesize(list []AS) SynthesisResult {
	seen := make(map[uint]struct{}, len(list))
	keep := make([]bool, len(list))

	for i, entry := range list {
		if _, exists := seen[entry.Number]; exists {
			keep[i] = false
			continue
		}
		seen[entry.Number] = struct{}{}
		keep[i] = true
	}

	var newList, removed []AS
	for i, entry := range list {
		if keep[i] {
			newList = append(newList, entry)
		} else {
			removed = append(removed, entry)
		}
	}

	return SynthesisResult{NewList: newList, RemovedEntries: removed}
}

// FindContaining returns the first AS in the list whose number matches the provided value.
func FindContaining(list []AS, value string) *AS {
	number, ok := parseASNumber(value)
	if !ok {
		return nil
	}
	for i := range list {
		if list[i].Number == number {
			return &list[i]
		}
	}
	return nil
}

// parseASNumber normalizes various AS textual formats (e.g., "AS123" or "123")
// and returns the numeric value along with a success flag.
func parseASNumber(line string) (uint, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return 0, false
	}
	if len(line) >= 2 && (line[0] == 'A' || line[0] == 'a') && (line[1] == 'S' || line[1] == 's') {
		line = strings.TrimSpace(line[2:])
	}
	if line == "" {
		return 0, false
	}
	number, err := strconv.ParseUint(line, 10, 32)
	if err != nil {
		return 0, false
	}
	return uint(number), true
}
