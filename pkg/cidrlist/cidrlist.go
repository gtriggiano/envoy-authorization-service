package cidrlist

import (
	"net/netip"
	"strings"
)

// CIDR represents a CIDR entry optionally annotated with a comment.
type CIDR struct {
	Value   netip.Prefix
	Comment string
}

// SynthesisResult carries the outcome of removing redundant CIDRs from a list.
type SynthesisResult struct {
	NewList        []CIDR
	RemovedEntries []CIDR
}

// Parse converts a textual CIDR list into structured entries. Invalid lines are ignored.
func Parse(text string) []CIDR {
	var result []CIDR
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
		if prefix, ok := parsePrefix(line); ok {
			result = append(result, CIDR{Value: prefix, Comment: currentComment})
		}
	}

	return result
}

// Format converts a CIDR slice back to the textual representation used by Parse.
func Format(list []CIDR) string {
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
		lines = append(lines, entry.Value.Masked().String())
	}

	return strings.Join(lines, "\n")
}

// Synthesize removes redundant CIDRs (those already covered by another entry).
func Synthesize(list []CIDR) SynthesisResult {
	keep := make([]bool, len(list))
	for i := range keep {
		keep[i] = true
	}

	for i := range list {
		if !keep[i] {
			continue
		}
		for j := range list {
			if i == j {
				continue
			}
			a := list[i].Value.Masked()
			b := list[j].Value.Masked()
			if a == b {
				if j < i {
					keep[i] = false
					break
				}
				continue
			}
			if containsPrefix(b, a) {
				keep[i] = false
				break
			}
		}
	}

	var newList, removed []CIDR
	for i, entry := range list {
		if keep[i] {
			newList = append(newList, entry)
		} else {
			removed = append(removed, entry)
		}
	}

	return SynthesisResult{NewList: newList, RemovedEntries: removed}
}

// FindContaining returns the first CIDR in the list that contains the provided IP/CIDR string.
func FindContaining(list []CIDR, ipOrCIDR string) (*CIDR, bool) {
	prefix, ok := parsePrefix(ipOrCIDR)
	if !ok {
		return nil, false
	}

	for i := range list {
		if containsPrefix(list[i].Value, prefix) {
			return &list[i], true
		}
	}

	return nil, false
}

// parsePrefix normalizes IPv4 addresses and CIDR strings into a masked prefix.
// It reports whether parsing succeeded.
func parsePrefix(input string) (netip.Prefix, bool) {
	if input == "" {
		return netip.Prefix{}, false
	}
	if strings.Contains(input, "/") {
		prefix, err := netip.ParsePrefix(input)
		if err != nil || !prefix.Addr().Is4() {
			return netip.Prefix{}, false
		}
		return prefix.Masked(), true
	}
	addr, err := netip.ParseAddr(input)
	if err != nil || !addr.Is4() {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(addr, 32), true
}

// containsPrefix reports whether the container prefix fully encompasses the
// target prefix. Unsupported address families result in false.
func containsPrefix(container, target netip.Prefix) bool {
	container = container.Masked()
	target = target.Masked()
	if !container.Addr().Is4() || !target.Addr().Is4() {
		return false
	}
	if container.Bits() > target.Bits() {
		return false
	}
	return container.Contains(target.Addr())
}
