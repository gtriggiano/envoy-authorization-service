// Package version exposes the build identity of the running binary.
//
// Version, Commit and BuildDate are meant to be stamped at link time:
//
//	go build -ldflags "-X github.com/gtriggiano/envoy-authorization-service/pkg/version.Version=1.5.0 \
//	                   -X github.com/gtriggiano/envoy-authorization-service/pkg/version.Commit=abc1234 \
//	                   -X github.com/gtriggiano/envoy-authorization-service/pkg/version.BuildDate=2026-09-23T10:00:00Z"
//
// When a value is not stamped, the package falls back to the information the Go
// toolchain embeds in the binary (release module version and VCS metadata), so a plain
// `go build` inside the repository still reports the commit, as "dev" version.
package version

import (
	"fmt"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
)

// Set at link time via -ldflags "-X ...". Left empty when not stamped.
var (
	Version   string
	Commit    string
	BuildDate string
)

// unknown is reported for fields that neither the linker nor the toolchain could fill.
const unknown = "unknown"

// releaseVersion matches a module version that names a release ("v1.4.4", "v2.0.0-rc.1"),
// as opposed to "(devel)" or a pseudo-version such as "v1.4.5-0.20260923125316-1b2258e30071+dirty".
var releaseVersion = regexp.MustCompile(`^v\d+\.\d+\.\d+(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?$`)

// shortRevisionLen is the length Go itself uses for revisions in pseudo-versions.
const shortRevisionLen = 12

// Info describes the running binary.
type Info struct {
	// Version is the release version (for example "1.5.0"), "dev" for unreleased builds.
	Version string
	// Commit is the VCS revision the binary was built from, with a "-dirty" suffix when
	// the working tree had uncommitted changes.
	Commit string
	// BuildDate is the build (or commit) time in RFC 3339 format.
	BuildDate string
	// GoVersion is the Go toolchain that compiled the binary.
	GoVersion string
	// Platform is the target operating system and architecture, as "os/arch".
	Platform string
}

// Get returns the build identity, combining link-time values with the toolchain's
// embedded build information for anything that was not stamped.
func Get() Info {
	bi, _ := debug.ReadBuildInfo()
	return build(Version, Commit, BuildDate, bi)
}

// build assembles an Info from stamped values and optional toolchain build info.
func build(version, commit, buildDate string, bi *debug.BuildInfo) Info {
	info := Info{
		Version:   version,
		Commit:    commit,
		BuildDate: buildDate,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}

	if bi != nil {
		// Only `go install module@vX.Y.Z` yields a release version here; a build inside
		// the repository yields "(devel)" or a pseudo-version, which is reported as "dev".
		if info.Version == "" && releaseVersion.MatchString(bi.Main.Version) {
			info.Version = strings.TrimPrefix(bi.Main.Version, "v")
		}
		var revision, vcsTime string
		modified := false
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				revision = s.Value
			case "vcs.time":
				vcsTime = s.Value
			case "vcs.modified":
				modified = s.Value == "true"
			}
		}
		if info.Commit == "" && revision != "" {
			info.Commit = revision
			if len(info.Commit) > shortRevisionLen {
				info.Commit = info.Commit[:shortRevisionLen]
			}
			if modified {
				info.Commit += "-dirty"
			}
		}
		if info.BuildDate == "" && vcsTime != "" {
			info.BuildDate = vcsTime
		}
	}

	if info.Version == "" {
		info.Version = "dev"
	}
	if info.Commit == "" {
		info.Commit = unknown
	}
	if info.BuildDate == "" {
		info.BuildDate = unknown
	}
	return info
}

// String renders the identity on one line, for example
// "1.5.0 (commit abc1234, built 2026-09-23T10:00:00Z, go1.27.0, linux/amd64)".
func (i Info) String() string {
	return fmt.Sprintf("%s (commit %s, built %s, %s, %s)", i.Version, i.Commit, i.BuildDate, i.GoVersion, i.Platform)
}
