package version

import (
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
)

func TestBuildPrefersStampedValues(t *testing.T) {
	bi := &debug.BuildInfo{
		Main: debug.Module{Version: "v9.9.9"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "deadbeef"},
			{Key: "vcs.time", Value: "2020-01-01T00:00:00Z"},
			{Key: "vcs.modified", Value: "true"},
		},
	}
	info := build("1.5.0", "abc1234", "2026-09-23T10:00:00Z", bi)
	if info.Version != "1.5.0" || info.Commit != "abc1234" || info.BuildDate != "2026-09-23T10:00:00Z" {
		t.Fatalf("stamped values must win, got %+v", info)
	}
	if info.GoVersion != runtime.Version() || info.Platform != runtime.GOOS+"/"+runtime.GOARCH {
		t.Fatalf("unexpected toolchain fields %+v", info)
	}
}

func TestBuildFallsBackToBuildInfo(t *testing.T) {
	bi := &debug.BuildInfo{
		Main: debug.Module{Version: "v1.4.4"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "deadbeef"},
			{Key: "vcs.time", Value: "2020-01-01T00:00:00Z"},
			{Key: "vcs.modified", Value: "true"},
		},
	}
	info := build("", "", "", bi)
	if info.Version != "1.4.4" {
		t.Fatalf("expected module version without the v prefix, got %q", info.Version)
	}
	if info.Commit != "deadbeef-dirty" {
		t.Fatalf("expected the VCS revision marked dirty, got %q", info.Commit)
	}
	if info.BuildDate != "2020-01-01T00:00:00Z" {
		t.Fatalf("expected the VCS time, got %q", info.BuildDate)
	}
}

func TestBuildDevelModuleVersionIsDev(t *testing.T) {
	bi := &debug.BuildInfo{
		Main:     debug.Module{Version: "(devel)"},
		Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "deadbeef"}, {Key: "vcs.modified", Value: "false"}},
	}
	info := build("", "", "", bi)
	if info.Version != "dev" || info.Commit != "deadbeef" || info.BuildDate != unknown {
		t.Fatalf("unexpected fallback %+v", info)
	}
}

func TestBuildPseudoVersionIsDevWithShortRevision(t *testing.T) {
	bi := &debug.BuildInfo{
		Main: debug.Module{Version: "v1.4.5-0.20260923125316-1b2258e30071+dirty"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "1b2258e30071c92da082389915bfe3682e2d1af4"},
			{Key: "vcs.modified", Value: "true"},
		},
	}
	info := build("", "", "", bi)
	if info.Version != "dev" {
		t.Fatalf("a pseudo-version must be reported as dev, got %q", info.Version)
	}
	if info.Commit != "1b2258e30071-dirty" {
		t.Fatalf("expected the revision shortened to 12 characters and marked dirty, got %q", info.Commit)
	}
}

func TestReleaseVersionPattern(t *testing.T) {
	for v, want := range map[string]bool{
		"v1.4.4": true, "v2.0.0-rc.1": true, "v1.0.0-beta": true,
		"(devel)": false, "": false, "v1.4.5-0.20260923125316-1b2258e30071": false,
		"v1.4.5-0.20260923125316-1b2258e30071+dirty": false, "v1.4.4+incompatible": false, "1.4.4": false,
	} {
		if got := releaseVersion.MatchString(v); got != want {
			t.Errorf("releaseVersion(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestBuildWithoutAnyInformation(t *testing.T) {
	info := build("", "", "", nil)
	if info.Version != "dev" || info.Commit != unknown || info.BuildDate != unknown {
		t.Fatalf("unexpected defaults %+v", info)
	}
	s := info.String()
	for _, want := range []string{"dev (commit unknown, built unknown, ", runtime.Version(), runtime.GOOS + "/" + runtime.GOARCH} {
		if !strings.Contains(s, want) {
			t.Fatalf("String() = %q, missing %q", s, want)
		}
	}
}

func TestGetDoesNotPanic(t *testing.T) {
	if got := Get(); got.Version == "" || got.GoVersion == "" {
		t.Fatalf("unexpected Info %+v", got)
	}
}
