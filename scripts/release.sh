#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION_FILE="${VERSION_FILE:-${ROOT_DIR}/VERSION}"
BUMP_KIND="${1:-auto}"
TAG_PREFIX="v"

cd "$ROOT_DIR"

require_clean_worktree() {
	if [ -n "$(git status --porcelain)" ]; then
		echo "Working tree is not clean. Please commit or stash your changes before releasing." >&2
		exit 1
	fi
}

ensure_git_chglog() {
	if ! command -v git-chglog >/dev/null 2>&1; then
		cat >&2 <<'EOF'
git-chglog is required to generate the changelog.
Install it with: go install github.com/git-chglog/git-chglog/cmd/git-chglog@latest
EOF
		exit 1
	fi
}

current_version() {
	local last_tag
	last_tag="$(git describe --tags --abbrev=0 --match "${TAG_PREFIX}[0-9]*" 2>/dev/null || true)"
	if [ -z "$last_tag" ]; then
		echo "0.0.0"
	else
		echo "${last_tag#${TAG_PREFIX}}"
	fi
}

recommended_bump() {
	local base_tag commits
	base_tag="$(git describe --tags --abbrev=0 --match "${TAG_PREFIX}[0-9]*" 2>/dev/null || true)"

	if [ -z "$base_tag" ]; then
		commits="$(git log --no-merges --format='%s%n%b')"
	else
		commits="$(git log --no-merges --format='%s%n%b' "${base_tag}..HEAD")"
	fi

	if [ -z "$commits" ]; then
		echo "No commits to release." >&2
		exit 1
	fi

	if echo "$commits" | grep -Eiq 'BREAKING CHANGE'; then
		echo "major"
	elif echo "$commits" | grep -Eiq '^.+!:'; then
		echo "major"
	elif echo "$commits" | grep -Eiq '^feat(\(.+\))?:'; then
		echo "minor"
	else
		echo "patch"
	fi
}

next_version() {
	local current bump major minor patch
	current="$1"
	bump="$2"

	if ! [[ "$current" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
		echo "Invalid current version: $current" >&2
		exit 1
	fi

	IFS='.' read -r major minor patch <<< "$current"

	case "$bump" in
		major)
			major=$((major + 1))
			minor=0
			patch=0
			;;
		minor)
			minor=$((minor + 1))
			patch=0
			;;
		patch)
			patch=$((patch + 1))
			;;
		*)
			echo "Unknown bump kind: $bump" >&2
			exit 1
			;;
	esac

	printf "%s.%s.%s" "$major" "$minor" "$patch"
}

main() {
	require_clean_worktree
	ensure_git_chglog

	local bump current new_version tag

	if [ "$BUMP_KIND" = "auto" ]; then
		bump="$(recommended_bump)"
	else
		bump="$BUMP_KIND"
	fi

	current="$(current_version)"
	new_version="$(next_version "$current" "$bump")"
	tag="${TAG_PREFIX}${new_version}"

	echo "Bumping version: ${current} -> ${new_version} (${bump})"
	echo "$new_version" > "$VERSION_FILE"

	git-chglog --next-tag "$tag" -o CHANGELOG.md

	git add "$VERSION_FILE" CHANGELOG.md
	git commit -m "chore(release): $tag"
	git tag "$tag"

	echo "Release ready. Push the commit and tag when you're ready:"
	echo "  git push origin main && git push origin $tag"
}

main "$@"
