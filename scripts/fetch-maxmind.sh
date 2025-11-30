#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="$ROOT_DIR/config"
TMP_DIR="$OUT_DIR/.maxmind-tmp"

FORCE_DOWNLOAD="${FORCE_DOWNLOAD:-0}"
FRESH_DAYS="${FRESH_DAYS:-14}"

EDITION_IDS=(GeoLite2-ASN GeoLite2-City)

mkdir -p "$OUT_DIR" "$TMP_DIR"

is_fresh() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    return 1
  fi
  # Fresh if modified within the last N days
  find "$file" -mtime -"${FRESH_DAYS}" -print -quit >/dev/null
}

download_and_extract() {
  local edition="$1"
  local url="https://github.com/P3TERX/GeoLite.mmdb/raw/download/${edition}.mmdb"
  echo "→ Fetching ${edition} from ${url}"
  curl -fsSL "$url" -o "$OUT_DIR/${edition}.mmdb"
  echo "Saved to config/${edition}.mmdb"
  echo
}

for edition in "${EDITION_IDS[@]}"; do
  target="$OUT_DIR/${edition}.mmdb"
  if [[ "$FORCE_DOWNLOAD" != "0" ]] || ! is_fresh "$target"; then
    download_and_extract "$edition"
  else
    echo "Skipping $edition (fresh file exists at $target)"
  fi
done

rm -rf "$TMP_DIR"
echo "Done."
