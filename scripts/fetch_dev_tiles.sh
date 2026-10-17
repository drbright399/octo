#!/usr/bin/env bash
# fetch_dev_tiles.sh — extract a regional PMTiles slice from Protomaps'
# daily planet build, into OCTO's tiles directory.
#
# Per docs/adrs/0001-fleet-map-basemap.md the basemap is self-hosted to
# keep customer buoy lat/lng off third-party tile CDNs. Protomaps now
# only publishes the planet-wide daily build (~135GB), so we use the
# `pmtiles` (go-pmtiles) CLI to HTTP-range-extract just the region we
# need — actual bytes downloaded ≈ the size of the regional output,
# NOT the planet.
#
# Usage:
#   ./scripts/fetch_dev_tiles.sh                   # → us.pmtiles, zoom 0-10
#   ./scripts/fetch_dev_tiles.sh --region california
#   ./scripts/fetch_dev_tiles.sh --build-date 20260518
#   ./scripts/fetch_dev_tiles.sh --maxzoom 12       # finer detail, bigger file
#
# Predefined regions (bbox = MIN_LON,MIN_LAT,MAX_LON,MAX_LAT):
#   us           -125,24,-66,50      (continental US)
#   california   -124.5,32.5,-114,42
#   conus-north  -125,40,-66,50
#
# Refuses to clobber an existing file unless --force is passed.

set -euo pipefail

REGION="us"
MAXZOOM=10
FORCE=0
BUILD_DATE=""           # YYYYMMDD; default = today (UTC)

while [[ $# -gt 0 ]]; do
  case "$1" in
    --region)     REGION="$2"; shift 2 ;;
    --maxzoom)    MAXZOOM="$2"; shift 2 ;;
    --build-date) BUILD_DATE="$2"; shift 2 ;;
    --force)      FORCE=1; shift ;;
    -h|--help)    sed -n '2,28p' "$0"; exit 0 ;;
    *)            echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

# Region → bbox lookup. Add more as needed.
case "$REGION" in
  us)          BBOX="-125,24,-66,50" ;;
  california)  BBOX="-124.5,32.5,-114,42" ;;
  conus-north) BBOX="-125,40,-66,50" ;;
  *)
    echo "error: unknown region '$REGION' — add a bbox case to this script" >&2
    exit 2
    ;;
esac

DATA_ROOT="${OCTO_DATA_ROOT:-$HOME/.octo-dev/data}"
TILES_DIR="$DATA_ROOT/tiles"
TARGET="$TILES_DIR/${REGION}.pmtiles"

mkdir -p "$TILES_DIR"

if [[ -f "$TARGET" && "$FORCE" -ne 1 ]]; then
  size=$(stat -c%s "$TARGET" 2>/dev/null || stat -f%z "$TARGET" 2>/dev/null || echo "?")
  echo "==> $TARGET already exists (${size} bytes)"
  echo "    pass --force to overwrite"
  exit 0
fi

# Ensure the go-pmtiles CLI is available. Install to ./scripts/.bin
# alongside this script — keeps the binary out of $HOME's bin path
# and avoids the user having to manage it.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PMTILES_BIN="$SCRIPT_DIR/.bin/pmtiles"

if [[ ! -x "$PMTILES_BIN" ]]; then
  mkdir -p "$SCRIPT_DIR/.bin"
  echo "==> Installing go-pmtiles binary to $PMTILES_BIN"
  # Detect arch/os.
  os=$(uname -s | tr '[:upper:]' '[:lower:]')
  arch=$(uname -m)
  case "$arch" in
    x86_64)  arch="x86_64" ;;
    aarch64|arm64) arch="arm64" ;;
    *)
      echo "error: unsupported arch '$arch' — install go-pmtiles manually from" >&2
      echo "       https://github.com/protomaps/go-pmtiles/releases" >&2
      exit 2
      ;;
  esac
  case "$os" in
    linux|darwin) ;;
    *)
      echo "error: unsupported os '$os' — install go-pmtiles manually" >&2
      exit 2
      ;;
  esac
  # Use the API to find the latest release rather than hardcoding a version.
  # NOTE: we capture curl's output to a variable BEFORE piping through grep —
  # using `curl | grep -m1` with `set -o pipefail` causes curl to fail with
  # exit code 23 when grep closes the pipe early after its first match.
  echo "    Detecting latest go-pmtiles release..."
  API_JSON=$(curl -sSL --fail "https://api.github.com/repos/protomaps/go-pmtiles/releases/latest")
  VERSION=$(printf '%s\n' "$API_JSON" | grep -m1 '"tag_name"' | sed 's/.*"v\?\([^"]*\)".*/\1/' | tr -d 'v')
  if [[ -z "$VERSION" ]]; then
    echo "error: could not resolve latest go-pmtiles version" >&2
    exit 2
  fi
  echo "    Latest: v${VERSION}"
  TARBALL_URL="https://github.com/protomaps/go-pmtiles/releases/download/v${VERSION}/go-pmtiles_${VERSION}_${os}_${arch}.tar.gz"
  echo "    Fetching $TARBALL_URL"
  tmpdir=$(mktemp -d)
  curl -sSL --fail -o "$tmpdir/pmtiles.tar.gz" "$TARBALL_URL"
  tar -xzf "$tmpdir/pmtiles.tar.gz" -C "$tmpdir" pmtiles
  mv "$tmpdir/pmtiles" "$PMTILES_BIN"
  chmod 0755 "$PMTILES_BIN"
  rm -rf "$tmpdir"
  echo "    Installed $("$PMTILES_BIN" version 2>&1 | head -1)"
fi

# Pick today's Protomaps build by default (UTC). Fall back to yesterday's
# if today's isn't published yet (their build typically lands by ~04:00 UTC).
if [[ -z "$BUILD_DATE" ]]; then
  BUILD_DATE=$(date -u +%Y%m%d)
fi

SOURCE_URL="https://build.protomaps.com/${BUILD_DATE}.pmtiles"

# Probe the source — fall back to yesterday if today's not there yet.
if ! curl -sI --fail "$SOURCE_URL" >/dev/null 2>&1; then
  YESTERDAY=$(date -u -d "yesterday" +%Y%m%d 2>/dev/null || date -u -v-1d +%Y%m%d)
  SOURCE_URL_Y="https://build.protomaps.com/${YESTERDAY}.pmtiles"
  echo "==> Today's build ($BUILD_DATE) not yet available, falling back to $YESTERDAY"
  if ! curl -sI --fail "$SOURCE_URL_Y" >/dev/null 2>&1; then
    echo "error: neither $BUILD_DATE nor $YESTERDAY are available at build.protomaps.com" >&2
    echo "       pass --build-date YYYYMMDD with a known-good date" >&2
    exit 2
  fi
  SOURCE_URL="$SOURCE_URL_Y"
fi

echo "==> Extracting region '$REGION' (bbox $BBOX, maxzoom $MAXZOOM)"
echo "    from $SOURCE_URL"
echo "    into $TARGET"
echo "    (this HTTP-range-fetches only the bytes for the region —"
echo "     planet is ~135GB but extract is typically 100MB–1GB depending"
echo "     on region + maxzoom)"
echo

"$PMTILES_BIN" extract \
  "$SOURCE_URL" \
  "$TARGET.partial" \
  --bbox="$BBOX" \
  --maxzoom="$MAXZOOM"

mv "$TARGET.partial" "$TARGET"

size=$(stat -c%s "$TARGET" 2>/dev/null || stat -f%z "$TARGET" 2>/dev/null || echo "?")
echo
echo "==> Done. $TARGET (${size} bytes)"
echo
echo "Reload the Athena Console fleet view — the basemap should now"
echo "load via /api/v1/tiles/${REGION}.pmtiles."
