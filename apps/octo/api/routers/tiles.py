"""GET /api/v1/tiles/{filename} — PMTiles vector-basemap static-file
endpoint for the Fleet map (slice-9 redesign).

Per the 2026-05-19 basemap design hand-off the basemap is
self-hosted (not external CDN) so customer buoy lat/lng never leak in
tile-coordinate URL paths to a third party.

This route serves .pmtiles files from `paths.tiles_dir()`. PMTiles
clients (`pmtiles` npm package) issue HTTP range requests — first a
~16 KB header read, then per-tile range reads. So this route MUST
honor the Range request header and return 206 Partial Content with
the appropriate Content-Range header.

Auth:
  - viewer+ session required (same gate as the rest of /api/v1/*).
    Tiles themselves are non-sensitive OSM data, but ALL OCTO surfaces
    require auth as a baseline posture.

Filename validation:
  - Must end in `.pmtiles`.
  - Must be a single path segment (no `..`, no separators, no
    leading dot).
  - Lowercase alphanumerics, hyphens, and underscores only.
  - Must resolve inside `paths.tiles_dir()` — defense in depth via
    `paths.tile_path` → `paths.resolve_inside`, the one containment
    check: realpath + strictly-under-root, applied BEFORE the file is
    touched; a symlinked file is refused (the tiles directory itself
    may be a symlink to bulk storage — deployment layout).

Added 2026-05-19 — basemap handoff impl.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import AsyncIterator, Optional

from fastapi import APIRouter, Depends, Header, Path as PathParam
from fastapi.responses import Response, StreamingResponse

from apps.octo import paths
from apps.octo.api.errors import APIError
from apps.octo.api.role_gates import session_viewer_plus
from apps.octo.auth import sessions


router = APIRouter(prefix="/tiles", tags=["tiles"])

# Filename pattern: lowercase alphanumeric + hyphen + underscore + dot
# (for the file extension only). Refuses `..`, `/`, leading dot.
_FILENAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*\.pmtiles$")

# Per-chunk size when streaming a full file (used when no Range header
# is present). PMTiles range requests never hit this path in practice
# — clients always request specific byte ranges.
_STREAM_CHUNK_BYTES = 64 * 1024

# Cap range-response length at 32 MB so a malformed client request
# can't ask for the entire tile file in one Content-Range slice.
_MAX_RANGE_BYTES = 32 * 1024 * 1024


def _validate_filename(filename: str) -> str:
    # fullmatch: `$` alone would also accept a trailing newline.
    if not _FILENAME_RE.fullmatch(filename):
        raise APIError(
            "VALIDATION_FAILED",
            "filename must match [a-z0-9][a-z0-9_-]*.pmtiles",
        )
    return filename


def _resolve_tile_path(filename: str) -> Path:
    """Resolve under tiles_dir() with no symlinks + no escape — the
    containment check runs before anything touches the filesystem, and a
    name it refuses is answered exactly like a missing file (404)."""
    try:
        resolved = paths.tile_path(filename)
    except paths.SlugError:
        raise APIError("NOT_FOUND") from None
    if not resolved.is_file():
        raise APIError("NOT_FOUND")
    return resolved


def _parse_range(range_header: str, total: int) -> Optional[tuple[int, int]]:
    """Parse a `Range: bytes=<start>-<end>` header.

    Returns (start, end_inclusive) on success, or None if the header is
    malformed / not a `bytes=` range. A None return signals "ignore the
    Range, serve the full file" — same behavior as most static servers.
    """
    if not range_header.startswith("bytes="):
        return None
    spec = range_header[len("bytes="):].strip()
    # We support a single range — pmtiles clients never issue multi-range.
    if "," in spec:
        return None
    if "-" not in spec:
        return None
    start_s, end_s = spec.split("-", 1)
    start_s = start_s.strip()
    end_s = end_s.strip()
    try:
        if start_s == "":
            # Suffix range: bytes=-N → last N bytes.
            if end_s == "":
                return None
            suffix = int(end_s)
            if suffix <= 0:
                return None
            start = max(0, total - suffix)
            end = total - 1
        else:
            start = int(start_s)
            end = int(end_s) if end_s else total - 1
    except ValueError:
        return None
    if start < 0 or end < start or start >= total:
        return None
    end = min(end, total - 1)
    # Clamp the served length so a client can't ask for an absurdly
    # large slice. The PMTiles client never does — this is defense.
    if end - start + 1 > _MAX_RANGE_BYTES:
        end = start + _MAX_RANGE_BYTES - 1
    return (start, end)


async def _stream_range(path: Path, start: int, end: int) -> AsyncIterator[bytes]:
    """Yield bytes [start, end] inclusive from path in chunks."""
    remaining = end - start + 1
    with path.open("rb") as f:
        f.seek(start)
        while remaining > 0:
            chunk = f.read(min(_STREAM_CHUNK_BYTES, remaining))
            if not chunk:
                break
            remaining -= len(chunk)
            yield chunk


async def _stream_full(path: Path) -> AsyncIterator[bytes]:
    with path.open("rb") as f:
        while True:
            chunk = f.read(_STREAM_CHUNK_BYTES)
            if not chunk:
                break
            yield chunk


@router.get("/{filename}")
def get_tile(
    filename: str = PathParam(min_length=1, max_length=128),
    range_header: Optional[str] = Header(default=None, alias="Range"),
    _caller: sessions.SessionInfo = Depends(session_viewer_plus),
) -> Response:
    name = _validate_filename(filename)
    tile_path = _resolve_tile_path(name)
    total = tile_path.stat().st_size

    headers = {
        "Accept-Ranges": "bytes",
        # PMTiles content is immutable per build — clients can cache
        # aggressively. Builds get a new filename anyway.
        "Cache-Control": "public, max-age=86400, immutable",
        "Content-Type": "application/octet-stream",
    }

    if range_header is None:
        # Full file. PMTiles clients almost never request this — only
        # debug / curl flows hit this branch.
        return StreamingResponse(
            _stream_full(tile_path),
            status_code=200,
            headers={**headers, "Content-Length": str(total)},
            media_type="application/octet-stream",
        )

    parsed = _parse_range(range_header, total)
    if parsed is None:
        # Malformed range → fall back to full file (200), matching nginx
        # behavior. Strict 416 is technically more correct but every
        # PMTiles client we care about issues well-formed ranges.
        return StreamingResponse(
            _stream_full(tile_path),
            status_code=200,
            headers={**headers, "Content-Length": str(total)},
            media_type="application/octet-stream",
        )

    start, end = parsed
    length = end - start + 1
    headers["Content-Range"] = f"bytes {start}-{end}/{total}"
    headers["Content-Length"] = str(length)
    return StreamingResponse(
        _stream_range(tile_path, start, end),
        status_code=206,
        headers=headers,
        media_type="application/octet-stream",
    )


# Internal helpers exported for unit testing.
__all__ = ["router", "_validate_filename", "_parse_range"]
