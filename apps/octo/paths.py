"""Path resolver — spec §2.3.

Every code site that touches a client DB routes through this module.
- Slug validation matches the app-layer regex.
- Symlinks are refused.
- Reserved names are refused.
- Output paths are verified to sit under data_root — ALWAYS, whether or not
  the file exists yet. `resolve_inside` is the one containment check: every
  path built from a name that came from outside (a tenant slug from a
  request or a registry row, a basemap file name) goes through it before
  anything touches the filesystem through that path.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Optional, Union

from apps.octo.auth.config import RESERVED_SLUGS, data_root

# `\Z`, not `$`: `$` also matches just before a trailing newline, so
# 'acme\n' passed the old pattern and named a different directory than
# 'acme'. Callers use `.match`, so the anchor has to live in the pattern.
SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*\Z")

StrPath = Union[str, "os.PathLike[str]"]


class SlugError(ValueError):
    """Raised when a slug fails validation, or a path built from one (or
    from any other outside name) fails the containment check."""


def validate_slug(slug: str) -> str:
    """Return slug if valid; raise SlugError otherwise."""
    if not isinstance(slug, str):
        raise SlugError(f"slug must be a string, got {type(slug).__name__}")
    if not SLUG_RE.match(slug):
        raise SlugError(
            f"invalid slug {slug!r}: must match {SLUG_RE.pattern} "
            "(one or more lowercase alphanumeric segments joined by single "
            "hyphens, nothing else: no trailing newline)"
        )
    if slug in RESERVED_SLUGS:
        raise SlugError(f"slug {slug!r} is reserved")
    return slug


def _check_segment(segment: object) -> str:
    """One plain path component: a non-empty str that is not '.' / '..' and
    carries no separator ('/' or '\\', whatever the OS), no drive and no NUL
    byte. Stops a name from ever meaning more than one directory level."""
    if not isinstance(segment, str):
        raise SlugError(f"path segment must be a string, got {type(segment).__name__}")
    if (
        segment in ("", ".", "..")
        or "\x00" in segment
        or "/" in segment
        or "\\" in segment
        or (os.altsep is not None and os.altsep in segment)
        or os.path.isabs(segment)
        or os.path.splitdrive(segment)[0]
    ):
        raise SlugError(f"not a single plain path segment: {segment!r}")
    return segment


def resolve_inside(root: StrPath, *segments: str) -> Path:
    """`root` joined with `segments`, proven to stay inside `root`.

    The one containment check of spec §2.3. Each segment must be a single
    plain path component (`_check_segment`); the joined path is normalised
    with os.path.realpath and must sit strictly under the (resolved) root;
    and no component below the root may be a symlink — a symlink inside the
    data tree could point one tenant's path at another tenant's files, so it
    is refused even when its target is inside the root. Symlinks ABOVE the
    root (in the configured data root's own location) are the operator's
    business and are followed.

    Applied whether or not the path exists, BEFORE the caller touches the
    filesystem through it. Raises SlugError; returns the resolved path."""
    if not segments:
        raise SlugError("resolve_inside needs at least one path segment")
    base = os.path.realpath(os.fspath(root))
    for segment in segments:
        _check_segment(segment)
    joined = os.path.join(base, *segments)
    resolved = os.path.realpath(joined)
    if not resolved.startswith(os.path.join(base, "")):
        raise SlugError(f"path {joined!r} escapes its root {base!r}")
    # Below the root the path is now known-contained. A symlink anywhere in
    # it makes realpath differ from the plain join — except a looping one
    # (realpath gives up and hands the path back as is), so every existing
    # component is also checked directly.
    if resolved != joined:
        raise SlugError(f"symlink refused under {base!r}: {joined!r}")
    current = base
    for part in resolved[len(base):].split(os.sep):
        if not part:
            continue
        current = os.path.join(current, part)
        if os.path.islink(current):
            raise SlugError(f"symlink refused at {current!r}")
    return Path(resolved)


def registry_db_path() -> Path:
    return data_root() / "registry.db"


def global_dir() -> Path:
    return data_root() / "global"


def patterns_db_path() -> Path:
    return global_dir() / "patterns.db"


def global_audit_db_path() -> Path:
    return global_dir() / "audit.db"


def client_dir(slug: str, *, root: Optional[StrPath] = None) -> Path:
    """`<data_root>/clients/<slug>`, contained and symlink-free (spec §2.3).
    `root` replaces data_root() for a store built on another data root (the
    ingest sink / telemetry store accept one; tests use it)."""
    validate_slug(slug)
    return resolve_inside(data_root() if root is None else root, "clients", slug)


CLIENT_DB_NAMES = frozenset({"indicators", "events", "audit", "tickets", "telemetry",
                             "entities"})


def client_db_path(slug: str, name: str, *, root: Optional[StrPath] = None) -> Path:
    """name ∈ CLIENT_DB_NAMES ('telemetry' = the tiered DNS / flow store,
    migration 036; 'entities' = entity resolution's lookups and answers,
    migration 040). Contained and symlink-free whether or not the file
    exists yet (`resolve_inside`); `root` as for `client_dir`."""
    if name not in CLIENT_DB_NAMES:
        raise ValueError(f"unknown client DB name: {name}")
    validate_slug(slug)
    return resolve_inside(
        data_root() if root is None else root, "clients", slug, f"{name}.db",
    )


def archive_dir() -> Path:
    return data_root() / "_archive"


def backups_dir() -> Path:
    return data_root() / "_backups"


def archive_root() -> Path | None:
    """Cold-archive root for pruned raw telemetry (`OCTO_ARCHIVE_ROOT`).

    None = the archive is DISABLED (the variable is unset or blank): the
    retention job then prunes raw telemetry without a copy and says so in
    its output and audit rows. Deliberately NOT under data_root — it belongs
    on bulk storage (an array share), not the SSD the SQLite state lives on.
    Whether the path exists / is writable is the job's business: a
    configured-but-unusable archive blocks pruning, it never disables it."""
    raw = os.environ.get("OCTO_ARCHIVE_ROOT", "").strip()
    return Path(raw) if raw else None


def tiles_dir() -> Path:
    """PMTiles vector-basemap files for the Fleet map (slice-9 redesign).

    Per the 2026-05-19 basemap design hand-off, the basemap
    is self-hosted to keep customer buoy lat/lng off external tile CDNs.
    Files are .pmtiles (single-file vector tiles, HTTP range-request
    served). Built offline via planetiler/tilemaker or pulled from a
    Protomaps regional export.
    """
    return data_root() / "tiles"


def tile_path(filename: str) -> Path:
    """One basemap file under `tiles_dir()`, through `resolve_inside`
    (single plain name, contained, the file itself not a symlink). The
    tiles directory itself may be a symlink to bulk storage — that is
    deployment layout, not request input. Format rules (the .pmtiles name
    pattern) are the router's; this is the containment half."""
    return resolve_inside(tiles_dir(), filename)
