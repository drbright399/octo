"""The per-tenant rollout switch (registry `clients.entity_resolution`, 040).

  off      (default) no identity work for the tenant — the feeders skip it,
           the worker skips it, the API answers "off", the NextDNS feed makes
           no call for it. ONE exception (v0.17.2, Rick's decision D): the
           Datto DEVICE LIST is read and kept (`inv_device`) for every
           Datto-mapped tenant — the Fleet's counts and the alerts' device
           names — but no link is made from it while the switch is off
  shadow   lookups are kept and answers computed and stored; the alert panel
           does not show them and no entity alert is raised (a week of
           shadow to check against reality)
  on       shown on alerts; the device-silence check raises its alerts

A registry without the column (before 040) or that cannot be read reads as
'off' — fail closed.
"""
from __future__ import annotations

import sqlite3
import threading
import time
from typing import Optional

from apps.octo import paths
from apps.octo.db import connect

MODES = ("off", "shadow", "on")
CACHE_SEC = 30.0

_lock = threading.Lock()
_cache: dict[str, tuple[float, str]] = {}


def _key(slug: str) -> str:
    # Keyed by the registry too: one process may serve several data roots
    # (tests), and a switch must never leak between them.
    return f"{paths.registry_db_path()}|{slug}"


def mode(slug: str, *, fresh: bool = False) -> str:
    now = time.monotonic()
    key = _key(slug)
    if not fresh:
        with _lock:
            hit = _cache.get(key)
        if hit is not None and now - hit[0] < CACHE_SEC:
            return hit[1]
    value = _read(slug)
    with _lock:
        _cache[key] = (now, value)
    return value


def _read(slug: str) -> str:
    try:
        reg = connect(paths.registry_db_path(), read_only=True)
    except (sqlite3.Error, FileNotFoundError):
        return "off"
    try:
        row = reg.execute(
            "SELECT entity_resolution, status FROM clients WHERE slug = ?", (slug,),
        ).fetchone()
    except sqlite3.Error:
        return "off"
    finally:
        reg.close()
    if row is None or row["status"] != "active":
        return "off"
    value = row["entity_resolution"]
    return value if value in MODES else "off"


def enabled(slug: str) -> bool:
    return mode(slug) in ("shadow", "on")


def tenants(modes: tuple[str, ...] = ("shadow", "on")) -> list[str]:
    """Active tenants whose switch is in `modes`, sorted."""
    try:
        reg = connect(paths.registry_db_path(), read_only=True)
    except (sqlite3.Error, FileNotFoundError):
        return []
    try:
        marks = ",".join("?" * len(modes))
        rows = reg.execute(
            f"SELECT slug FROM clients WHERE status = 'active' "
            f"AND entity_resolution IN ({marks}) ORDER BY slug", modes,
        ).fetchall()
    except sqlite3.Error:
        return []
    finally:
        reg.close()
    return [r["slug"] for r in rows]


def set_mode(slug: str, value: str) -> Optional[str]:
    """Write the switch; returns the previous value (None: no such tenant).
    The caller audits."""
    if value not in MODES:
        raise ValueError(f"mode must be one of {', '.join(MODES)}")
    reg = connect(paths.registry_db_path())
    try:
        reg.execute("BEGIN IMMEDIATE")
        row = reg.execute("SELECT entity_resolution FROM clients WHERE slug = ?",
                          (slug,)).fetchone()
        if row is None:
            reg.execute("ROLLBACK")
            return None
        reg.execute("UPDATE clients SET entity_resolution = ? WHERE slug = ?", (value, slug))
        reg.execute("COMMIT")
    finally:
        reg.close()
    reset(slug)
    return str(row["entity_resolution"])


def reset(slug: Optional[str] = None) -> None:
    with _lock:
        if slug is None:
            _cache.clear()
        else:
            _cache.pop(_key(slug), None)
