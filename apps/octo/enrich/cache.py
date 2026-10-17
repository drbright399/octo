"""The registry's `enrichment_cache` (migration 046): one row per (kind,
key) with an expiry. A cache — rows are replaced and pruned; a read never
fails a page (an unreadable cache is a miss)."""
from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from apps.octo import paths
from apps.octo.db import connect, transaction
from apps.octo.ingest.timestamps import format_utc_ms

logger = logging.getLogger(__name__)

IP, HOST, BOOTSTRAP = "ip", "host", "rdap_bootstrap"
OK_TTL = timedelta(days=7)
FAIL_TTL = timedelta(hours=1)
HOST_TTL = timedelta(days=1)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def get(kind: str, key: str, *, now: Optional[datetime] = None,
        include_failed: bool = False) -> Optional[dict[str, Any]]:
    """The cached value when fresh (a failure only with `include_failed`,
    as {"failed": True, ...}); None on a miss or when unreadable."""
    now = now or _now()
    try:
        reg = connect(paths.registry_db_path(), read_only=True)
    except (sqlite3.Error, FileNotFoundError):
        return None
    try:
        r = reg.execute("SELECT value_json, ok, expires_at, fetched_at FROM enrichment_cache "
                        "WHERE kind = ? AND key = ?", (kind, key)).fetchone()
    except sqlite3.Error:
        return None
    finally:
        reg.close()
    if r is None or str(r["expires_at"]) <= format_utc_ms(now):
        return None
    if not r["ok"]:
        return {"failed": True, "fetched_at": r["fetched_at"]} if include_failed else None
    try:
        value = json.loads(r["value_json"])
    except ValueError:
        return None
    if isinstance(value, dict):
        value.setdefault("fetched_at", r["fetched_at"])
        return value
    return None


def many(kind: str, keys: list[str], *, now: Optional[datetime] = None) -> dict[str, dict[str, Any]]:
    """Fresh answers (failures as {"failed": True}) for several keys."""
    keys = sorted(set(keys))
    if not keys:
        return {}
    now = now or _now()
    try:
        reg = connect(paths.registry_db_path(), read_only=True)
    except (sqlite3.Error, FileNotFoundError):
        return {}
    out: dict[str, dict[str, Any]] = {}
    try:
        for i in range(0, len(keys), 400):
            chunk = keys[i:i + 400]
            rows = reg.execute(
                f"SELECT key, value_json, ok, fetched_at FROM enrichment_cache WHERE kind = ? "
                f"AND expires_at > ? AND key IN ({','.join('?' * len(chunk))})",
                (kind, format_utc_ms(now), *chunk)).fetchall()
            for r in rows:
                if not r["ok"]:
                    out[r["key"]] = {"failed": True, "fetched_at": r["fetched_at"]}
                    continue
                try:
                    value = json.loads(r["value_json"])
                except ValueError:
                    continue
                if isinstance(value, dict):
                    value.setdefault("fetched_at", r["fetched_at"])
                    out[r["key"]] = value
    except sqlite3.Error:
        return {}
    finally:
        reg.close()
    return out


def ip_info(ip: str) -> Optional[dict[str, Any]]:
    return get(IP, ip)


def put(kind: str, key: str, value: Optional[dict[str, Any]], *, ok: bool = True,
        ttl: Optional[timedelta] = None, now: Optional[datetime] = None) -> None:
    now = now or _now()
    ttl = ttl or (OK_TTL if ok else FAIL_TTL)
    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            reg.execute(
                "INSERT INTO enrichment_cache (kind, key, value_json, ok, fetched_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (kind, key) DO UPDATE SET "
                "value_json = excluded.value_json, ok = excluded.ok, "
                "fetched_at = excluded.fetched_at, expires_at = excluded.expires_at",
                (kind, key[:300], json.dumps(value or {}, sort_keys=True, separators=(",", ":")),
                 1 if ok else 0, format_utc_ms(now), format_utc_ms(now + ttl)))
    finally:
        reg.close()


def prune(now: Optional[datetime] = None) -> int:
    """Drop expired rows. Returns how many."""
    now = now or _now()
    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            return reg.execute("DELETE FROM enrichment_cache WHERE expires_at <= ?",
                               (format_utc_ms(now),)).rowcount
    finally:
        reg.close()
