"""Durable per-instance poller state — `adapter_poller_state` (registry, 036).

What a poller must still know after a restart that is NOT in the events it
stored. One JSON value per (instance, key); the writer bounds its size.
First user: RocketCyber's history-skipped incidents (`adapters/rocketcyber/
poller.py`) — skipped at first connect and never stored, so a restart that
seeded only from stored rows forgot them, and the next change of such an
incident's updatedAt stored it as a brand-new HIGH row.

Fail-soft on purpose: a poller must never stop because the registry hiccuped.
`load` returns None and `save` returns False (both logged) — the poller then
behaves as it did before this table existed.

A poller with MANY small parts of state (NextDNS: one row per profile)
writes only the rows that changed, in ONE transaction (`save_many`, with
the rows to delete), and reads them back by key prefix (`load_prefix`).
"""
from __future__ import annotations

import json
import logging
import sqlite3
from typing import Any, Iterable, Optional

from apps.octo import paths
from apps.octo.ingest.timestamps import utcnow_iso

logger = logging.getLogger(__name__)

MAX_VALUE_BYTES = 2_000_000


def load(instance_id: int, key: str) -> Optional[Any]:
    """The stored value, or None (none stored, pre-036 registry, unreadable)."""
    try:
        conn = sqlite3.connect(
            f"file:{paths.registry_db_path()}?mode=ro", uri=True, timeout=5.0)
        try:
            row = conn.execute(
                "SELECT value_json FROM adapter_poller_state WHERE instance_id = ? AND key = ?",
                (int(instance_id), key),
            ).fetchone()
        finally:
            conn.close()
    except sqlite3.Error as exc:
        logger.warning("[poller-state] %s/%s not read (%s)", instance_id, key,
                       type(exc).__name__)
        return None
    if row is None:
        return None
    try:
        return json.loads(row[0])
    except ValueError:
        return None


def save(instance_id: int, key: str, value: Any) -> bool:
    """Store `value` (JSON) for (instance, key). False when it could not be
    written or is over MAX_VALUE_BYTES — never raises."""
    text = dumps(value)
    if len(text.encode("utf-8")) > MAX_VALUE_BYTES:
        logger.warning("[poller-state] %s/%s not saved: %d bytes over the bound",
                       instance_id, key, len(text))
        return False
    try:
        conn = sqlite3.connect(paths.registry_db_path(), timeout=5.0)
        try:
            with conn:
                conn.execute(
                    "INSERT INTO adapter_poller_state (instance_id, key, value_json, updated_at) "
                    "VALUES (?, ?, ?, ?) ON CONFLICT (instance_id, key) DO UPDATE SET "
                    "value_json = excluded.value_json, updated_at = excluded.updated_at",
                    (int(instance_id), key, text, utcnow_iso()),
                )
        finally:
            conn.close()
    except sqlite3.Error as exc:
        logger.warning("[poller-state] %s/%s not saved (%s)", instance_id, key,
                       type(exc).__name__)
        return False
    return True


def dumps(value: Any) -> str:
    """The canonical JSON text a value is stored as (what `save` writes) —
    a writer can compare it with what it stored last."""
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def load_prefix(instance_id: int, prefix: str) -> Optional[dict[str, Any]]:
    """{key: value} for every stored key starting with `prefix` (values that
    are not JSON are skipped), or None when the registry cannot be read."""
    escaped = prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    try:
        conn = sqlite3.connect(
            f"file:{paths.registry_db_path()}?mode=ro", uri=True, timeout=5.0)
        try:
            rows = conn.execute(
                "SELECT key, value_json FROM adapter_poller_state WHERE instance_id = ? "
                "AND key LIKE ? ESCAPE '\\'",
                (int(instance_id), escaped + "%"),
            ).fetchall()
        finally:
            conn.close()
    except sqlite3.Error as exc:
        logger.warning("[poller-state] %s/%s* not read (%s)", instance_id, prefix,
                       type(exc).__name__)
        return None
    out: dict[str, Any] = {}
    for key, text in rows:
        if not str(key).startswith(prefix):
            continue
        try:
            out[str(key)] = json.loads(text)
        except ValueError:
            continue
    return out


def save_many(instance_id: int, values: dict[str, Any], delete: Iterable[str] = ()) -> bool:
    """Store every (key → value) of `values` and delete the `delete` keys for
    the instance in ONE transaction: all of it or none. False (logged) when
    it could not be written or a value is over MAX_VALUE_BYTES — never
    raises for a registry fault."""
    texts: list[tuple[str, str]] = []
    for key, value in values.items():
        text = dumps(value)
        if len(text.encode("utf-8")) > MAX_VALUE_BYTES:
            logger.warning("[poller-state] %s/%s not saved: %d bytes over the bound",
                           instance_id, key, len(text))
            return False
        texts.append((key, text))
    gone = [k for k in delete if k not in values]
    if not texts and not gone:
        return True
    now = utcnow_iso()
    try:
        conn = sqlite3.connect(paths.registry_db_path(), timeout=5.0)
        try:
            with conn:
                conn.executemany(
                    "INSERT INTO adapter_poller_state (instance_id, key, value_json, updated_at) "
                    "VALUES (?, ?, ?, ?) ON CONFLICT (instance_id, key) DO UPDATE SET "
                    "value_json = excluded.value_json, updated_at = excluded.updated_at",
                    [(int(instance_id), key, text, now) for key, text in texts],
                )
                conn.executemany(
                    "DELETE FROM adapter_poller_state WHERE instance_id = ? AND key = ?",
                    [(int(instance_id), key) for key in gone],
                )
        finally:
            conn.close()
    except sqlite3.Error as exc:
        logger.warning("[poller-state] %s: %d row(s) not saved (%s)", instance_id,
                       len(texts) + len(gone), type(exc).__name__)
        return False
    return True
