"""super_admin bundle-wide config surface.

Slice 7a — initial focus is the L2 LLM enable toggle. The same
endpoint shape will service future bundle-config writes (theme
brand, retention policies that aren't already in the dedicated
retention router, etc.).

  GET /api/v1/admin/bundle-config/llm
      → { l2_llm_enabled: bool, l2_llm_active_model: str }

  PUT /api/v1/admin/bundle-config/llm
      { l2_llm_enabled?: bool }
      → { l2_llm_enabled: bool, l2_llm_active_model: str }

Per Rick's 2026-05-21 design call, the bundle-wide L2 LLM toggle is
super_admin-gated (not factory-only — turning the feature on/off
for the bundle is delegatable; only swapping the actual model is
factory-only).

Audit row per change. Idempotent no-ops do not write.

Banked 2026-05-21 as slice 7a.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from apps.octo import paths
from apps.octo.api.role_gates import session_at_least
from apps.octo.api.routers.auth import _audit_append
from apps.octo.auth import sessions
from apps.octo.db import connect


router = APIRouter(prefix="/admin/bundle-config", tags=["admin", "llm"])


_KEY_LLM_ENABLED = "l2_llm_enabled"
_KEY_ACTIVE_MODEL = "l2_llm_active_model"
_DEFAULT_ACTIVE_MODEL = "granite-3b-q4"


class LlmBundleConfig(BaseModel):
    l2_llm_enabled: bool
    l2_llm_active_model: str


class LlmBundleConfigUpdate(BaseModel):
    l2_llm_enabled: Optional[bool] = None


def _read_bool(conn: sqlite3.Connection, key: str, default: bool) -> bool:
    try:
        row = conn.execute(
            "SELECT value_json FROM bundle_config WHERE key = ?", (key,),
        ).fetchone()
    except sqlite3.OperationalError:
        return default
    if row is None:
        return default
    try:
        parsed = json.loads(row[0] if not hasattr(row, "keys") else row["value_json"])
    except (json.JSONDecodeError, TypeError):
        return default
    return parsed is True


def _read_str(conn: sqlite3.Connection, key: str, default: str) -> str:
    try:
        row = conn.execute(
            "SELECT value_json FROM bundle_config WHERE key = ?", (key,),
        ).fetchone()
    except sqlite3.OperationalError:
        return default
    if row is None:
        return default
    try:
        parsed = json.loads(row[0] if not hasattr(row, "keys") else row["value_json"])
    except (json.JSONDecodeError, TypeError):
        return default
    return str(parsed) if isinstance(parsed, str) else default


def _ensure_bundle_config(conn: sqlite3.Connection) -> None:
    """Create bundle_config if migration 022 hasn't landed in this
    fixture. Tests may run against partially-migrated DBs."""
    try:
        conn.execute("SELECT 1 FROM bundle_config LIMIT 1")
    except sqlite3.OperationalError:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS bundle_config (
                key             TEXT PRIMARY KEY,
                value_json      TEXT NOT NULL,
                description     TEXT NOT NULL DEFAULT '',
                updated_at      TEXT NOT NULL,
                updated_by      INTEGER
            );
        """)


@router.get("/llm", response_model=LlmBundleConfig)
def get_llm_config(
    info: sessions.SessionInfo = Depends(session_at_least("super_admin")),
) -> LlmBundleConfig:
    conn = connect(paths.registry_db_path(), read_only=True)
    try:
        enabled = _read_bool(conn, _KEY_LLM_ENABLED, default=False)
        model = _read_str(conn, _KEY_ACTIVE_MODEL, default=_DEFAULT_ACTIVE_MODEL)
    finally:
        conn.close()
    return LlmBundleConfig(
        l2_llm_enabled=enabled,
        l2_llm_active_model=model,
    )


@router.put("/llm", response_model=LlmBundleConfig)
def put_llm_config(
    body: LlmBundleConfigUpdate,
    info: sessions.SessionInfo = Depends(session_at_least("super_admin")),
) -> LlmBundleConfig:
    request_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    conn = connect(paths.registry_db_path())
    try:
        _ensure_bundle_config(conn)
        before_enabled = _read_bool(conn, _KEY_LLM_ENABLED, default=False)
        before_model = _read_str(conn, _KEY_ACTIVE_MODEL, default=_DEFAULT_ACTIVE_MODEL)

        if body.l2_llm_enabled is not None and body.l2_llm_enabled != before_enabled:
            conn.execute(
                "INSERT OR REPLACE INTO bundle_config "
                "(key, value_json, updated_at, updated_by) "
                "VALUES (?, ?, ?, ?)",
                (_KEY_LLM_ENABLED, json.dumps(body.l2_llm_enabled), now,
                 info.operator_id),
            )
            conn.commit()
            _audit_append(
                "l2_llm_bundle_toggle",
                actor=str(info.operator_id),
                target_id=f"bundle_config:{_KEY_LLM_ENABLED}",
                before={"enabled": before_enabled},
                after={"enabled": body.l2_llm_enabled},
                reason=None,
                request_id=request_id,
            )
            after_enabled = body.l2_llm_enabled
        else:
            after_enabled = before_enabled
    finally:
        conn.close()

    return LlmBundleConfig(
        l2_llm_enabled=after_enabled,
        l2_llm_active_model=before_model,
    )
