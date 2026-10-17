"""Per-operator preferences endpoint.

  GET /api/v1/account/preferences
  PUT /api/v1/account/preferences { l2_llm_enabled: bool, ... }

Stores small personal settings in operators.preferences (JSON blob,
added by migration 025). Defaults filled in on read so callers don't
have to handle NULL.

v1 preferences:
  l2_llm_enabled — per-operator opt-out from octo-llm enrichment.
                   Defaults to true. When false, /agent-query rejects
                   with 412 "user_disabled" even if the bundle-wide
                   flag is on. Independent of bundle_config —
                   operator can disable themselves while the bundle
                   has it enabled for everyone else.

Why per-operator (not per-tenant):
  Two operators in the same MSP may have different trust levels with
  AI suggestions. An analyst doing forensics work may want pure-
  heuristic view; a triage operator may want enrichment on. The
  per-tenant opt-out (which already exists for AI consumption per
  the ephemeral customer-viewer accounts design) governs whose DATA the
  LLM can see; this preference governs whether the LLM speaks to
  this operator.

Banked 2026-05-21 as Slice 5b of the LLM-container arc.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from apps.octo import paths
from apps.octo.api.errors import APIError
from apps.octo.api.routers.auth import session_identity, _audit_append
from apps.octo.auth import sessions
from apps.octo.db import connect


router = APIRouter(prefix="/account", tags=["account"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

# Defaults applied when the operator's preferences column is NULL or
# missing a key. Single source of truth for "what's a preference"
# lives here.
_DEFAULTS: dict = {
    "l2_llm_enabled": True,
}


class OperatorPreferences(BaseModel):
    """Returned from GET and accepted on PUT. All fields optional on
    PUT so a partial update is one merged write."""
    l2_llm_enabled: Optional[bool] = None

    def merged_into(self, base: dict) -> dict:
        """Apply non-None fields from this update onto `base`."""
        out = dict(base)
        for k, v in self.model_dump(exclude_none=True).items():
            out[k] = v
        return out


class OperatorPreferencesResponse(BaseModel):
    """Full resolved preferences — defaults filled in."""
    l2_llm_enabled: bool


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_preferences(operator_id: int) -> dict:
    """Return the operator's effective preferences with defaults
    filled in for missing keys.

    Tolerant of: NULL column, missing column (pre-migration-025 DB),
    malformed JSON. Falls back to defaults in every case so a
    storage glitch can't lock the operator out of the API.
    """
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        try:
            row = reg.execute(
                "SELECT preferences FROM operators WHERE id = ?",
                (operator_id,),
            ).fetchone()
        except sqlite3.OperationalError:
            # Column doesn't exist yet (test DB pre-migration-025).
            return dict(_DEFAULTS)
    finally:
        reg.close()
    if row is None:
        raise APIError("AUTH_OPERATOR_NOT_FOUND")
    raw = row[0] if not hasattr(row, "keys") else row["preferences"]
    if raw is None or raw == "":
        return dict(_DEFAULTS)
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return dict(_DEFAULTS)
    if not isinstance(parsed, dict):
        return dict(_DEFAULTS)
    # Merge defaults under the stored values so any new pref added
    # in a future version has its default value without a backfill.
    merged = dict(_DEFAULTS)
    merged.update(parsed)
    return merged


def _save_preferences(operator_id: int, prefs: dict) -> None:
    reg = connect(paths.registry_db_path())
    try:
        reg.execute(
            "UPDATE operators SET preferences = ? WHERE id = ?",
            (json.dumps(prefs, sort_keys=True), operator_id),
        )
        reg.commit()
    finally:
        reg.close()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/preferences", response_model=OperatorPreferencesResponse)
def get_preferences(
    info: sessions.SessionInfo = Depends(session_identity),
) -> OperatorPreferencesResponse:
    prefs = _load_preferences(info.operator_id)
    return OperatorPreferencesResponse(
        l2_llm_enabled=bool(prefs.get("l2_llm_enabled", True)),
    )


@router.put("/preferences", response_model=OperatorPreferencesResponse)
def put_preferences(
    body: OperatorPreferences,
    info: sessions.SessionInfo = Depends(session_identity),
) -> OperatorPreferencesResponse:
    existing = _load_preferences(info.operator_id)
    merged = body.merged_into(existing)
    _save_preferences(info.operator_id, merged)
    _audit_append(
        "operator_preferences_update",
        actor=str(info.operator_id),
        target_id=f"operator:{info.operator_id}",
        before=existing,
        after=merged,
        reason=None,
        request_id=str(uuid.uuid4()),
    )
    return OperatorPreferencesResponse(
        l2_llm_enabled=bool(merged.get("l2_llm_enabled", True)),
    )


# ---------------------------------------------------------------------------
# Public helper for other routers (avoids cross-import circulars)
# ---------------------------------------------------------------------------

def operator_l2_llm_enabled(operator_id: int) -> bool:
    """Read-only convenience for the /agent-query bridge — returns
    True iff the operator has NOT opted out of LLM enrichment."""
    return bool(_load_preferences(operator_id).get("l2_llm_enabled", True))


# ---------------------------------------------------------------------------
# /api/v1/account/llm-status — universal visibility (slice 5d-2)
# ---------------------------------------------------------------------------

class LlmStatusResponse(BaseModel):
    """Resolves all four LLM gates for the current operator + the
    live sibling state so the UI can show one consolidated status
    chip without separately calling the probe endpoint.

    Per Rick's 2026-05-21 design call:
      'all users see what model is running for them per the
       super-admin selection.'

    Slice 7l adds sibling_healthy + sibling_backend +
    sibling_model_version so the topbar pill can show "ready" /
    "down" / "stub mode" at a glance + which model is loaded.
    """
    active_model: str        # bundle_config-recorded active model
    your_grant: bool          # admin-granted access
    your_preference: bool     # operator's own toggle
    bundle_enabled: bool      # super_admin's bundle-wide flag
    effectively_active: bool   # AND of all four gates (incl. healthz)
    # Slice 7l — live sibling state (visible to every operator
    # — these are operational, not privileged. Backend "stub"
    # vs "llama-cpp" is useful for analyst trust: if it's stub
    # the answers are canned, not real model output).
    sibling_healthy: bool
    sibling_backend: Optional[str] = None
    sibling_model_version: Optional[str] = None


def _probe_sibling_lite() -> dict:
    """Lightweight sibling-state probe. Returns dict with three
    optional fields: healthy bool, backend str, model_version str.
    Tolerant of network errors — never raises."""
    try:
        import httpx as _httpx
        from apps.octo.api.routers.agent_query import _octo_llm_url
        r = _httpx.get(f"{_octo_llm_url()}/v1/healthz", timeout=1.5)
        if r.status_code != 200:
            return {"healthy": False, "backend": None, "model_version": None}
        body = r.json()
        return {
            "healthy": bool(body.get("model_loaded")),
            "backend": body.get("backend"),
            "model_version": body.get("model_version"),
        }
    except Exception:  # noqa: BLE001
        return {"healthy": False, "backend": None, "model_version": None}


@router.get("/llm-status", response_model=LlmStatusResponse)
def llm_status(
    info: sessions.SessionInfo = Depends(session_identity),
) -> LlmStatusResponse:
    """Returns the LLM-availability snapshot for THIS operator.

    Visible to every authenticated operator regardless of tier —
    they all want to know whether their next 'ask octo' click will
    actually fire, AND what model is currently loaded.
    """
    # Lazy imports to avoid import cycle (these modules import
    # from this one).
    from apps.octo.api.routers.admin_llm_grants import operator_l2_llm_granted
    from apps.octo.api.routers.admin_llm_models import _active_model
    from apps.octo.api.routers.agent_query import _llm_enabled

    granted = operator_l2_llm_granted(info.operator_id)
    pref_enabled = operator_l2_llm_enabled(info.operator_id)
    bundle = _llm_enabled()

    # Always probe the sibling — every operator wants to see "ready"
    # or "down" regardless of whether THEIR gates are on. The 1.5s
    # timeout caps the cost. Topbar polls every ~10s so this is a
    # 1.5s/10s = 15% bandwidth amortized cost on the backend at the
    # worst case (every operator's tab open with a stale octo-llm).
    sibling = _probe_sibling_lite()
    healthz = sibling["healthy"]

    return LlmStatusResponse(
        active_model=_active_model(),
        your_grant=granted,
        your_preference=pref_enabled,
        bundle_enabled=bundle,
        effectively_active=(
            granted and pref_enabled and bundle and healthz
        ),
        sibling_healthy=healthz,
        sibling_backend=sibling["backend"],
        sibling_model_version=sibling["model_version"],
    )
