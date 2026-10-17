"""super_admin LLM model selector (Slice 5c scaffold).

Read-only listing surface for now. Future slice 5d adds download,
integrity verification, signature checking, and hot-swap restart
orchestration.

Endpoints (super_admin only):

  GET /api/v1/admin/llm/models
      → { active: "granite-3b-q4", models: [ModelInfo, ...] }

  PUT /api/v1/admin/llm/models/active
      { name: "granite-3b-q4" }
      → { active: "granite-3b-q4" }

Active model is stored in bundle_config.l2_llm_active_model (JSON
string). When changed, the octo-llm container needs to be restarted
to pick up the new model; the UI surfaces a "restart required"
hint after every change. Slice 5d wires the restart orchestration.

Model discovery: walks /var/lib/octo-llm/models/ for *.gguf files.
The path is overridable via OCTO_LLM_MODELS_DIR for dev. Each file
is reported with name, size_bytes, sha256 (if computed and cached),
and mtime.

We deliberately don't compute sha256 on every list (large files,
slow). A future slice adds a `verify` action that computes + caches
the hash, surfaces a Verified/Unverified status badge in the UI.

Banked 2026-05-21 as Slice 5c of the LLM-container arc.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from apps.octo import paths
from apps.octo.api.errors import APIError
from apps.octo.api.role_gates import session_at_least, session_factory
from apps.octo.api.routers.auth import _audit_append
from apps.octo.api.routers.search import require_step_up
from apps.octo.auth import sessions
from apps.octo.db import connect


router = APIRouter(prefix="/admin/llm", tags=["admin", "llm"])


# Default location octo-llm volume-mounts. Tests + dev override
# with OCTO_LLM_MODELS_DIR.
_MODELS_DIR_ENV = "OCTO_LLM_MODELS_DIR"
_DEFAULT_MODELS_DIR = "/var/lib/octo-llm/models"

# bundle_config key for the active-model selection. Default below.
_ACTIVE_MODEL_KEY = "l2_llm_active_model"
_DEFAULT_ACTIVE_MODEL = "granite-3b-q4"

# Cap on listing — defensive, in case someone mounts a directory
# with thousands of model files.
_MAX_MODELS_LISTED = 100


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class ModelInfo(BaseModel):
    """One model file on disk."""
    name: str            # stem (no .gguf)
    filename: str        # full filename including extension
    size_bytes: int
    sha256: Optional[str] = None  # populated only if cached
    mtime: str            # ISO8601 UTC
    is_active: bool


class ModelListResponse(BaseModel):
    active: str           # name stem of the currently-active model
    models: list[ModelInfo]
    models_dir: str       # what dir was scanned — operator visibility


class SetActiveRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)


class SetActiveResponse(BaseModel):
    active: str
    restart_required: bool


class ManifestModelEntry(BaseModel):
    """One entry from the pinned-hash manifest. Slice 5d-3 surfaces
    these so the operator can see what's installable; slice 5d-4 wires
    the actual download path. The non-null sha256 field on a manifest
    entry is what gates download — until set by a code review +
    commit, the download endpoint refuses the model."""
    name: str
    display_name: str
    description: str
    source_url: Optional[str]
    size_bytes_approx: int
    sha256: Optional[str]
    license: str
    publisher: str
    # Slice 7i — tier classification surfaced in the UI ("dev" /
    # "balanced" / "max") so super_admin can pick at-a-glance
    # based on the host's resource envelope.
    tier: Optional[str] = None
    default: bool
    installed: bool


class ManifestResponse(BaseModel):
    manifest_version: int
    models: list[ManifestModelEntry]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _models_dir() -> Path:
    return Path(os.environ.get(_MODELS_DIR_ENV, _DEFAULT_MODELS_DIR))


def _active_model() -> str:
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        try:
            row = reg.execute(
                "SELECT value_json FROM bundle_config WHERE key = ?",
                (_ACTIVE_MODEL_KEY,),
            ).fetchone()
        except sqlite3.OperationalError:
            return _DEFAULT_ACTIVE_MODEL
    finally:
        reg.close()
    if row is None:
        return _DEFAULT_ACTIVE_MODEL
    raw = row[0] if not hasattr(row, "keys") else row["value_json"]
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return _DEFAULT_ACTIVE_MODEL
    return str(parsed) if isinstance(parsed, str) else _DEFAULT_ACTIVE_MODEL


def _set_active_model(name: str, *, operator_id: int) -> None:
    request_id = str(uuid.uuid4())
    reg = connect(paths.registry_db_path())
    try:
        # Best-effort: read existing for audit before-state, even if
        # bundle_config table doesn't exist yet.
        before = None
        try:
            row = reg.execute(
                "SELECT value_json FROM bundle_config WHERE key = ?",
                (_ACTIVE_MODEL_KEY,),
            ).fetchone()
            if row is not None:
                before = {"active": json.loads(row[0])}
        except sqlite3.OperationalError:
            # Migration 022 may not have run; create the table on
            # demand to avoid breaking the read-only fallback path.
            reg.executescript("""
                CREATE TABLE IF NOT EXISTS bundle_config (
                    key TEXT PRIMARY KEY,
                    value_json TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL,
                    updated_by INTEGER
                );
            """)
        now = datetime.now(timezone.utc).isoformat()
        reg.execute(
            "INSERT OR REPLACE INTO bundle_config "
            "(key, value_json, updated_at, updated_by) VALUES (?, ?, ?, ?)",
            (_ACTIVE_MODEL_KEY, json.dumps(name), now, operator_id),
        )
        reg.commit()
    finally:
        reg.close()

    _audit_append(
        "l2_llm_active_model_change",
        actor=str(operator_id),
        target_id=f"bundle_config:{_ACTIVE_MODEL_KEY}",
        before=before,
        after={"active": name},
        reason=None,
        request_id=request_id,
    )


def _scan_models(dir_: Path) -> list[ModelInfo]:
    """List *.gguf files under `dir_`. Returns sorted by name."""
    if not dir_.is_dir():
        return []
    active = _active_model()
    out: list[ModelInfo] = []
    for child in sorted(dir_.iterdir()):
        if child.is_dir() or child.is_symlink():
            # Skip directories + symlinks defensively.
            continue
        if child.suffix.lower() != ".gguf":
            continue
        stat = child.stat()
        name = child.stem
        out.append(ModelInfo(
            name=name,
            filename=child.name,
            size_bytes=stat.st_size,
            sha256=None,  # not computed in slice 5c
            mtime=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
            is_active=(name == active),
        ))
        if len(out) >= _MAX_MODELS_LISTED:
            break
    return out


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

def _read_manifest() -> dict:
    """Load apps/octo_llm/manifest.json. Returns the parsed dict; on
    failure returns a minimal stub so the endpoint stays consumable."""
    # The manifest lives in the octo_llm package directory so it's
    # part of the bundle artifact. Resolved relative to this file.
    here = Path(__file__).resolve()
    # apps/octo/api/routers/admin_llm_models.py → apps/octo_llm/manifest.json
    repo_root = here.parents[4]  # → repo root
    p = repo_root / "apps" / "octo_llm" / "manifest.json"
    try:
        with p.open() as f:
            import json as _json
            return _json.load(f)
    except (OSError, ValueError):
        return {"manifest_version": 1, "models": []}


@router.get("/models/manifest", response_model=ManifestResponse)
def get_manifest(
    info: sessions.SessionInfo = Depends(session_at_least("super_admin")),
) -> ManifestResponse:
    """super_admin: returns the pinned-hash manifest of blessed models
    that can be installed via the in-product download flow (slice
    5d-4 wires the actual download). Each entry's `installed` flag
    reflects whether the .gguf file is present on disk.

    Slice 5d-3 returns this as read-only — the download endpoint
    isn't built yet; this is the UI's index of "what could be
    installed."
    """
    raw = _read_manifest()
    dir_ = _models_dir()
    on_disk: set[str] = set()
    if dir_.is_dir():
        for child in dir_.iterdir():
            if child.suffix.lower() == ".gguf":
                on_disk.add(child.stem)
    entries: list[ManifestModelEntry] = []
    for m in raw.get("models", []):
        entries.append(ManifestModelEntry(
            name=m["name"],
            display_name=m.get("display_name", m["name"]),
            description=m.get("description", ""),
            source_url=m.get("source_url"),
            size_bytes_approx=int(m.get("size_bytes_approx", 0)),
            sha256=m.get("sha256"),
            license=m.get("license", "unknown"),
            publisher=m.get("publisher", "unknown"),
            tier=m.get("tier"),
            default=bool(m.get("default", False)),
            installed=(m["name"] in on_disk),
        ))
    return ManifestResponse(
        manifest_version=int(raw.get("manifest_version", 1)),
        models=entries,
    )


@router.get("/models", response_model=ModelListResponse)
def list_models(
    info: sessions.SessionInfo = Depends(session_at_least("super_admin")),
) -> ModelListResponse:
    """LIST is super_admin (read-only visibility for any super_admin).
    WRITE actions (set active, download, promote) require factory."""
    dir_ = _models_dir()
    models = _scan_models(dir_)
    return ModelListResponse(
        active=_active_model(),
        models=models,
        models_dir=str(dir_),
    )


class RestartResponse(BaseModel):
    """Factory-admin restart-octo-llm result. Slice 7j."""
    requested: bool
    method: str            # "signal" (dev) | "docker" (prod) | "noop"
    detail: str            # human-readable description of what happened
    pid_killed: Optional[int] = None


@router.post("/restart", response_model=RestartResponse)
def restart_sibling(
    info: sessions.SessionInfo = Depends(session_at_least("super_admin")),
) -> RestartResponse:
    """Factory-admin: restart the octo-llm sibling so a model swap
    takes effect without leaving the dashboard.

    Two implementations depending on deploy shape:
      - Dev (uvicorn child of dev.sh): SIGTERM the uvicorn process by
        cmdline pattern. dev.sh's respawn loop relaunches it with the
        same env (including the new OCTO_LLM_MODEL_PATH if the operator
        also set that on the way in).
      - Prod (docker container): would call `docker restart octo-llm`
        via the host socket. Not wired yet (see slice 5d-4d) — returns
        method="noop" with a hint about the gap.

    Gated to super_admin tier (not factory-only) because the action is
    NON-DESTRUCTIVE for routine model swaps — operator confirms via the
    UI dialog. The model-SWAP itself (PUT /models/active) is what's
    factory + step-up gated. Restart is just "apply the change."

    Audit row per call regardless of method.
    """
    import os as _os
    import signal as _signal
    import subprocess as _subprocess
    import uuid as _uuid

    request_id = str(_uuid.uuid4())

    # Find the uvicorn child running octo-llm.
    pid_to_kill: Optional[int] = None
    try:
        out = _subprocess.run(
            ["pgrep", "-f", "uvicorn apps.octo_llm.server:app"],
            capture_output=True, text=True, timeout=2,
        )
        if out.returncode == 0:
            # pgrep returns one PID per line; take the first (most
            # recently launched in dev's typical case).
            lines = [int(p) for p in out.stdout.split() if p.strip().isdigit()]
            if lines:
                pid_to_kill = lines[0]
    except (_subprocess.SubprocessError, OSError, ValueError):
        pid_to_kill = None

    method = "noop"
    detail = ""
    if pid_to_kill is not None:
        try:
            _os.kill(pid_to_kill, _signal.SIGTERM)
            method = "signal"
            detail = (
                f"sent SIGTERM to octo-llm uvicorn (pid {pid_to_kill}); "
                "dev.sh respawn loop will relaunch with current env"
            )
        except (ProcessLookupError, PermissionError) as exc:
            method = "noop"
            detail = f"could not signal pid {pid_to_kill}: {exc}"
            pid_to_kill = None
    else:
        # No uvicorn child found — in prod this is where we'd hit
        # docker restart via host socket. Not wired yet; surface the
        # gap clearly so operator can fall back to manual restart.
        detail = (
            "no octo-llm uvicorn process found. In production, this "
            "endpoint would issue `docker restart octo-llm` via the "
            "host socket (slice 5d-4d, not yet wired). Restart the "
            "container manually for now."
        )

    _audit_append(
        "octo_llm_restart_requested",
        actor=str(info.operator_id),
        target_id="sibling:octo-llm",
        before=None,
        after={"method": method, "pid_killed": pid_to_kill},
        reason=detail,
        request_id=request_id,
    )
    return RestartResponse(
        requested=True, method=method, detail=detail,
        pid_killed=pid_to_kill,
    )


def _factory_step_up():
    """Compose: caller must be factory super_admin AND hold an active
    step-up window. Step-up is the second gate that defeats a stolen
    cookie or session-hijack from making model changes.

    Implemented as nested deps so FastAPI's session_factory() + the
    require_step_up signature are both applied at request time.
    """
    factory_dep = session_factory()

    def _dep(
        info: sessions.SessionInfo = Depends(factory_dep),
        request_info: sessions.SessionInfo = Depends(require_step_up),
    ) -> sessions.SessionInfo:
        # Both deps fire and validate the SAME session. require_step_up
        # returns the (slid) session_info; we return it.
        return request_info

    _dep.__name__ = "session_factory_with_step_up"
    return _dep


class SiblingProbeResponse(BaseModel):
    """Live state of the octo-llm sibling container, proxied through
    the backend (the SPA can't reach :8101 directly cross-origin).

    Slice 7g — Rick needs to see WHY the bridge says "service
    unavailable" from the UI, not by piecing it together from server
    logs. This surface answers four questions per request:
      1. Is octo-llm reachable from the backend network?
      2. Did its /v1/healthz return 200?
      3. Is its model loaded?
      4. Which backend (stub vs llama-cpp) is it running?
    """
    reachable: bool
    error: Optional[str] = None
    octo_llm_url: str
    # Raw healthz response when reachable; None on error.
    backend: Optional[str] = None
    model_loaded: Optional[bool] = None
    model_version: Optional[str] = None
    uptime_seconds: Optional[float] = None
    mem_used_mb: Optional[int] = None


@router.get("/probe", response_model=SiblingProbeResponse)
def probe_sibling(
    info: sessions.SessionInfo = Depends(session_at_least("super_admin")),
) -> SiblingProbeResponse:
    """Live probe of octo-llm's /v1/healthz. Super_admin-only.

    Surfaces the actual sibling state to the Settings → System panel
    so the operator can distinguish:
      - sibling unreachable (network / process not running)
      - sibling reachable but model not loaded (config error)
      - sibling running stub (no real LLM despite OCTO_LLM_BACKEND=llama-cpp)
      - sibling fully healthy
    """
    # Lazy import to avoid the cross-module circular at module load.
    import httpx as _httpx
    from apps.octo.api.routers.agent_query import _octo_llm_url

    url = _octo_llm_url()
    try:
        r = _httpx.get(f"{url}/v1/healthz", timeout=2.0)
    except _httpx.TimeoutException:
        return SiblingProbeResponse(
            reachable=False, error="timeout (2.0s)", octo_llm_url=url,
        )
    except _httpx.HTTPError as exc:
        return SiblingProbeResponse(
            reachable=False,
            error=f"{type(exc).__name__}: {exc}",
            octo_llm_url=url,
        )
    if r.status_code != 200:
        return SiblingProbeResponse(
            reachable=True,
            error=f"healthz returned HTTP {r.status_code}",
            octo_llm_url=url,
        )
    body = r.json()
    return SiblingProbeResponse(
        reachable=True,
        octo_llm_url=url,
        backend=body.get("backend"),
        model_loaded=body.get("model_loaded"),
        model_version=body.get("model_version"),
        uptime_seconds=body.get("uptime_seconds"),
        mem_used_mb=body.get("mem_used_mb"),
    )


# Slice 9g (consensus reviewer S2): OOM pre-check before a model
# swap takes effect. We multiply the manifest's size_bytes_approx
# (which is the QUANTIZED file size on disk) by this factor to
# estimate the working-set RAM the loaded model will occupy.
# llama-cpp's mmap loader keeps the file mapped + grows a small
# context buffer on top; 1.5x covers the kv-cache + context window
# overhead without being overly conservative. A future refinement
# can read the running model's actual rss + use that as a baseline.
_OOM_SAFETY_FACTOR = 1.5

# Threshold below which we treat the swap as definitely-unsafe.
# Operators with hosts close to this threshold should switch to a
# smaller-tier model via the manifest's "tier" classification.
_OOM_MIN_FREE_MB = 256


def _manifest_size_bytes(model_name: str) -> Optional[int]:
    """Lookup the manifest's `size_bytes_approx` for `model_name`.
    Returns None if the model isn't in the manifest (BYOM path)."""
    raw = _read_manifest()
    for entry in raw.get("models", []):
        if entry.get("name") == model_name:
            sz = entry.get("size_bytes_approx")
            return int(sz) if isinstance(sz, (int, float)) else None
    return None


def _oom_precheck_or_raise(model_name: str, *, operator_id: int) -> None:
    """Refuse model swap if available memory < estimated need.

    Estimated need = size_bytes_approx * 1.5 (factor) + 256MB floor.
    Available memory comes from psutil.virtual_memory().available
    which reports memory the kernel believes can be allocated
    without paging.

    BYOM models (no manifest entry) skip the precheck because we
    have no size estimate to compare against — they go through the
    existing "available on disk" check and the operator owns the
    decision. Logged so the operator sees the bypass."""
    size_bytes = _manifest_size_bytes(model_name)
    if size_bytes is None:
        # BYOM — no manifest size to compare against. Audit the
        # bypass so operators can see it in forensic review.
        from apps.octo.api.routers.auth import _audit_append
        _audit_append(
            "octo_llm_swap_oom_precheck_skipped",
            actor=str(operator_id),
            target_id=model_name,
            before=None,
            after={"reason": "byom_no_manifest_size"},
            reason="model not in manifest; OOM precheck skipped",
            request_id=str(uuid.uuid4()),
        )
        return

    try:
        import psutil  # lazy — heavy
        available_bytes = int(psutil.virtual_memory().available)
    except Exception:  # noqa: BLE001
        # psutil unavailable — log + skip rather than block. Better
        # to allow a swap that might OOM than block on a missing
        # diagnostic dependency.
        from apps.octo.api.routers.auth import _audit_append
        _audit_append(
            "octo_llm_swap_oom_precheck_skipped",
            actor=str(operator_id),
            target_id=model_name,
            before=None,
            after={"reason": "psutil_unavailable"},
            reason="psutil not importable; OOM precheck skipped",
            request_id=str(uuid.uuid4()),
        )
        return

    needed_bytes = int(size_bytes * _OOM_SAFETY_FACTOR) + (_OOM_MIN_FREE_MB * 1024 * 1024)
    if available_bytes < needed_bytes:
        from apps.octo.api.routers.auth import _audit_append
        _audit_append(
            "octo_llm_swap_oom_precheck_rejected",
            actor=str(operator_id),
            target_id=model_name,
            before=None,
            after={
                "needed_bytes": needed_bytes,
                "available_bytes": available_bytes,
                "model_size_bytes": size_bytes,
                "safety_factor": _OOM_SAFETY_FACTOR,
            },
            reason=(
                f"insufficient memory for {model_name!r}: "
                f"need ~{needed_bytes // (1024*1024)}MB, "
                f"have {available_bytes // (1024*1024)}MB"
            ),
            request_id=str(uuid.uuid4()),
        )
        raise APIError(
            "PRECONDITION_FAILED",
            f"insufficient memory to load {model_name!r}: "
            f"requires ~{needed_bytes // (1024*1024)}MB "
            f"(model {size_bytes // (1024*1024)}MB × "
            f"{_OOM_SAFETY_FACTOR}x safety factor); "
            f"only {available_bytes // (1024*1024)}MB available. "
            f"Pick a lower-tier model or free memory before swapping.",
        )


@router.put("/models/active", response_model=SetActiveResponse)
def set_active(
    body: SetActiveRequest,
    info: sessions.SessionInfo = Depends(_factory_step_up()),
) -> SetActiveResponse:
    """FACTORY super_admin + STEP-UP: select which installed model
    octo-llm should load on next restart. Refuses to set a model
    that isn't present on disk — bad config caught at write time,
    not at restart time.

    Two-layer gate per Rick's 2026-05-21 design call:
      1. Factory super_admin only (not delegatable to subordinates)
      2. Active step-up window (defeats stolen-cookie attack on
         this high-impact action)

    Slice 9g (consensus reviewer S2): additional OOM precheck —
    refuses if available memory < manifest size_bytes × 1.5. A
    successful swap to a too-large model would OOM-crash octo-llm
    on next restart, leaving the bundle without enrichment until
    the operator manually reverts. Better to refuse the WRITE."""
    dir_ = _models_dir()
    available = {m.name for m in _scan_models(dir_)}
    if body.name not in available:
        raise APIError(
            "NOT_FOUND",
            f"model {body.name!r} not found in {dir_} "
            f"(available: {sorted(available) or 'none'})",
        )
    _oom_precheck_or_raise(body.name, operator_id=info.operator_id)
    _set_active_model(body.name, operator_id=info.operator_id)
    return SetActiveResponse(active=body.name, restart_required=True)
