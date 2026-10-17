"""POST /api/v1/buoy/heartbeat — buoy fleet heartbeat ingestion.

Each deployed buoy runs `buoy-heartbeat` (sibling to `buoy-forwarder`)
which posts this endpoint every 60 s with its current system load,
service-unit states, and last-event-forwarded timestamp.

Auth: bearer-token (same client-token pattern as ingest). The bearer's
resolved slug is the authoritative slug for the row — the buoy may send
`slug` in the body but it is asserted, not trusted. A mismatch returns
ISOLATION_VIOLATION (the buoy is presenting a credential bound to a
different tenant).

Side-effect: publishes a `{"kind": "buoy_heartbeat", "slug": ...,
"health": ...}` event on the SSE `fleet` channel so any subscribed UI
client repaints immediately (no polling lag for live transitions).

The dashboard read endpoint lives in dashboard.py as
`GET /api/v1/dashboard/buoy-fleet`.

Added 2026-05-15 — Buoy Heartbeat slice 1.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Header, Path, Query, Request
from pydantic import BaseModel, Field

from apps.octo import paths
from apps.octo.api import buoy_health
from apps.octo.api.auth_helpers import _extract_bearer
from apps.octo.api.errors import APIError
from apps.octo.api.event_stream import publish
from apps.octo.api.role_gates import ROLE_TIER, operator_max_tier, resolve_caller_scope
from apps.octo.api.routers.auth import session_identity, _audit_append
from apps.octo.api.routers.search import require_step_up
from apps.octo.auth import core as core_auth, sessions
from apps.octo.db import connect


router = APIRouter(prefix="/buoy", tags=["buoy"])


# ---------------------------------------------------------------------------
# Request / response shapes
# ---------------------------------------------------------------------------

class BuoyHeartbeatRequest(BaseModel):
    """Payload the buoy POSTs every INTERVAL_SEC seconds.

    Field nullability matches what /proc / systemctl can plausibly fail
    to produce. The buoy daemon best-effort populates each field; OCTO
    stores whatever was provided and treats nulls as "unknown for this
    cycle" (no validation).
    """
    slug: str = Field(min_length=1, max_length=64)
    hostname: str = Field(min_length=1, max_length=128)
    uptime_sec: int = Field(ge=0)
    interval_sec: int = Field(ge=10, le=3600, default=60)
    load_1: Optional[float] = None
    load_5: Optional[float] = None
    load_15: Optional[float] = None
    mem_used_mb: Optional[int] = None
    mem_total_mb: Optional[int] = None
    disk_used_pct: Optional[int] = Field(default=None, ge=0, le=100)
    services: dict[str, "str | dict[str, object]"] = Field(default_factory=dict)
    """Map of systemd unit → service info.

    Two shapes accepted for backward compat with pre-2026-05-19 daemons:
      - Legacy (slice 3): `{ unit: state_string }`
        e.g. `{ "tailscaled": "active" }`
      - Extended (heartbeat-services-contract-extension, 2026-05-19):
        `{ unit: { "state": "active", "version": "1.86.2",
                   "stat": "324 events/hr", "last_activity": "<iso>" } }`

    OCTO normalizes both into the dict-of-dicts shape before persisting.
    The dashboard read endpoint always emits the new shape so the
    frontend can ignore the legacy form entirely."""
    last_event_at: Optional[str] = None
    """ISO-8601 timestamp of the most recent successful event the
    buoy-forwarder relayed to OCTO. NULL on first heartbeat post-boot,
    or if the forwarder hasn't seen any events since the last cycle."""

    lat: Optional[float] = Field(default=None, ge=-90.0, le=90.0)
    lng: Optional[float] = Field(default=None, ge=-180.0, le=180.0)
    """Geographic coordinates for the Fleet map view (per the 2026-05-19
    fleet redesign). Optional — buoys without LAT/LNG configured in
    heartbeat.env continue to function normally; they just don't render
    on the map view. Migration 021 added the persistence columns."""


class BuoyPendingCommand(BaseModel):
    """One queued command the buoy should execute. Returned inline on
    the heartbeat response so the buoy needs no extra round-trip."""
    id: int
    command_kind: str
    args: dict[str, str] = Field(default_factory=dict)


class BuoyHeartbeatResponse(BaseModel):
    accepted: bool
    slug: str
    next_expected_by: str  # ISO-8601 — last_heartbeat + 2× interval
    pending_commands: list[BuoyPendingCommand] = Field(default_factory=list)
    """Commands queued for this buoy. Each transitions to 'dispatched'
    server-side when included in this response — the buoy is expected
    to execute + report via /command/{id}/result. Empty when none
    pending."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _iso_now() -> str:
    dt = datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _boot_time_from_uptime(uptime_sec: int) -> str:
    dt = datetime.now(timezone.utc) - timedelta(seconds=uptime_sec)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _normalize_services(raw: dict[str, object]) -> dict[str, dict[str, object]]:
    """Normalize the heartbeat `services` payload to the dict-of-dicts
    shape (heartbeat-services-contract-extension, 2026-05-19).

    Accepts both:
      - Legacy: `{ unit: "active" }`         → `{ unit: { "state": "active" } }`
      - New:    `{ unit: { "state": ..., "version": ..., ... } }` — passed through

    Drops unknown keys from the value dict (defensive; only allow the
    documented fields). Missing `state` defaults to "unknown"."""
    _ALLOWED = {"state", "enabled", "version", "stat", "last_activity"}
    out: dict[str, dict[str, object]] = {}
    for unit, v in raw.items():
        if isinstance(v, str):
            out[unit] = {"state": v}
        elif isinstance(v, dict):
            cleaned: dict[str, object] = {}
            for k, val in v.items():
                if k in _ALLOWED and val is not None:
                    cleaned[k] = val
            if "state" not in cleaned:
                cleaned["state"] = "unknown"
            out[unit] = cleaned
        else:
            # Unrecognized — coerce to unknown.
            out[unit] = {"state": "unknown"}
    return out


def _upsert_heartbeat(
    conn: sqlite3.Connection,
    *,
    slug: str,
    body: BuoyHeartbeatRequest,
    received_at: str,
) -> None:
    """UPSERT one row. INSERT...ON CONFLICT keeps created_at stable and
    bumps updated_at to received_at."""
    normalized = _normalize_services(body.services)
    services_json = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
    boot_time = _boot_time_from_uptime(body.uptime_sec)
    conn.execute(
        """
        INSERT INTO buoys (
            slug, hostname, last_heartbeat_at, boot_time,
            uptime_sec, interval_sec,
            load_1, load_5, load_15,
            mem_used_mb, mem_total_mb, disk_used_pct,
            services_json, last_event_at,
            lat, lng,
            created_at, updated_at
        ) VALUES (
            :slug, :hostname, :received_at, :boot_time,
            :uptime_sec, :interval_sec,
            :load_1, :load_5, :load_15,
            :mem_used_mb, :mem_total_mb, :disk_used_pct,
            :services_json, :last_event_at,
            :lat, :lng,
            :received_at, :received_at
        )
        ON CONFLICT(slug) DO UPDATE SET
            hostname          = excluded.hostname,
            last_heartbeat_at = excluded.last_heartbeat_at,
            boot_time         = excluded.boot_time,
            uptime_sec        = excluded.uptime_sec,
            interval_sec      = excluded.interval_sec,
            load_1            = excluded.load_1,
            load_5            = excluded.load_5,
            load_15           = excluded.load_15,
            mem_used_mb       = excluded.mem_used_mb,
            mem_total_mb      = excluded.mem_total_mb,
            disk_used_pct     = excluded.disk_used_pct,
            services_json     = excluded.services_json,
            last_event_at     = COALESCE(excluded.last_event_at, buoys.last_event_at),
            lat               = COALESCE(excluded.lat, buoys.lat),
            lng               = COALESCE(excluded.lng, buoys.lng),
            updated_at        = excluded.updated_at
        """,
        {
            "slug": slug,
            "hostname": body.hostname,
            "received_at": received_at,
            "boot_time": boot_time,
            "uptime_sec": body.uptime_sec,
            "interval_sec": body.interval_sec,
            "load_1": body.load_1,
            "load_5": body.load_5,
            "load_15": body.load_15,
            "mem_used_mb": body.mem_used_mb,
            "mem_total_mb": body.mem_total_mb,
            "disk_used_pct": body.disk_used_pct,
            "services_json": services_json,
            "last_event_at": body.last_event_at,
            "lat": body.lat,
            "lng": body.lng,
        },
    )
    conn.commit()


def _derive_health(services: dict[str, object]) -> str:
    """Roll up the services map into a single chip color for the UI —
    `apps.octo.api.buoy_health.rollup` (green / yellow / red / unknown; a
    unit disabled on purpose is retired, not a fault). Accepts both the
    legacy flat and the dict-of-dicts shape (the dict shape used to read
    as "red" here: a dict is never equal to "active"). Pure UI hint, not
    load-bearing for any auth decision."""
    return buoy_health.rollup(_normalize_services(services))


# ---------------------------------------------------------------------------
# POST /buoy/heartbeat
# ---------------------------------------------------------------------------

@router.post("/heartbeat", response_model=BuoyHeartbeatResponse)
async def buoy_heartbeat(
    body: BuoyHeartbeatRequest,
    request: Request,
    authorization: Optional[str] = Header(default=None),
) -> BuoyHeartbeatResponse:
    """Accept one heartbeat, upsert into buoys, publish SSE event."""
    token = _extract_bearer(authorization)
    reg = connect(paths.registry_db_path())
    try:
        try:
            resolution = core_auth.resolve_client_token(reg, token)
        except core_auth.AuthError:
            raise APIError("AUTH_INVALID")

        if resolution.slug != body.slug:
            # Bearer is bound to a different tenant than the body claims.
            # Buoy must present a token whose slug matches its own.
            raise APIError("ISOLATION_VIOLATION")

        received_at = _iso_now()
        _upsert_heartbeat(reg, slug=resolution.slug, body=body, received_at=received_at)

        # Note last-used (debounced — one write per token per 5 min, counted
        # from the last write; the same flush the ingest routes use).
        ip = request.client.host if request.client else None
        if core_auth.note_token_used(resolution.token_id, ip):
            try:
                core_auth.flush_last_used(reg)
            except sqlite3.OperationalError:
                # Older registry schemas may not have last_used_ip; best-effort.
                pass
    finally:
        reg.close()

    # Fire-and-forget SSE notification so any /fleet subscriber repaints
    # immediately. Errors here must NEVER fail the heartbeat — the row
    # is already persisted and the next cycle would re-emit anyway.
    try:
        await publish("fleet", {
            "kind": "buoy_heartbeat",
            "slug": body.slug,
            "hostname": body.hostname,
            "health": _derive_health(body.services),
            "received_at": received_at,
        })
    except Exception:
        pass

    # next_expected_by = now + 2× interval (matches the "yellow when
    # stale" threshold used by /dashboard/buoy-fleet).
    next_dt = datetime.now(timezone.utc) + timedelta(seconds=2 * body.interval_sec)
    next_iso = next_dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{next_dt.microsecond // 1000:03d}Z"

    # Fetch pending commands for this buoy and atomically flip them to
    # 'dispatched'. The buoy will execute + report via /command/{id}/result.
    pending = _fetch_and_dispatch_pending_commands(resolution.slug)

    return BuoyHeartbeatResponse(
        accepted=True,
        slug=resolution.slug,
        next_expected_by=next_iso,
        pending_commands=pending,
    )


# ===========================================================================
# Slice 7 — Buoy command queue
# ===========================================================================
#
# Operators queue commands at a buoy via POST /api/v1/buoy/:slug/command.
# Each command_kind has a minimum role tier (analyst+ / admin+ /
# super_admin) and step-up auth is required for every queue action.
# Commands are piggy-backed on the next heartbeat: the buoy daemon
# fetches `pending_commands` from the heartbeat response, executes them
# locally, and reports back via POST /api/v1/buoy/command/:id/result.
#
# Slug-scope is enforced at queue time (operator must have visibility
# into the slug) and again at result time (bearer's slug must match the
# command's slug — a buoy can't complete another tenant's command).

# Minimum role tier per command_kind. Server-side enforcement is the
# load-bearing check; UI mirrors this for affordance hiding only.
_COMMAND_MIN_ROLE: dict[str, str] = {
    "ping":             "analyst",
    "refresh":          "analyst",
    "tail-log":         "analyst",
    "restart-service":  "admin",
    "reboot":           "super_admin",
    "update":           "super_admin",
}

# Service-unit whitelist for restart-service / tail-log. Buoys MUST
# refuse units outside this list even if the queued command somehow
# contained an unfamiliar unit — defense in depth.
_ALLOWED_UNITS = frozenset({
    "tailscaled",
    "wazuh-agent",
    "opencanary",
    "suricata",
    "buoy-forwarder",
    "octo-forwarder",
    "pihole-FTL",
    "nextdns",
    "buoy-heartbeat",
})

# Queued command TTL — if a buoy hasn't picked it up in this window the
# command transitions to 'expired'. Five minutes lets a buoy survive a
# brief network blip without dropping operator intent on the floor.
_COMMAND_TTL_SEC = 300

# tail-log line cap. The buoy will tail at most this many lines into
# the result; UI displays the tail.
_TAIL_LOG_MAX_LINES = 500


# ---------------------------------------------------------------------------
# Request / response shapes
# ---------------------------------------------------------------------------

class BuoyCommandQueueRequest(BaseModel):
    command_kind: str = Field(min_length=1, max_length=32)
    args: dict[str, str] = Field(default_factory=dict)


class BuoyCommandQueueResponse(BaseModel):
    id: int
    slug: str
    command_kind: str
    status: str
    requested_at: str
    expires_at: str


class BuoyCommandResultRequest(BaseModel):
    """Buoy → OCTO. Reports completion or failure."""
    ok: bool
    exit_code: int = 0
    stdout_tail: str = Field(default="", max_length=64 * 1024)
    stderr_tail: str = Field(default="", max_length=64 * 1024)
    error: Optional[str] = None


class BuoyCommandHistoryRow(BaseModel):
    """One row in the per-slug command history (UI consumption)."""
    id: int
    slug: str
    command_kind: str
    args: dict[str, str]
    status: str
    requested_by: int
    requested_at: str
    dispatched_at: Optional[str]
    completed_at: Optional[str]
    expires_at: str
    result_ok: Optional[bool] = None
    result_exit_code: Optional[int] = None
    result_error: Optional[str] = None


class BuoyCommandHistoryResponse(BaseModel):
    commands: list[BuoyCommandHistoryRow]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resolve_caller_scope(operator_id: int) -> list[str]:
    """'*' → ['*']; otherwise the caller's concrete slugs, ACTIVE tenants
    only — the shared rule in `role_gates.resolve_caller_scope`. A viewer
    is a client user: once its tenant is offboarded, that tenant's buoys,
    their command history and notes are no longer its to see."""
    return resolve_caller_scope(operator_id)


def _operator_can_see_slug(operator_id: int, slug: str) -> bool:
    scope = _resolve_caller_scope(operator_id)
    return scope == ["*"] or slug in scope


def _validate_args(command_kind: str, args: dict[str, str]) -> dict[str, str]:
    """Per-command_kind arg validation. Reject bad shapes BEFORE queueing
    so the buoy never gets a malformed command. Returns a normalized
    dict (e.g. stripped unit name)."""
    if command_kind in ("ping", "refresh", "reboot", "update"):
        # No args expected — empty dict only.
        if args:
            raise APIError("VALIDATION_FAILED",
                           f"{command_kind} accepts no arguments")
        return {}
    if command_kind in ("restart-service", "tail-log"):
        unit = (args.get("unit") or "").strip()
        if not unit:
            raise APIError("VALIDATION_FAILED",
                           f"{command_kind} requires an 'unit' arg")
        if unit not in _ALLOWED_UNITS:
            raise APIError("VALIDATION_FAILED",
                           f"unit {unit!r} is not in the allowed-units list")
        out = {"unit": unit}
        if command_kind == "tail-log":
            try:
                n = int(args.get("lines", "200"))
            except ValueError:
                raise APIError("VALIDATION_FAILED",
                               "tail-log 'lines' must be an integer")
            if n < 1 or n > _TAIL_LOG_MAX_LINES:
                raise APIError("VALIDATION_FAILED",
                               f"tail-log 'lines' must be 1..{_TAIL_LOG_MAX_LINES}")
            out["lines"] = str(n)
        return out
    raise APIError("VALIDATION_FAILED", f"unknown command_kind {command_kind!r}")


def _fetch_and_dispatch_pending_commands(slug: str) -> list[BuoyPendingCommand]:
    """Called inside the heartbeat handler. Returns commands queued for
    this slug AND atomically flips them to 'dispatched' so a network
    blip on the result-report side doesn't re-deliver the same command
    to the buoy on the next cycle.

    Expired commands are reaped here too (transition queued → expired
    when expires_at has passed). The buoy never sees expired ones.
    """
    reg = connect(paths.registry_db_path())
    try:
        now = _iso_now()
        # Reap any expired-while-queued commands first. Operator gets
        # to see them in the history with status='expired' — useful
        # signal that the buoy was offline when intent was issued.
        reg.execute(
            "UPDATE buoy_commands SET status='expired' "
            " WHERE slug = ? AND status = 'queued' AND expires_at <= ?",
            (slug, now),
        )
        rows = reg.execute(
            "SELECT id, command_kind, args_json FROM buoy_commands "
            " WHERE slug = ? AND status = 'queued' "
            " ORDER BY requested_at ASC LIMIT 20",
            (slug,),
        ).fetchall()
        out: list[BuoyPendingCommand] = []
        for r in rows:
            try:
                args = json.loads(r["args_json"]) if r["args_json"] else {}
                if not isinstance(args, dict):
                    args = {}
            except (json.JSONDecodeError, TypeError):
                args = {}
            out.append(BuoyPendingCommand(
                id=r["id"],
                command_kind=r["command_kind"],
                args={k: str(v) for k, v in args.items()},
            ))
        if out:
            ids = [r["id"] for r in rows]
            placeholders = ",".join("?" * len(ids))
            reg.execute(
                f"UPDATE buoy_commands SET status='dispatched', "
                f"  dispatched_at = ? "
                f" WHERE id IN ({placeholders})",
                (now, *ids),
            )
        reg.commit()
        return out
    except sqlite3.OperationalError:
        # buoy_commands table may not exist if migration 019 hasn't been
        # applied yet — pre-slice-7 deployments. Return empty list so
        # heartbeat still succeeds.
        return []
    finally:
        reg.close()


# ---------------------------------------------------------------------------
# POST /buoy/{slug}/command — operator queues a command
# ---------------------------------------------------------------------------

@router.post("/{slug}/command", response_model=BuoyCommandQueueResponse)
def queue_command(
    body: BuoyCommandQueueRequest,
    request: Request,
    slug: str = Path(min_length=1, max_length=64),
    info: sessions.SessionInfo = Depends(require_step_up),
) -> BuoyCommandQueueResponse:
    # 1. command_kind must be known
    min_role = _COMMAND_MIN_ROLE.get(body.command_kind)
    if min_role is None:
        raise APIError("VALIDATION_FAILED",
                       f"unknown command_kind {body.command_kind!r}")

    # 2. role tier check
    required_tier = ROLE_TIER[min_role]
    if operator_max_tier(info.operator_id) < required_tier:
        raise APIError(
            "ISOLATION_VIOLATION",
            f"{body.command_kind!r} requires at least {min_role!r}",
        )

    # 3. scope check — operator must see this slug
    if not _operator_can_see_slug(info.operator_id, slug):
        raise APIError("ISOLATION_VIOLATION")

    # 4. arg validation (per-kind whitelist)
    args = _validate_args(body.command_kind, body.args)

    # 5. insert + audit
    request_id = str(uuid.uuid4())
    now = _iso_now()
    expires_dt = datetime.now(timezone.utc) + timedelta(seconds=_COMMAND_TTL_SEC)
    expires_at = expires_dt.strftime("%Y-%m-%dT%H:%M:%S.") + \
                 f"{expires_dt.microsecond // 1000:03d}Z"

    reg = connect(paths.registry_db_path())
    try:
        cur = reg.execute(
            "INSERT INTO buoy_commands "
            "  (slug, command_kind, args_json, status, requested_by, "
            "   requested_at, expires_at, audit_request_id) "
            "VALUES (?, ?, ?, 'queued', ?, ?, ?, ?)",
            (slug, body.command_kind, json.dumps(args, sort_keys=True),
             info.operator_id, now, expires_at, request_id),
        )
        reg.commit()
        cmd_id = cur.lastrowid
    finally:
        reg.close()

    ip = request.client.host if request.client else None
    _audit_append(
        "buoy.command_queued",
        actor=f"operator:{info.operator_id}",
        target_id=f"{slug}:{cmd_id}",
        before=None,
        after={
            "slug": slug,
            "command_kind": body.command_kind,
            "args": args,
            "min_role": min_role,
            "ip": ip,
        },
        reason="operator queued buoy command",
        request_id=request_id,
    )

    return BuoyCommandQueueResponse(
        id=cmd_id,
        slug=slug,
        command_kind=body.command_kind,
        status="queued",
        requested_at=now,
        expires_at=expires_at,
    )


# ---------------------------------------------------------------------------
# POST /buoy/command/{cmd_id}/result — buoy reports completion
# ---------------------------------------------------------------------------

@router.post("/command/{cmd_id}/result")
def report_command_result(
    body: BuoyCommandResultRequest,
    cmd_id: int = Path(ge=1),
    authorization: Optional[str] = Header(default=None),
) -> dict:
    token = _extract_bearer(authorization)
    reg = connect(paths.registry_db_path())
    try:
        try:
            resolution = core_auth.resolve_client_token(reg, token)
        except core_auth.AuthError:
            raise APIError("AUTH_INVALID")

        row = reg.execute(
            "SELECT id, slug, status FROM buoy_commands WHERE id = ?",
            (cmd_id,),
        ).fetchone()
        if row is None:
            raise APIError("NOT_FOUND")
        if row["slug"] != resolution.slug:
            # A buoy can complete only its own commands.
            raise APIError("ISOLATION_VIOLATION")
        if row["status"] not in ("dispatched", "queued"):
            # Already completed / failed / expired — no-op (idempotent).
            return {"accepted": True, "noop": True}

        result_payload = {
            "ok": body.ok,
            "exit_code": body.exit_code,
            "stdout_tail": body.stdout_tail,
            "stderr_tail": body.stderr_tail,
            "error": body.error,
        }
        new_status = "completed" if body.ok else "failed"
        now = _iso_now()
        reg.execute(
            "UPDATE buoy_commands SET status = ?, completed_at = ?, "
            "  result_json = ? WHERE id = ?",
            (new_status, now, json.dumps(result_payload), cmd_id),
        )
        reg.commit()
    finally:
        reg.close()
    return {"accepted": True, "status": new_status}


# ---------------------------------------------------------------------------
# GET /buoy/{slug}/commands — operator sees command history for a buoy
# ---------------------------------------------------------------------------

@router.get("/{slug}/commands", response_model=BuoyCommandHistoryResponse)
def list_commands(
    slug: str = Path(min_length=1, max_length=64),
    limit: int = Query(default=50, ge=1, le=200),
    info: sessions.SessionInfo = Depends(session_identity),
) -> BuoyCommandHistoryResponse:
    # viewer+ scope check — viewers can see their own buoy's command
    # history, which is read-only and doesn't reveal cross-tenant data.
    if not _operator_can_see_slug(info.operator_id, slug):
        raise APIError("ISOLATION_VIOLATION")

    reg = connect(paths.registry_db_path(), read_only=True)
    reg.row_factory = sqlite3.Row
    try:
        rows = reg.execute(
            "SELECT id, slug, command_kind, args_json, status, "
            "  requested_by, requested_at, dispatched_at, completed_at, "
            "  expires_at, result_json "
            "FROM buoy_commands WHERE slug = ? "
            "ORDER BY requested_at DESC LIMIT ?",
            (slug, limit),
        ).fetchall()
    except sqlite3.OperationalError:
        # Pre-migration-019 — table missing. Return empty.
        return BuoyCommandHistoryResponse(commands=[])
    finally:
        reg.close()

    out: list[BuoyCommandHistoryRow] = []
    for r in rows:
        try:
            args = json.loads(r["args_json"]) if r["args_json"] else {}
            if not isinstance(args, dict):
                args = {}
        except (json.JSONDecodeError, TypeError):
            args = {}
        result_ok: Optional[bool] = None
        result_exit: Optional[int] = None
        result_error: Optional[str] = None
        if r["result_json"]:
            try:
                rj = json.loads(r["result_json"])
                if isinstance(rj, dict):
                    result_ok = rj.get("ok")
                    result_exit = rj.get("exit_code")
                    result_error = rj.get("error")
            except (json.JSONDecodeError, TypeError):
                pass
        out.append(BuoyCommandHistoryRow(
            id=r["id"], slug=r["slug"],
            command_kind=r["command_kind"],
            args={k: str(v) for k, v in args.items()},
            status=r["status"],
            requested_by=r["requested_by"],
            requested_at=r["requested_at"],
            dispatched_at=r["dispatched_at"],
            completed_at=r["completed_at"],
            expires_at=r["expires_at"],
            result_ok=result_ok,
            result_exit_code=result_exit,
            result_error=result_error,
        ))
    return BuoyCommandHistoryResponse(commands=out)
