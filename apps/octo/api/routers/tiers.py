"""Tier rules, the Yellow knobs, the storm brake and the threat registries
(Tier Black slice 1; design 6.7).

  GET  /api/v1/tiers/rules                         analyst+ — rule ids, versions,
                                                   stage, kind, inputs and per-tenant
                                                   coverage (scoped). NO PUT: a rule is
                                                   code; promotion is a release.
  GET  /api/v1/admin/tiers/yellow?scope=msp|<slug> admin+ — the Yellow / Notice knobs
  PUT  /api/v1/admin/tiers/yellow                  admin+, audited BEFORE the write;
                                                   bounded — no value can name Red or
                                                   Black
  GET  /api/v1/admin/tiers/restricted              admin+ — the restricted-incident (B7,
                                                   CSAM) client-notice switch (OFF)
  PUT  /api/v1/admin/tiers/restricted              admin+ with an all-tenant scope,
                                                   audited BEFORE the write, the other
                                                   admins told
  GET  /api/v1/admin/tiers/brake                   admin+ — live and recent brakes
  POST /api/v1/admin/tiers/brake                   super_admin + step-up: one automated
                                                   rule held at a Red ceiling ≤ 24 h
  POST /api/v1/admin/tiers/brake/{id}/release      super_admin + step-up
  GET  /api/v1/admin/registry/asset-tags?tenant=   analyst+ (scoped)
  POST /api/v1/admin/registry/asset-tags           life_safety and the other
                                                   response-only caps: analyst+;
                                                   detection-suppressing tags (lab,
                                                   evidence_hold, dev, kiosk,
                                                   hands_off): admin+. Audited BEFORE
                                                   the write; every tag tells the
                                                   other admins. A life_safety tag
                                                   names a host or an address (a
                                                   path: an address or a network).
  POST /api/v1/admin/registry/asset-tags/{id}/clear admin+ (it removes a protection)
  GET  /api/v1/admin/registry/exceptions           admin+ (read)
  POST /api/v1/admin/registry/exceptions           super_admin + step-up, ≤ 90 d
  POST /api/v1/admin/registry/exceptions/{id}/revoke super_admin + step-up
  GET  /api/v1/admin/registry/verdicts             admin+ (read; written by a
                                                   false-positive close)
  GET  /api/v1/admin/registry/remote-access        admin+ (read view; credential-class:
                                                   never in a client payload)
  GET  /api/v1/admin/registry/canary-allowlist     admin+
  POST /api/v1/admin/registry/canary-allowlist     admin+, audited (R6's N15
                                                   precondition)

Every edit is audited before it is written, with a reason, and an edit that
does not happen after its row appends `<action>_failed` (`_write`). EVERY edit
of the tables that can suppress or bound a tier tells the other admins
(design 6.7): an asset tag set or cleared (`life_safety` included — it makes
an asset immune from every lockdown), an exception created or revoked, the
canary allowlist, the brake set or released. The notice id carries the row id
(`tag:<id>:set|clear`), so clearing and setting a tag again tells them again.
The e-mail copy is fixed and neutral (`notify.notify_admins`).
"""
from __future__ import annotations

import ipaddress
import logging
import sqlite3
from datetime import datetime, timezone
from typing import Any, Callable, Literal, Optional, TypeVar

from fastapi import APIRouter, Depends, Path, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from apps.octo import paths
from apps.octo.api.errors import APIError
from apps.octo.api.models import AuditReason
from apps.octo.api.role_gates import (
    ROLE_TIER,
    operator_max_tier,
    resolve_caller_scope,
    session_admin_plus,
    session_analyst_plus,
)
from apps.octo.auth import sessions
from apps.octo.db import connect, transaction
from apps.octo.fleet import build, sources
from apps.octo.threat import audit as taudit
from apps.octo.threat import brake, coverage, notify, registry, rules

logger = logging.getLogger(__name__)

router = APIRouter(tags=["tiers"])

_SLUG = r"^[a-z0-9]+(?:-[a-z0-9]+)*$"


def _in_scope(scope: list[str], slug: str) -> bool:
    return scope == ["*"] or slug in scope


def _active() -> dict[str, str]:
    try:
        return {s: t.name for s, t in sources.tenants().items()}
    except sqlite3.Error:
        return {}


def _scoped(info: sessions.SessionInfo, slug: str) -> str:
    if slug not in _active() or not _in_scope(resolve_caller_scope(info.operator_id), slug):
        raise APIError("NOT_FOUND", "no such tenant in your scope")
    return slug


def _super(info: sessions.SessionInfo) -> None:
    if operator_max_tier(info.operator_id) < ROLE_TIER["super_admin"]:
        raise APIError("ISOLATION_VIOLATION", "this action requires a super_admin")


def _step_up(request: Request, info: sessions.SessionInfo) -> None:
    from apps.octo.api.routers.search import require_step_up

    require_step_up(request, info)


def _audit(info: sessions.SessionInfo, action: str, slug: str, kind: str,
           target: Optional[str], *, before: Any = None, after: Any = None,
           reason: Optional[str] = None) -> None:
    taudit.human(info.operator_id, action, slug, kind, target, before=before, after=after,
                 reason=reason)


T = TypeVar("T")


def _write(info: sessions.SessionInfo, action: str, slug: str, kind: str,
           target: Optional[str], fn: Callable[[sqlite3.Connection], T]) -> T:
    """The registry write the row above audited, in one transaction. If it
    does not happen — whatever the reason — `<action>_failed` says so (the
    error class only), then the error goes on to the caller."""
    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            return fn(reg)
    except BaseException as exc:
        try:
            _audit(info, f"{action}_failed", slug, kind, target,
                   after={"error": type(exc).__name__},
                   reason=f"the recorded {action} was not written: {type(exc).__name__}")
        except Exception:  # noqa: BLE001 — the audit log itself is failing
            logger.error("[tiers] %s_failed could not be audited", action)
        raise
    finally:
        reg.close()


# ---------------------------------------------------------------------------
# Rules (read only — there is no PUT)
# ---------------------------------------------------------------------------

class RuleOut(BaseModel):
    id: str
    version: int
    tier: str
    stage: str
    kind: str
    title: str
    inputs: list[str]
    description: str
    braked_until: Optional[str] = None
    coverage: dict[str, dict[str, Any]] = Field(default_factory=dict)
    """tenant slug → {covered, missing} (the caller's scope)."""
    restricted: bool = False
    """A restricted rule (B7, CSAM): admin-only incidents, never braked."""


class RulesResponse(BaseModel):
    rules: list[RuleOut]


@router.get("/tiers/rules", response_model=RulesResponse)
def list_rules(
    response: Response,
    info: sessions.SessionInfo = Depends(session_analyst_plus),
) -> RulesResponse:
    response.headers["Cache-Control"] = "no-store"
    scope = resolve_caller_scope(info.operator_id)
    tenants = [s for s in sorted(_active()) if _in_scope(scope, s)]
    cov = {s: coverage.tenant_coverage(s) for s in tenants}
    live = {b.rule_id: b.expires_at for b in brake.brakes()}
    return RulesResponse(rules=[RuleOut(
        id=r.id, version=r.version, tier=r.tier, stage=r.stage, kind=r.kind, title=r.title,
        inputs=list(r.inputs), description=r.description, braked_until=live.get(r.id),
        coverage={s: cov[s][r.id].as_dict() for s in tenants if r.id in cov[s]},
        restricted=r.restricted,
    ) for r in rules.RULES.values()])


# ---------------------------------------------------------------------------
# Yellow / Notice knobs
# ---------------------------------------------------------------------------

class KnobsResponse(BaseModel):
    scope: str
    stored: dict[str, Any]
    effective: dict[str, Any]
    knobs: list[dict[str, Any]]


class KnobsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scope: str = Field(default="msp", min_length=1, max_length=64)
    values: dict[str, Any]
    reason: AuditReason


def _knobs(scope: str) -> KnobsResponse:
    return KnobsResponse(
        scope=scope, stored=registry.stored_settings(scope),
        effective=registry.settings(None if scope == "msp" else scope),
        knobs=[{"key": k.key, "default": k.default, "choices": list(k.choices or []),
                "low": k.low, "high": k.high, "help": k.help} for k in registry.KNOBS.values()])


@router.get("/admin/tiers/yellow", response_model=KnobsResponse)
def get_knobs(
    response: Response,
    scope: str = Query(default="msp", min_length=1, max_length=64),
    info: sessions.SessionInfo = Depends(session_admin_plus),
) -> KnobsResponse:
    response.headers["Cache-Control"] = "no-store"
    if scope != "msp":
        _scoped(info, scope)
    return _knobs(scope)


@router.put("/admin/tiers/yellow", response_model=KnobsResponse)
def put_knobs(
    body: KnobsIn,
    info: sessions.SessionInfo = Depends(session_admin_plus),
) -> KnobsResponse:
    if body.scope != "msp":
        _scoped(info, body.scope)
    elif resolve_caller_scope(info.operator_id) != ["*"]:
        raise APIError("ISOLATION_VIOLATION", "the MSP-wide knobs need an all-tenant scope")
    for key, value in body.values.items():
        if key not in registry.KNOBS:
            raise APIError("VALIDATION_FAILED", f"unknown setting {key!r}")
        try:
            registry.KNOBS[key].valid(value)
        except ValueError as exc:
            raise APIError("VALIDATION_FAILED", str(exc)) from None
    before = registry.stored_settings(body.scope)
    where = body.scope if body.scope != "msp" else "global"
    _audit(info, "tier_settings.update", where, "tier_settings", body.scope, before=before,
           after=body.values, reason=body.reason)
    try:
        _write(info, "tier_settings.update", where, "tier_settings", body.scope,
               lambda reg: registry.put_settings(reg, body.scope, body.values,
                                                 by=info.operator_id))
    except sqlite3.Error:
        raise APIError("SERVICE_UNAVAILABLE", "the settings could not be written") from None
    build.invalidate()
    return _knobs(body.scope)


# ---------------------------------------------------------------------------
# Restricted incidents (B7, CSAM) — the MSP's client-notice switch
# ---------------------------------------------------------------------------

class RestrictedSettingsResponse(BaseModel):
    csam_client_notice: bool
    """Rick, 2026-10-06 (B6): may a client user read the neutral 60-minute
    line of a restricted (CSAM) incident? OFF by default: suppressed."""
    help: str


class RestrictedSettingsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    csam_client_notice: bool
    reason: AuditReason


_RESTRICTED_HELP = ("Restricted (CSAM) incidents: show the client the neutral 'urgent "
                    "security incident' line after acknowledgement or 60 minutes. Off by "
                    "default — the client sees nothing; they are never offered an action.")


@router.get("/admin/tiers/restricted", response_model=RestrictedSettingsResponse)
def get_restricted(
    response: Response,
    info: sessions.SessionInfo = Depends(session_admin_plus),
) -> RestrictedSettingsResponse:
    response.headers["Cache-Control"] = "no-store"
    return RestrictedSettingsResponse(csam_client_notice=registry.csam_client_notice(),
                                      help=_RESTRICTED_HELP)


@router.put("/admin/tiers/restricted", response_model=RestrictedSettingsResponse)
def put_restricted(
    body: RestrictedSettingsIn,
    info: sessions.SessionInfo = Depends(session_admin_plus),
) -> RestrictedSettingsResponse:
    """admin+ with an all-tenant scope (an MSP-wide switch), audited BEFORE
    the write, the other admins told."""
    if resolve_caller_scope(info.operator_id) != ["*"]:
        raise APIError("ISOLATION_VIOLATION", "the MSP-wide switch needs an all-tenant scope")
    before = {registry.CSAM_CLIENT_NOTICE: registry.csam_client_notice()}
    after = {registry.CSAM_CLIENT_NOTICE: body.csam_client_notice}
    _audit(info, "tier_settings.restricted_update", "global", "tier_settings", "msp",
           before=before, after=after, reason=body.reason)
    try:
        _write(info, "tier_settings.restricted_update", "global", "tier_settings", "msp",
               lambda reg: registry.put_restricted(reg, after, by=info.operator_id))
    except sqlite3.Error:
        raise APIError("SERVICE_UNAVAILABLE", "the setting could not be written") from None
    state = "ON (the client sees the neutral line)" if body.csam_client_notice \
        else "OFF (suppressed)"
    notify.notify_admins(
        kind="threat_registry", exclude=info.operator_id,
        title=f"Restricted-incident client notice turned {state}",
        body=f"Operator #{info.operator_id} set the client notice for restricted (CSAM) "
             f"incidents to {state}: {body.reason}",
        request_id=f"restricted-notice:{body.csam_client_notice}:{info.operator_id}:"
                   f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}")
    build.invalidate()
    return RestrictedSettingsResponse(csam_client_notice=registry.csam_client_notice(),
                                      help=_RESTRICTED_HELP)


# ---------------------------------------------------------------------------
# The storm brake
# ---------------------------------------------------------------------------

class BrakeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rule_id: str = Field(min_length=1, max_length=16)
    hours: float = Field(gt=0, le=brake.MAX_HOURS)
    reason: AuditReason


class BrakeReleaseIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: AuditReason


class BrakesResponse(BaseModel):
    brakes: list[dict[str, Any]]


@router.get("/admin/tiers/brake", response_model=BrakesResponse)
def list_brakes(
    response: Response,
    _info: sessions.SessionInfo = Depends(session_admin_plus),
) -> BrakesResponse:
    response.headers["Cache-Control"] = "no-store"
    return BrakesResponse(brakes=[b.as_dict() for b in brake.brakes(live_only=False)])


@router.post("/admin/tiers/brake", response_model=BrakesResponse)
def set_brake(
    body: BrakeIn,
    request: Request,
    info: sessions.SessionInfo = Depends(session_admin_plus),
) -> BrakesResponse:
    _super(info)
    try:
        brake.validate(body.rule_id, body.hours)
    except brake.BrakeError as exc:
        raise APIError("VALIDATION_FAILED", str(exc)) from None
    if brake.live_brake(body.rule_id) is not None:
        raise APIError("CONFLICT", f"{body.rule_id} is already braked")
    _step_up(request, info)
    _audit(info, "rule.brake", "global", "rule", body.rule_id,
           after={"rule": body.rule_id, "ceiling": "red", "hours": body.hours},
           reason=body.reason)
    try:
        bid = _write(info, "rule.brake", "global", "rule", body.rule_id,
                     lambda reg: brake.set_brake(reg, body.rule_id, by=info.operator_id,
                                                 reason=body.reason, hours=body.hours))
    except (brake.BrakeError, sqlite3.IntegrityError) as exc:
        raise APIError("CONFLICT", str(exc)) from None
    except sqlite3.Error:
        raise APIError("SERVICE_UNAVAILABLE", "the brake could not be written") from None
    notify.notify_admins(kind="threat_registry", exclude=info.operator_id,
                         title=f"Storm brake: {body.rule_id} held at Red for {body.hours:g} h",
                         body=f"Operator #{info.operator_id} braked {body.rule_id} (existing "
                              f"Blacks untouched; it expires on its own): {body.reason}",
                         request_id=f"brake:{bid}")
    return BrakesResponse(brakes=[b.as_dict() for b in brake.brakes(live_only=False)])


@router.post("/admin/tiers/brake/{brake_id}/release", response_model=BrakesResponse)
def release_brake(
    body: BrakeReleaseIn,
    request: Request,
    brake_id: int = Path(..., ge=1),
    info: sessions.SessionInfo = Depends(session_admin_plus),
) -> BrakesResponse:
    _super(info)
    if not any(b.id == brake_id for b in brake.brakes()):
        raise APIError("NOT_FOUND", "no live brake with that id")
    _step_up(request, info)
    _audit(info, "rule.brake_release", "global", "rule_brake", str(brake_id),
           reason=body.reason)

    def release(reg: sqlite3.Connection) -> None:
        if not brake.release(reg, brake_id, by=info.operator_id):
            raise APIError("NOT_FOUND", "no live brake with that id")

    try:
        _write(info, "rule.brake_release", "global", "rule_brake", str(brake_id), release)
    except sqlite3.Error:
        raise APIError("SERVICE_UNAVAILABLE", "the brake could not be released") from None
    notify.notify_admins(kind="threat_registry", exclude=info.operator_id,
                         title=f"Storm brake #{brake_id} released",
                         body=f"Operator #{info.operator_id} released brake #{brake_id}: "
                              f"{body.reason}",
                         request_id=f"brake:{brake_id}:release")
    return BrakesResponse(brakes=[b.as_dict() for b in brake.brakes(live_only=False)])


# ---------------------------------------------------------------------------
# Asset tags (life-safety first)
# ---------------------------------------------------------------------------

class TagIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant: str = Field(min_length=1, max_length=64, pattern=_SLUG)
    ref_kind: Literal["device", "path"] = "device"
    device_ref: str = Field(min_length=1, max_length=200)
    tag: Literal["lab", "evidence_hold", "dev", "kiosk", "hands_off", "server", "dc", "cjis",
                 "life_safety", "patient_care", "critical_24x7"]
    reason: AuditReason


class TagClearIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: AuditReason


class TagsResponse(BaseModel):
    tags: list[dict[str, Any]]


@router.get("/admin/registry/asset-tags", response_model=TagsResponse)
def list_tags(
    response: Response,
    tenant: Optional[str] = Query(default=None, max_length=64),
    info: sessions.SessionInfo = Depends(session_analyst_plus),
) -> TagsResponse:
    response.headers["Cache-Control"] = "no-store"
    scope = resolve_caller_scope(info.operator_id)
    if tenant is not None:
        _scoped(info, tenant)
    return TagsResponse(tags=[t.as_dict() for t in registry.asset_tags(tenant)
                              if _in_scope(scope, t.tenant_slug)])


@router.post("/admin/registry/asset-tags", response_model=TagsResponse)
def add_tag(
    body: TagIn,
    info: sessions.SessionInfo = Depends(session_analyst_plus),
) -> TagsResponse:
    """life_safety (and the other response-only caps) — analyst+: a
    protective tag never hides a detection. Tags that change detection —
    admin+, and the other admins are told."""
    _scoped(info, body.tenant)
    suppressive = body.tag in registry.SUPPRESSIVE_TAGS
    if suppressive and operator_max_tier(info.operator_id) < ROLE_TIER["admin"]:
        raise APIError("ISOLATION_VIOLATION", f"the '{body.tag}' tag changes detection: it "
                                              "needs an admin")
    try:
        registry.validate_tag(ref_kind=body.ref_kind, device_ref=body.device_ref, tag=body.tag)
    except ValueError as exc:
        raise APIError("VALIDATION_FAILED", str(exc)) from None
    after = {"ref_kind": body.ref_kind, "device_ref": body.device_ref, "tag": body.tag}
    _audit(info, "asset_tag.update", body.tenant, "asset_tag", body.device_ref,
           after={"set": after}, reason=body.reason)
    try:
        tag_id = _write(info, "asset_tag.update", body.tenant, "asset_tag", body.device_ref,
                        lambda reg: registry.add_tag(
                            reg, slug=body.tenant, ref_kind=body.ref_kind,
                            device_ref=body.device_ref, tag=body.tag,
                            set_by=info.operator_id, reason=body.reason))
    except sqlite3.IntegrityError:
        raise APIError("CONFLICT", "that asset already carries this tag") from None
    except sqlite3.Error:
        raise APIError("SERVICE_UNAVAILABLE", "the tag could not be written") from None
    # Every tag edit tells the other admins (design 6.7): a suppressive tag
    # changes what detection does; `life_safety` (and the other response
    # caps) make an asset immune from every lockdown — on an attacker-held
    # host too, so a second pair of eyes sees it.
    what = ("it changes what detection does there" if suppressive else
            "it is carved out of every lockdown request" if body.tag == registry.LIFE_SAFETY
            else "it caps what any response may do there")
    notify.notify_admins(kind="threat_registry", slug=body.tenant, exclude=info.operator_id,
                         title=f"Asset tag '{body.tag}' set on {body.device_ref}",
                         body=f"Operator #{info.operator_id} tagged {body.device_ref} at "
                              f"{body.tenant} '{body.tag}' ({what}): {body.reason}",
                         request_id=f"tag:{tag_id}:set")
    build.invalidate()
    return TagsResponse(tags=[t.as_dict() for t in registry.asset_tags(body.tenant)])


@router.post("/admin/registry/asset-tags/{tag_id}/clear", response_model=TagsResponse)
def clear_tag(
    body: TagClearIn,
    tag_id: int = Path(..., ge=1),
    info: sessions.SessionInfo = Depends(session_admin_plus),
) -> TagsResponse:
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        row = registry.get_tag(reg, tag_id)
    finally:
        reg.close()
    if row is None or row["cleared_at"] is not None:
        raise APIError("NOT_FOUND", "no such live tag in your scope")
    slug = row["tenant_slug"]
    _scoped(info, slug)
    _audit(info, "asset_tag.update", slug, "asset_tag", row["device_ref"],
           before={"tag": row["tag"], "device_ref": row["device_ref"]},
           after={"cleared": tag_id}, reason=body.reason)

    def clear(conn: sqlite3.Connection) -> None:
        if not registry.clear_tag(conn, tag_id, by=info.operator_id, reason=body.reason):
            raise APIError("NOT_FOUND", "no such live tag in your scope")

    try:
        _write(info, "asset_tag.update", slug, "asset_tag", row["device_ref"], clear)
    except sqlite3.Error:
        raise APIError("SERVICE_UNAVAILABLE", "the tag could not be cleared") from None
    # Clearing removes a protection (a life-safety carve-out, a response
    # cap) or a suppression: the other admins are told either way.
    notify.notify_admins(kind="threat_registry", slug=slug, exclude=info.operator_id,
                         title=f"Asset tag '{row['tag']}' CLEARED on {row['device_ref']}",
                         body=f"Operator #{info.operator_id} cleared '{row['tag']}' on "
                              f"{row['device_ref']} at {slug}: {body.reason}",
                         request_id=f"tag:{tag_id}:clear")
    build.invalidate()
    return TagsResponse(tags=[t.as_dict() for t in registry.asset_tags(slug)])


# ---------------------------------------------------------------------------
# Exceptions, verdicts, the remote-access registry, the canary allowlist
# ---------------------------------------------------------------------------

class RowsResponse(BaseModel):
    rows: list[dict[str, Any]]


def _rows(table: str, info: sessions.SessionInfo, tenant: Optional[str]) -> RowsResponse:
    scope = resolve_caller_scope(info.operator_id)
    if tenant is not None:
        _scoped(info, tenant)
    found = registry.rows(table, slug=tenant)
    return RowsResponse(rows=[r for r in found if r.get("tenant_slug") == "*"
                              or _in_scope(scope, str(r.get("tenant_slug")))])


@router.get("/admin/registry/exceptions", response_model=RowsResponse)
def list_exceptions(
    response: Response,
    tenant: Optional[str] = Query(default=None, max_length=64),
    info: sessions.SessionInfo = Depends(session_admin_plus),
) -> RowsResponse:
    response.headers["Cache-Control"] = "no-store"
    return _rows("threat_exception", info, tenant)


class ExceptionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant: str = Field(min_length=1, max_length=64, pattern=_SLUG)
    binding_kind: Literal["path_prefix", "product_instance", "signature"]
    binding: str = Field(min_length=1, max_length=300)
    rule_id: str = Field(min_length=1, max_length=16)
    days: int = Field(ge=1, le=registry.EXCEPTION_MAX_DAYS)
    reason: AuditReason


class RevokeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: AuditReason


@router.post("/admin/registry/exceptions", response_model=RowsResponse)
def add_exception(
    body: ExceptionIn,
    request: Request,
    info: sessions.SessionInfo = Depends(session_admin_plus),
) -> RowsResponse:
    _super(info)
    _scoped(info, body.tenant)
    if rules.rule(body.rule_id) is None:
        raise APIError("VALIDATION_FAILED", f"no rule {body.rule_id!r}")
    _step_up(request, info)
    after = body.model_dump(exclude={"reason"})
    _audit(info, "exception.create", body.tenant, "threat_exception", body.binding,
           after=after, reason=body.reason)
    try:
        eid = _write(info, "exception.create", body.tenant, "threat_exception", body.binding,
                     lambda reg: registry.add_exception(
                         reg, slug=body.tenant, binding_kind=body.binding_kind,
                         binding=body.binding, rule_id=body.rule_id, reason=body.reason,
                         by=info.operator_id, days=body.days))
    except ValueError as exc:
        raise APIError("VALIDATION_FAILED", str(exc)) from None
    except sqlite3.Error:
        raise APIError("SERVICE_UNAVAILABLE", "the exception could not be written") from None
    notify.notify_admins(kind="threat_registry", slug=body.tenant, exclude=info.operator_id,
                         title=f"Exception for {body.rule_id} at {body.tenant} "
                               f"({body.days} d)",
                         body=f"Operator #{info.operator_id}: {body.binding_kind} "
                              f"'{body.binding}' — {body.reason}",
                         request_id=f"exception:{eid}")
    return _rows("threat_exception", info, body.tenant)


@router.post("/admin/registry/exceptions/{exc_id}/revoke", response_model=RowsResponse)
def revoke_exception(
    body: RevokeIn,
    request: Request,
    exc_id: int = Path(..., ge=1),
    info: sessions.SessionInfo = Depends(session_admin_plus),
) -> RowsResponse:
    _super(info)
    row = next((r for r in registry.rows("threat_exception") if r["id"] == exc_id), None)
    if row is None or row.get("revoked_at"):
        raise APIError("NOT_FOUND", "no such live exception in your scope")
    _scoped(info, row["tenant_slug"])
    _step_up(request, info)
    _audit(info, "exception.revoke", row["tenant_slug"], "threat_exception", str(exc_id),
           reason=body.reason)

    def revoke(reg: sqlite3.Connection) -> None:
        if not registry.revoke_exception(reg, exc_id, by=info.operator_id, reason=body.reason):
            raise APIError("NOT_FOUND", "no such live exception in your scope")

    try:
        _write(info, "exception.revoke", row["tenant_slug"], "threat_exception", str(exc_id),
               revoke)
    except sqlite3.Error:
        raise APIError("SERVICE_UNAVAILABLE", "the exception could not be revoked") from None
    notify.notify_admins(kind="threat_registry", slug=row["tenant_slug"],
                         exclude=info.operator_id,
                         title=f"Exception #{exc_id} for {row['rule_id']} at "
                               f"{row['tenant_slug']} revoked",
                         body=f"Operator #{info.operator_id} revoked exception #{exc_id}: "
                              f"{body.reason}",
                         request_id=f"exception:{exc_id}:revoke")
    return _rows("threat_exception", info, row["tenant_slug"])


@router.get("/admin/registry/verdicts", response_model=RowsResponse)
def list_verdicts(
    response: Response,
    tenant: Optional[str] = Query(default=None, max_length=64),
    info: sessions.SessionInfo = Depends(session_admin_plus),
) -> RowsResponse:
    response.headers["Cache-Control"] = "no-store"
    return _rows("analyst_verdict", info, tenant)


@router.get("/admin/registry/remote-access", response_model=RowsResponse)
def list_remote_access(
    response: Response,
    tenant: Optional[str] = Query(default=None, max_length=64),
    info: sessions.SessionInfo = Depends(session_admin_plus),
) -> RowsResponse:
    response.headers["Cache-Control"] = "no-store"
    return _rows("remote_access_registry", info, tenant)


@router.get("/admin/registry/canary-allowlist", response_model=RowsResponse)
def list_allowlist(
    response: Response,
    tenant: Optional[str] = Query(default=None, max_length=64),
    info: sessions.SessionInfo = Depends(session_admin_plus),
) -> RowsResponse:
    response.headers["Cache-Control"] = "no-store"
    return _rows("canary_scanner_allowlist", info, tenant)


class AllowIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant: str = Field(min_length=1, max_length=64, pattern=_SLUG)
    ip: str = Field(min_length=2, max_length=64)
    label: str = Field(min_length=1, max_length=120)
    reason: AuditReason


@router.post("/admin/registry/canary-allowlist", response_model=RowsResponse)
def add_allowlist(
    body: AllowIn,
    info: sessions.SessionInfo = Depends(session_admin_plus),
) -> RowsResponse:
    _scoped(info, body.tenant)
    try:
        ip = str(ipaddress.ip_address(body.ip.strip()))
    except ValueError:
        raise APIError("VALIDATION_FAILED", "not an IP address") from None
    _audit(info, "canary_allowlist.update", body.tenant, "canary_allowlist", ip,
           after={"ip": ip, "label": body.label}, reason=body.reason)
    try:
        aid = _write(info, "canary_allowlist.update", body.tenant, "canary_allowlist", ip,
                     lambda reg: registry.add_allowlist(reg, slug=body.tenant, ip=ip,
                                                        label=body.label,
                                                        by=info.operator_id))
    except sqlite3.IntegrityError:
        raise APIError("CONFLICT", "that address is already allowlisted") from None
    except sqlite3.Error:
        raise APIError("SERVICE_UNAVAILABLE", "the allowlist could not be written") from None
    # An allowlisted address never reaches R6 (a decoy credential from it is
    # ignored): it suppresses detection — the other admins are told.
    notify.notify_admins(kind="threat_registry", slug=body.tenant, exclude=info.operator_id,
                         title=f"Canary allowlist: {ip} at {body.tenant}",
                         body=f"Operator #{info.operator_id} allowlisted {ip} ({body.label}) "
                              f"— its decoy credentials no longer reach R6: {body.reason}",
                         request_id=f"allowlist:{aid}")
    return _rows("canary_scanner_allowlist", info, body.tenant)
