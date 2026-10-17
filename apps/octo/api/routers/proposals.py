"""Proposals — an integration proposes, an operator confirms (registry 043).

  GET  /api/v1/proposals                  admin+ (scoped) ?kind=site_location
                                          &status=open|decided|all&tenant=<slug>
  GET  /api/v1/proposals/summary          admin+ (scoped) — the open count (the
                                          Fleet page's badge)
  POST /api/v1/proposals/refresh          admin+ — read Autotask NOW (mapped,
                                          active companies; no geocoding)
  POST /api/v1/proposals/{id}/lookup      admin+ (scoped) — the address lookup
                                          of ONE proposal (rate-limited)
  POST /api/v1/proposals/{id}/confirm     admin+ (scoped), audited BEFORE the write
  POST /api/v1/proposals/{id}/reject      admin+ (scoped), audited BEFORE the write

The first kind is 'site_location' (`apps.octo.proposals.site_location`):
Autotask company / company-location addresses proposed as Fleet site pins.

ROLES. admin / super_admin only. A viewer (client user) or an analyst gets
403; a proposal of a tenant outside the caller's scope is the same 404 as no
such proposal. A shared-address (or shared-company) warning names the OTHER
tenants in the caller's scope only (`others_hidden` says there are more). A
proposal's target that now belongs to another tenant (a site re-mapped)
shows nothing of it — no name, no pin, no console distance.

DECISIONS. Confirm: a match of the operator's lookup (or a typed / pasted
point), the label (default: the Autotask address with its suite), the site
(required when the proposal has none — "pick a site" — and only one of the
tenant's own), a reason, and what the operator reviewed: the proposal's
`updated_at` and the chosen site's own pin (`set_at`, or null for none) —
either changed since is a 409 ("reload") before anything is audited. Two
audit rows are written BEFORE the change — `proposal_confirm` (the decision)
and `site_location_set` (the pin, origin 'autotask', as a hand edit writes
it) — then the pin and the decision in ONE registry transaction (which
checks both again: a race loses). Reject: a reason, `proposal_reject`, the
decision. A change that fails after its audit rows appends
`proposal_confirm_failed` / `proposal_reject_failed` (the error code only:
nothing was written). A reason is whitespace-collapsed and refused (422)
under 3 characters before anything is audited. The address lookup records
who looked something up and how many matches (the polled-read roll-up) —
never the address.
"""
from __future__ import annotations

import sqlite3
import threading
import time
import uuid
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, Path, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from apps.octo import paths
from apps.octo.api.errors import APIError
from apps.octo.api.models import AuditReason
from apps.octo.api.role_gates import resolve_caller_scope, session_admin_plus
from apps.octo.api.routers.fleet import operator_names
from apps.octo.auth import audit, sessions
from apps.octo.auth.audit_rollup import PolledReadAudit
from apps.octo.db import connect
from apps.octo.fleet import build, geocode, locations
from apps.octo.proposals import site_location, store

router = APIRouter(prefix="/proposals", tags=["proposals"])

REFRESH_MIN_INTERVAL_SEC = 30.0
_SITE_KEY = r"^[ut]-[0-9a-f]{20}$"
_refresh_gate = threading.Lock()
_last_refresh_at: list[float] = []


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class CurrentPinOut(BaseModel):
    lat: float
    lng: float
    label: str
    source: str
    """'site' (the site's own pin) | 'manual' (the client's fallback) |
    'unifi' (what the console reports)."""
    origin: Optional[str] = None
    by: Optional[str] = None


class PointOut(BaseModel):
    lat: float
    lng: float


class TargetOut(BaseModel):
    """Where a tenant's proposals may be confirmed — with what the map shows
    there now (and where its console is), so the review warns for the site
    the operator PICKS, not only for the proposed one."""
    key: str
    name: str
    kind: Literal["site", "tenant"]
    current: Optional[CurrentPinOut] = None
    pin_set_at: Optional[str] = None
    """When the site's own pin was set (None: it has none) — sent back as
    the confirm's `expected_pin_set_at`."""
    console: Optional[PointOut] = None
    """Where its UniFi console says it is (the distance warning)."""


class ProposalOut(BaseModel):
    id: int
    kind: str
    source: str
    status: str
    tenant_slug: str
    tenant_name: str
    target_key: Optional[str] = None
    target_name: Optional[str] = None
    target_mode: str
    source_ref: str
    origin: str
    """'company' (the company address) | 'location' (a CompanyLocation)."""
    name: str
    label: str
    address: dict[str, Any] = Field(default_factory=dict)
    flags: list[dict[str, Any]] = Field(default_factory=list)
    previous: Optional[dict[str, Any]] = None
    """The record's previous data (Autotask changed it): id, status, label."""
    confirmed_before: bool = False
    """The same address was confirmed earlier for a target that is gone (a
    client that gained a UniFi site): offered again for the new one."""
    matches: list[dict[str, Any]] = Field(default_factory=list)
    looked_up_at: Optional[str] = None
    current: Optional[CurrentPinOut] = None
    created_at: str
    updated_at: str
    decided_by: Optional[str] = None
    decided_at: Optional[str] = None
    decision_reason: Optional[str] = None


class ProposalsResponse(BaseModel):
    kind: str
    items: list[ProposalOut]
    open: int
    geocoder: Optional[str] = None
    autotask: bool
    """An Autotask instance is running (Refresh is possible)."""
    last_refresh: Optional[dict[str, Any]] = None
    targets: dict[str, list[TargetOut]] = Field(default_factory=dict)
    """Per tenant in the listing: where its proposals may be confirmed."""


class SummaryResponse(BaseModel):
    kind: str
    open: int


class RefreshIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["site_location"] = "site_location"


class RefreshResponse(BaseModel):
    kind: str
    open: int
    summary: dict[str, Any]


class LookupResponse(BaseModel):
    proposal: ProposalOut
    provider: str


class ConfirmIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    match_index: Optional[int] = Field(default=None, ge=0, le=geocode.MAX_MATCHES - 1)
    lat: Optional[float] = Field(default=None, ge=-90.0, le=90.0)
    lng: Optional[float] = Field(default=None, ge=-180.0, le=180.0)
    label: Optional[str] = Field(default=None, max_length=120)
    target_key: Optional[str] = Field(default=None, min_length=3, max_length=40,
                                      pattern=_SITE_KEY)
    reason: AuditReason
    # What the operator reviewed (required — a confirm is never applied to
    # something else): the proposal's updated_at, and the chosen site's own
    # pin (its `pin_set_at` in the listing; null = it has none).
    expected_updated_at: str = Field(min_length=1, max_length=40)
    expected_pin_set_at: Optional[str] = Field(max_length=40)


class RejectIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: AuditReason


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _in_scope(scope: list[str], slug: str) -> bool:
    return scope == ["*"] or slug in scope


def _model(request: Request) -> build.FleetModel:
    return build.get_model(getattr(request.app.state, "instance_manager", None))


def _tenant_names() -> dict[str, str]:
    from apps.octo.fleet import sources

    return {slug: t.name for slug, t in sources.tenants().items()}


def _autotask_clients(request: Request) -> list[tuple[int, Any]]:
    """(instance id, client) of every RUNNING Autotask instance."""
    manager = getattr(request.app.state, "instance_manager", None)
    out: list[tuple[int, Any]] = []
    if manager is None or not hasattr(manager, "list_running"):
        return out
    for record in manager.list_running():
        if record.vendor_slug != "autotask":
            continue
        adapter = manager.running_adapter(record.id)
        client = getattr(adapter, "client", None)
        if client is not None:
            out.append((record.id, client))
    return out


def _last_refresh(scope: list[str], names: dict[str, str]) -> Optional[dict[str, Any]]:
    """The newest refresh of any Autotask instance — counts for `*`; a
    concrete scope sees whether CompanyLocations was readable, when, and
    its own skipped tenants only."""
    from apps.octo.fleet import sources

    best: Optional[dict[str, Any]] = None
    for record in sources.instances("autotask"):
        last = site_location.last_refresh(record.id)
        if last and (best is None or str(last.get("at")) > str(best.get("at"))):
            best = last
    if best is None:
        return None
    skipped = [s for s in best.get("skipped_tenants") or [] if _in_scope(scope, s)]
    out = {k: best.get(k) for k in ("at", "trigger", "locations")}
    out["skipped_non_us"] = [names.get(s, s) for s in skipped]
    if scope == ["*"]:
        out.update({k: best.get(k) for k in ("companies_mapped", "companies_read",
                                             "locations_read", "candidates", "created",
                                             "superseded", "kept_rejected")})
    return out


def _flags_out(flags: list[dict[str, Any]], scope: list[str],
               names: dict[str, str]) -> list[dict[str, Any]]:
    out = []
    for f in flags:
        if not isinstance(f, dict) or not isinstance(f.get("code"), str):
            continue
        item = dict(f)
        if f["code"] in ("shared_address", "shared_company"):
            others = [t for t in f.get("tenants") or [] if isinstance(t, str)]
            item["tenants"] = [names.get(t, t) for t in others if _in_scope(scope, t)]
            item["others_hidden"] = any(not _in_scope(scope, t) for t in others)
        out.append(item)
    return out


def _pin_out(ref: Optional[site_location.SiteRef],
             ops: dict[int, str]) -> Optional[CurrentPinOut]:
    loc = ref.location if ref is not None else None
    if loc is None:
        return None
    return CurrentPinOut(
        lat=loc.lat, lng=loc.lng, label=loc.label, source=loc.source,
        origin=loc.origin if loc.source in ("site", "manual") else None,
        by=ops.get(loc.set_by) if loc.set_by and loc.origin != "manual" else None)


def _out(p: store.Proposal, *, scope: list[str], names: dict[str, str],
         refs: dict[str, site_location.SiteRef], ops: dict[int, str]) -> ProposalOut:
    # Its target only while it is still this tenant's (a site re-mapped to
    # another tenant shows nothing of that tenant).
    ref = site_location.own_ref(refs, p.target_key, p.tenant_slug)
    target_name = ref.name if ref is not None else (
        names.get(p.tenant_slug) if p.target_key == site_location.tenant_key(p.tenant_slug)
        else None)
    current = _pin_out(ref, ops)
    geo = p.geocode or {}
    payload = p.payload or {}
    address = payload.get("address")
    return ProposalOut(
        id=p.id, kind=p.kind, source=p.source, status=p.status, tenant_slug=p.tenant_slug,
        tenant_name=names.get(p.tenant_slug, p.tenant_slug), target_key=p.target_key,
        target_name=target_name,
        target_mode=str(payload.get("target_mode") or ("pick" if p.target_key is None
                                                       else "site")),
        source_ref=p.source_ref, origin=str(payload.get("origin") or ""),
        name=str(payload.get("name") or ""), label=str(payload.get("label") or ""),
        address=address if isinstance(address, dict) else {},
        flags=_flags_out(site_location.live_flags(p, refs), scope, names),
        previous=payload.get("previous") if isinstance(payload.get("previous"), dict) else None,
        confirmed_before=isinstance(payload.get("confirmed_before"), dict),
        matches=[m for m in geo.get("matches") or [] if isinstance(m, dict)],
        looked_up_at=geo.get("at") if isinstance(geo.get("at"), str) else None,
        current=current, created_at=p.created_at, updated_at=p.updated_at,
        decided_by=ops.get(p.decided_by) if p.decided_by else None,
        decided_at=p.decided_at, decision_reason=p.decision_reason,
    )


def _context(request: Request) -> tuple[dict[str, site_location.SiteRef], dict[str, str]]:
    refs = site_location.fleet_refs(_model(request).sites)
    return {r.key: r for r in refs}, _tenant_names()


def _scoped(info: sessions.SessionInfo, proposal_id: int) -> tuple[store.Proposal, list[str]]:
    """The proposal, if the caller's scope holds its tenant — out of scope is
    the same 404 as none."""
    scope = resolve_caller_scope(info.operator_id)
    p = store.get(proposal_id)
    if p is None or p.kind != site_location.KIND or not _in_scope(scope, p.tenant_slug):
        raise APIError("NOT_FOUND", "no such proposal in your scope")
    return p, scope


def _one(request: Request, p: store.Proposal, scope: list[str]) -> ProposalOut:
    refs, names = _context(request)
    fresh = store.get(p.id) or p
    ops = operator_names([fresh.decided_by] + [r.location.set_by for r in refs.values()
                                               if r.location is not None])
    return _out(fresh, scope=scope, names=names, refs=refs, ops=ops)


def _audit(info: sessions.SessionInfo, action: str, slug: str, target_kind: str,
           target_id: str, before: Any, after: Any, reason: str) -> None:
    g = connect(paths.global_audit_db_path())
    try:
        audit.append(g, audit.AuditEntry(
            actor=str(info.operator_id), actor_kind="human", action=action,
            target_kind=target_kind, target_id=target_id, client_slug=slug,
            before_state=before, after_state=after, reason=reason,
            request_id=str(uuid.uuid4())))
    finally:
        g.close()


def _failed(info: sessions.SessionInfo, action: str, p: store.Proposal, key: Optional[str],
            exc: Exception) -> None:
    """The decision audited above did NOT happen: say so (the error's code
    or class only — never its text, which could carry a path)."""
    error = exc.code if isinstance(exc, store.ProposalError) else type(exc).__name__
    _audit(info, action, p.tenant_slug, "proposal", str(p.id), None,
           {"status": p.status, "target_key": key, "error": error},
           f"{action.removesuffix('_failed').replace('_', ' ')} failed: {error}; nothing "
           "was written")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

_STATUS_FILTER = {"open": (store.OPEN,), "decided": ("confirmed", "rejected"),
                  "all": store.STATUSES}


@router.get("", response_model=ProposalsResponse)
def list_proposals(
    request: Request,
    response: Response,
    kind: Literal["site_location"] = Query(default="site_location"),
    status: Literal["open", "decided", "all"] = Query(default="open"),
    tenant: Optional[str] = Query(default=None, min_length=1, max_length=64),
    info: sessions.SessionInfo = Depends(session_admin_plus),
) -> ProposalsResponse:
    response.headers["Cache-Control"] = "no-store"
    scope = resolve_caller_scope(info.operator_id)
    refs, names = _context(request)
    visible = [s for s in names if _in_scope(scope, s)]
    if tenant is not None:
        visible = [s for s in visible if s == tenant]
    rows = store.list_proposals(kind, statuses=_STATUS_FILTER[status], tenants=visible)
    ops = operator_names([p.decided_by for p in rows] +
                         [r.location.set_by for r in refs.values() if r.location is not None])
    items = [_out(p, scope=scope, names=names, refs=refs, ops=ops) for p in rows]
    targets: dict[str, list[TargetOut]] = {}
    overrides = locations.all_site_overrides()
    for slug in sorted({p.tenant_slug for p in rows}):
        out: list[TargetOut] = []
        for k in site_location.valid_targets(slug, refs.values()):
            ref = site_location.own_ref(refs, k, slug)
            own = locations.site_override_for(overrides, k, slug)
            console = ref.console_location if ref is not None else None
            out.append(TargetOut(
                key=k, name=ref.name if ref is not None else names.get(slug, slug),
                kind="site" if k.startswith("u-") else "tenant", current=_pin_out(ref, ops),
                pin_set_at=own.get("set_at") if own is not None else None,
                console=PointOut(lat=console.lat, lng=console.lng) if console else None))
        targets[slug] = out
    return ProposalsResponse(
        kind=kind, items=items,
        open=store.count_open(kind, visible) if status != "open" else len(items),
        geocoder=geocode.provider(), autotask=bool(_autotask_clients(request)),
        last_refresh=_last_refresh(scope, names), targets=targets)


@router.get("/summary", response_model=SummaryResponse)
def proposals_summary(
    response: Response,
    kind: Literal["site_location"] = Query(default="site_location"),
    info: sessions.SessionInfo = Depends(session_admin_plus),
) -> SummaryResponse:
    response.headers["Cache-Control"] = "no-store"
    scope = resolve_caller_scope(info.operator_id)
    visible = [s for s in _tenant_names() if _in_scope(scope, s)]
    return SummaryResponse(kind=kind, open=store.count_open(kind, visible))


@router.post("/refresh", response_model=RefreshResponse)
def refresh_proposals(
    request: Request,
    body: Optional[RefreshIn] = None,
    info: sessions.SessionInfo = Depends(session_admin_plus),
) -> RefreshResponse:
    """Read Autotask now — the same bounded read as the daily run (mapped,
    active companies and their locations; never a geocoder call)."""
    from apps.octo.adapters.autotask.client import AutotaskAuthError, AutotaskClientError

    kind = (body or RefreshIn()).kind
    clients = _autotask_clients(request)
    if not clients:
        raise APIError("CONFLICT", "Autotask is not connected (or not running) — connect it "
                                   "under Settings → Integrations")
    with _refresh_gate:
        now = time.monotonic()
        if _last_refresh_at and now - _last_refresh_at[-1] < REFRESH_MIN_INTERVAL_SEC:
            raise APIError("RATE_LIMITED", "Autotask was just read — try again in a minute")
        _last_refresh_at[:] = [now]
    scope = resolve_caller_scope(info.operator_id)
    fleet = _model(request).sites
    # Who asked Autotask to be read, BEFORE anything is written (the counts
    # are kept with the run — `last_refresh`).
    _audit(info, "proposals_refresh", "global", "proposals", f"{kind}:autotask", None,
           {"instances": [i for i, _ in clients]}, "Refresh from Autotask (on demand)")
    summaries = []
    for instance_id, client in clients:
        try:
            summaries.append(site_location.refresh(client, instance_id, fleet=fleet))
        except site_location.RefreshBusy:
            raise APIError("CONFLICT", "a refresh is already running — try again shortly") \
                from None
        except AutotaskAuthError:
            raise APIError("VENDOR_UNREACHABLE", "Autotask refused the credentials — check the "
                                                 "integration") from None
        except AutotaskClientError:
            raise APIError("VENDOR_UNREACHABLE", "Autotask could not be read — try again "
                                                 "later") from None
    total: dict[str, Any] = {k: sum(int(s.get(k) or 0) for s in summaries)
             for k in ("created", "refreshed", "superseded", "kept_rejected", "kept_confirmed",
                       "candidates", "companies_read", "skipped_non_us")}
    total["locations"] = summaries[-1].get("locations") if summaries else None
    names = _tenant_names()
    visible = [s for s in names if _in_scope(scope, s)]
    shown = total if scope == ["*"] else {"locations": total["locations"]}
    return RefreshResponse(kind=kind, open=store.count_open(kind, visible), summary=shown)


@router.post("/{proposal_id}/lookup", response_model=LookupResponse)
def lookup_proposal(
    request: Request,
    response: Response,
    proposal_id: int = Path(..., ge=1),
    info: sessions.SessionInfo = Depends(session_admin_plus),
) -> LookupResponse:
    """The address lookup of ONE proposal (the Census geocoder, the one-line
    address with its unit stripped — nothing else leaves the box); the
    matches are kept on the proposal."""
    response.headers["Cache-Control"] = "no-store"
    p, scope = _scoped(info, proposal_id)
    if not p.open:
        raise APIError("CONFLICT", "this proposal is already decided")
    name = geocode.provider()
    if name is None:
        raise APIError("CONFLICT", "address lookup is turned off on this server — paste the "
                                   "coordinates or a map link instead")
    if not geocode.LIMITER.allow(info.operator_id):
        raise APIError("RATE_LIMITED", "too many address lookups — wait a minute and try again")
    refs, _names = _context(request)
    try:
        matches = site_location.lookup(p, refs)
    except geocode.GeocodeError as exc:
        code = {"invalid": "VALIDATION_FAILED", "off": "CONFLICT"}.get(exc.kind,
                                                                       "VENDOR_UNREACHABLE")
        raise APIError(code, str(exc) if exc.kind != "invalid" else
                       "this address is too short to look up — paste the coordinates "
                       "or a map link instead") from None
    except store.ProposalError as exc:
        raise APIError(exc.code, str(exc)) from None
    # Who looked something up and how many matches — never the address.
    PolledReadAudit.for_app(request.app).record(
        "proposals.lookup", operator_id=info.operator_id, session_id=info.id,
        reason="location proposal address lookup", rows=len(matches), shape=f"provider={name}",
        detail={"matches": len(matches)},
    )
    return LookupResponse(proposal=_one(request, p, scope), provider=name)


@router.post("/{proposal_id}/confirm", response_model=ProposalOut)
def confirm_proposal(
    body: ConfirmIn,
    request: Request,
    proposal_id: int = Path(..., ge=1),
    info: sessions.SessionInfo = Depends(session_admin_plus),
) -> ProposalOut:
    p, scope = _scoped(info, proposal_id)
    if not p.open:
        raise APIError("CONFLICT", "this proposal is already decided")
    names = _tenant_names()
    if p.tenant_slug not in names:
        raise APIError("CONFLICT", "only an active tenant can be placed on the map")
    if body.expected_updated_at != p.updated_at:
        raise APIError("CONFLICT", "this proposal changed since you loaded it (Autotask was "
                                   "read again, or it was looked up) — reload, then confirm")
    refs, _ = _context(request)
    key = body.target_key or p.target_key
    if key is None:
        raise APIError("VALIDATION_FAILED", "pick the site this address is for")
    valid = site_location.valid_targets(p.tenant_slug, refs.values())
    if key not in valid:
        raise APIError("VALIDATION_FAILED", "that is not one of this client's sites")
    if site_location.pin_set_at(key, p.tenant_slug) != body.expected_pin_set_at:
        raise APIError("CONFLICT", site_location.PIN_CHANGED)
    picked: Optional[dict[str, Any]] = None
    if body.match_index is not None:
        if body.lat is not None or body.lng is not None:
            raise APIError("VALIDATION_FAILED", "give a match or a point, not both")
        matches = (p.geocode or {}).get("matches") or []
        if body.match_index >= len(matches) or not isinstance(matches[body.match_index], dict):
            raise APIError("VALIDATION_FAILED", "look the address up first, then pick a match")
        picked = matches[body.match_index]
        lat, lng = picked.get("lat"), picked.get("lng")
    elif body.lat is not None and body.lng is not None:
        lat, lng = body.lat, body.lng
    else:
        raise APIError("VALIDATION_FAILED", "pick a match of the lookup, or give the point")
    label = (body.label or "").strip() or str(p.payload.get("label") or "") or \
        str((picked or {}).get("label") or "")
    try:
        lat, lng, label = locations.validated(lat, lng, label)
    except locations.LocationError as exc:
        raise APIError("VALIDATION_FAILED", str(exc)) from None
    ref = site_location.own_ref(refs, key, p.tenant_slug)
    site_name = ref.name if ref is not None else names.get(p.tenant_slug, p.tenant_slug)
    before_pin = locations.get_site(key, p.tenant_slug)
    before = {k: before_pin[k] for k in ("lat", "lng", "label")} if before_pin else None
    _audit(info, "proposal_confirm", p.tenant_slug, "proposal", str(p.id),
           {"status": p.status, "target_key": p.target_key, "pin": before},
           {"status": "confirmed", "target_key": key, "site": site_name,
            "source": p.source, "source_ref": p.source_ref, "lat": lat, "lng": lng,
            "label": label, "match_index": body.match_index,
            "km_from_console": (picked or {}).get("km_from_console")},
           body.reason)
    _audit(info, "site_location_set", p.tenant_slug, "site_location", key, before,
           {"lat": lat, "lng": lng, "label": label, "site": site_name, "origin": p.source,
            "proposal": p.id}, body.reason)
    try:
        site_location.confirm(p, key=key, lat=lat, lng=lng, label=label,
                              actor=info.operator_id, reason=body.reason,
                              expected_updated_at=body.expected_updated_at,
                              expected_pin_set_at=body.expected_pin_set_at)
    except (store.ProposalError, sqlite3.Error, locations.LocationError) as exc:
        _failed(info, "proposal_confirm_failed", p, key, exc)
        if isinstance(exc, store.ProposalError):
            raise APIError(exc.code, str(exc)) from None
        raise
    return _one(request, p, scope)


@router.post("/{proposal_id}/reject", response_model=ProposalOut)
def reject_proposal(
    body: RejectIn,
    request: Request,
    proposal_id: int = Path(..., ge=1),
    info: sessions.SessionInfo = Depends(session_admin_plus),
) -> ProposalOut:
    p, scope = _scoped(info, proposal_id)
    if not p.open:
        raise APIError("CONFLICT", "this proposal is already decided")
    _audit(info, "proposal_reject", p.tenant_slug, "proposal", str(p.id),
           {"status": p.status, "target_key": p.target_key, "source_ref": p.source_ref,
            "label": p.payload.get("label")},
           {"status": "rejected"}, body.reason)
    try:
        site_location.reject(p, actor=info.operator_id, reason=body.reason)
    except (store.ProposalError, sqlite3.Error) as exc:
        _failed(info, "proposal_reject_failed", p, None, exc)
        if isinstance(exc, store.ProposalError):
            raise APIError(exc.code, str(exc)) from None
        raise
    return _one(request, p, scope)
