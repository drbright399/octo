"""Incidents — Red and Black (Tier Black slice 1; design 6.4 / 6.7 and
Rick's section 9).

  GET  /api/v1/incidents?status=open|closed|all&tier=red|black   analyst+ (scoped)
  GET  /api/v1/incidents/summary            viewer+ — operators {black_unacked, black,
                                            red, items}; a client user the NEUTRAL form
                                            ({black, red} of what they may see and the
                                            worst of their neutral lines)
  GET  /api/v1/incidents/client             viewer — the client user's own visible
                                            incidents: the neutral line + two actions
  POST /api/v1/incidents/client/{ref}/decision
                                            viewer — "lockdown" | "allow": RECORDED,
                                            audited (the client user's id), the analysts
                                            paged, a confirmation shown. Nothing on the
                                            network changes in slice 1.
  POST /api/v1/incidents/declare            analyst+ — B6: a bare device, a site (one of
                                            THIS client's) or a signal declared BLACK
                                            (reason)
  GET  /api/v1/incidents/{slug}/{id}        analyst+ (scoped) — evidence, timeline, the
                                            rule, "why", "why this device?", the
                                            freshness matrix frozen at open, coverage,
                                            mode, proposed steps, the client's
                                            decisions, the client's view
  POST …/{id}/ack | assign | note | contain | raise | close | reclassify
  GET  /api/v1/incidents/evidence-windows?state=held|released|all
                                            analyst+ (scoped) — every EVIDENCE WINDOW
                                            (Rick, 2026-10-05: a confirmed threat's
                                            first detection → its all-clear; kept by
                                            every retention path until released):
                                            start, end / open, rows kept, ~events
  POST …/{id}/evidence-window               admin+ with step-up — add a window (an
                                            explicit start, an optional end: none =
                                            held open until released) or extend one
                                            (`window_id`: start earlier / end later);
                                            the other admins are told. (The former
                                            tenant-wide legal hold.)
       …/{id}/evidence-window/{wid}/widen   analyst+ — an earlier start (dwell time
                                            found later; never before 2000), a
                                            reason; the admins are told
       …/{id}/evidence-window/{wid}/release admin+ with step-up, a reason — only after
                                            the all-clear; audited BEFORE the write;
                                            the other admins are told. Nobody shrinks
                                            a window otherwise; nothing expires it.
       …/{id}/lockdown-request              analyst+ — recorded only; life-safety
                                            assets carved out (canonical identities:
                                            host names, addresses, networks; a
                                            target that cannot be checked is left
                                            out and marked for an analyst)
       …/{id}/decisions/{did}/answer        analyst+ — confirm / decline a client's
                                            pending request (a Black "allow")
  POST /api/v1/signals/{slug}/{event_id}/confirm
                                            analyst+ — R8: a Yellow signal confirmed as a
                                            threat (RED), reason ≥ 20 characters

ROLE MATRIX (6.4)
  viewer        neutral summary + their own visible incidents + the two
                client actions; every operator route is 403.
  analyst       (scoped) see, acknowledge, assign to SELF, note, confirm
                (R8, ≥ 20 chars), raise to Black (B6, reason), contain,
                close a RED (remediated | authorized_activity | duplicate |
                false_positive), lockdown requests, answer a client's request.
  admin, super_admin
                + assign anyone; close a BLACK (step-up — a re-authentication
                within the window — a code, a text and, for a true positive,
                the checklist: C2 blocked or n/a, rescue point verified,
                device state, client notified — who, when); close a Black as
                false_positive or reclassify it to Red (step-up + reason;
                every admin is told — 24 h peer review).
  nobody        lower in place, mute, snooze: NO ROUTE EXISTS.

RESTRICTED INCIDENTS (B7, CSAM — v0.17.1, Rick 2026-10-06). Admin and
super_admin only: the detail (with the "DO NOT OPEN" warning, the fixed
checklist and the lookups' domains DEFANGED) is served only after its audit
row (`incident.restricted_view`: who, when); an analyst's attempt is refused
and audited (`incident.restricted_denied`); the list, the strip and the
evidence windows show anyone else "Restricted incident" at the tenant and
nothing more. An admin may acknowledge, assign (to an admin+), note, close
(the normal Black close: step-up, a reason, the checklist) and keep the
evidence window — nothing that touches the device (contain, lockdown, allow,
raise, reclassify: 409), and a client user is offered no action at all.

ANALYST VERDICTS (G10). A false-positive close writes the analyst verdict for
the exact key ONLY when the incident was opened by an AUTOMATED rule and the
closer is an admin+ with step-up (a Black's close always is; an admin closing
an automated Red as a false positive is asked for step-up). The verdict
blocks that rule re-firing or reopening on that key for 365 days — it never
blocks a PERSON: a B6 / R8 declaration is heard whatever was closed before.
An analyst's false-positive close writes no verdict.

THE CLIENT'S DECISIONS are throttled: the same person's same decision on the
same incident within 10 minutes is answered with what was already recorded —
no new row, no new page (a client pressing twice, or a stolen session in a
loop, never pages every analyst again).

AUDIT BEFORE WRITE: every change appends its row (global chain, client_slug
= the tenant) and only then writes; a write that fails after its row appends
`<action>_failed`. A reason is mandatory for close, raise, confirm and
reclassify.
"""
from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Literal, Optional

from fastapi import APIRouter, Depends, Path, Query, Request, Response
from pydantic import AfterValidator, BaseModel, ConfigDict, Field

from apps.octo import paths
from apps.octo.api.errors import APIError
from apps.octo.api.models import AuditReason, _audit_reason
from apps.octo.api.role_gates import (
    ROLE_TIER,
    operator_max_tier,
    resolve_caller_scope,
    session_analyst_plus,
    session_viewer_plus,
)
from apps.octo.auth import sessions
from apps.octo.fleet import build, sources
from apps.octo.threat import audit as taudit
from apps.octo.threat import (
    client_view,
    coverage,
    engine,
    lockdown,
    notify,
    registry,
    restricted,
    rules,
    store,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/incidents", tags=["incidents"])
signals_router = APIRouter(prefix="/signals", tags=["incidents"])

CONFIRM_REASON_MIN = 20
DECISION_THROTTLE = timedelta(minutes=10)
READY_TO_CLOSE_AFTER = timedelta(hours=72)
KILL_CHAIN = ("lure", "access", "c2", "privilege", "credentials", "lateral", "evasion",
              "impact")
_SLUG = r"^[a-z0-9]+(?:-[a-z0-9]+)*$"


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class IncidentOut(BaseModel):
    tenant_slug: str
    tenant_name: str
    id: int
    tier: str
    status: str
    open: bool
    rule_id: str
    rule_version: int
    rule_title: str
    summary: str
    opened_at: str
    age_s: int
    site_key: Optional[str] = None
    device_ref: Optional[str] = None
    device_label: Optional[str] = None
    scope: str
    acked: bool
    acked_by: Optional[str] = None
    acked_by_name: Optional[str] = None
    acknowledged_at: Optional[str] = None
    assigned_to: Optional[str] = None
    assigned_to_name: Optional[str] = None
    contained: bool
    contained_at: Optional[str] = None
    closed_at: Optional[str] = None
    close_reason_code: Optional[str] = None
    reclassified_from: Optional[int] = None
    reopened_count: int = 0
    escalation_step: int = 0
    client_visible: bool = False
    opened_by: Optional[str] = None
    ready_to_close: bool = False
    """A Black contained for over 72 h with no new evidence: the console asks
    "ready to close?" (design 6.4) — a prompt, never an automatic close."""
    evidence_held: bool = False
    """An evidence window of this incident is held: everything of the
    client inside it is kept by every retention path until an admin
    releases it (Rick, 2026-10-05)."""
    restricted: bool = False
    """A RESTRICTED incident (B7, CSAM — v0.17.1): admin / super_admin only.
    Anyone else reads "Restricted incident" at the tenant and nothing more
    (no rule, summary, device or site); no device action is ever offered."""


class IncidentListResponse(BaseModel):
    items: list[IncidentOut]


class SummaryResponse(BaseModel):
    view: Literal["operator", "client"]
    black: int
    red: int
    black_unacked: Optional[int] = None
    """Operators only (a client user never sees a pulse): absent for them."""
    items: Optional[list[dict[str, Any]]] = None
    """Operators: the open Blacks and Reds (banner / strip); absent for a
    client user."""
    status_neutral: Optional[str] = None
    """A client user: the line their global strip shows — the WORST of what
    they may see ("…has been alerted", "…is responding", "…contained…",
    "…under investigation…"); absent for operators."""


class IncidentDetail(BaseModel):
    incident: IncidentOut
    timeline: list[dict[str, Any]]
    evidence: list[dict[str, Any]]
    snapshot: dict[str, Any]
    stages: list[dict[str, Any]]
    why: list[dict[str, Any]]
    ruled_out: list[dict[str, Any]]
    ruled_out_note: Optional[str] = None
    kill_chain: list[dict[str, Any]]
    coverage: list[dict[str, Any]]
    mode: dict[str, Any]
    proposed_steps: list[str]
    decisions: list[dict[str, Any]]
    client_view: Optional[dict[str, Any]] = None
    """Exactly what the client's users see now (None: hidden from them)."""
    asset_tags: list[str] = Field(default_factory=list)
    why_device: list[str] = Field(default_factory=list)
    """"Why this device?" — how the incident came to name its device (or
    why it names none)."""
    freshness: list[dict[str, Any]] = Field(default_factory=list)
    """The per-source freshness matrix FROZEN at open (G8): each detection
    source's last good contact, whether it was failing, and since when."""
    evidence_windows: list["EvidenceWindowOut"] = Field(default_factory=list)
    """The incident's evidence windows (owned, or opened by it), newest
    first."""
    restricted: Optional[dict[str, Any]] = None
    """A RESTRICTED incident (B7, CSAM), admins only — every read audited:
    {category, warning ("DO NOT OPEN …"), checklist (fixed, plain text),
    lookups, first_at, last_at, client_notice (the MSP switch), evidence: the
    lookups with their domains DEFANGED ("example[.]test" — never a link,
    never resolved, fetched, enriched or previewed)}."""


class EvidenceWindowOut(BaseModel):
    """One evidence window — operators only (a client user never sees one)."""
    id: int
    tenant_slug: str
    tenant_name: str
    incident_id: int
    origin_incident_id: int
    incident_tier: Optional[str] = None
    incident_status: Optional[str] = None
    incident_open: Optional[bool] = None
    incident_summary: Optional[str] = None
    kind: Literal["incident", "manual"]
    start: str
    end: Optional[str] = None
    open: bool
    """No end yet: until the incident's all-clear (automatic), or until an
    admin releases it (a manual window without an end)."""
    held: bool
    opened_by: str
    opened_by_name: Optional[str] = None
    opened_at: str
    reason: str
    released_at: Optional[str] = None
    released_by: Optional[str] = None
    released_by_name: Optional[str] = None
    release_reason: Optional[str] = None
    kept_rows: Optional[int] = None
    """Rows the last nightly retention run kept past their normal retention
    because of this window (None: not counted yet)."""
    kept_counted_at: Optional[str] = None
    events_in_window: Optional[int] = None
    """About how many events (signals) of the client arrived inside the
    window — capped at `EVENTS_COUNT_CAP` (None: not cheap to count)."""
    events_capped: bool = False


class EvidenceWindowListResponse(BaseModel):
    items: list[EvidenceWindowOut]


IncidentDetail.model_rebuild()


class AckIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    note: Optional[str] = Field(default=None, max_length=500)


class AssignIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    to: int


class NoteIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str = Field(min_length=1, max_length=4000)


class ContainIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    receipt: AuditReason


class RaiseIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: AuditReason


class Checklist(BaseModel):
    model_config = ConfigDict(extra="forbid")
    c2_blocked: Literal["yes", "n/a"]
    rescue_point_verified: bool
    device_state: str = Field(min_length=3, max_length=300)
    client_notified_who: str = Field(min_length=2, max_length=120)
    client_notified_when: str = Field(min_length=4, max_length=40)


class CloseIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: Literal["remediated", "authorized_activity", "duplicate", "false_positive"]
    text: AuditReason
    checklist: Optional[Checklist] = None


class ReclassifyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: AuditReason


class LockdownIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    note: AuditReason
    targets: list[dict[str, str]] = Field(default_factory=list, max_length=20)


class AnswerIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirm: bool
    note: AuditReason


class EvidenceWindowIn(BaseModel):
    """Add a window (no `window_id`) or extend one: an explicit start and an
    optional end (a new window without one is held open until released)."""
    model_config = ConfigDict(extra="forbid")
    start: str = Field(min_length=10, max_length=40)
    end: Optional[str] = Field(default=None, min_length=10, max_length=40)
    reason: AuditReason
    window_id: Optional[int] = Field(default=None, ge=1)


class WidenIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    start: str = Field(min_length=10, max_length=40)
    reason: AuditReason


class ReleaseIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: AuditReason


class ClientDecisionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["lockdown", "allow"]
    note: Optional[str] = Field(default=None, max_length=500)


class DeclareIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant: str = Field(min_length=1, max_length=64, pattern=_SLUG)
    summary: str = Field(min_length=3, max_length=300)
    reason: AuditReason
    site_key: Optional[str] = Field(default=None, pattern=r"^[ut]-[0-9a-f]{20}$")
    device_ref: Optional[str] = Field(default=None, min_length=1, max_length=200)
    device_label: Optional[str] = Field(default=None, max_length=200)
    event_id: Optional[int] = None


def _confirm_reason(value: str) -> str:
    text = _audit_reason(value)               # whitespace collapsed, as every reason
    if len(text) < CONFIRM_REASON_MIN:
        raise ValueError(f"a reason of at least {CONFIRM_REASON_MIN} characters is required")
    return text


# R8's reason: AuditReason's normalising, ≥ 20 characters AFTER it (twenty
# spaces are not a reason).
ConfirmReason = Annotated[str, Field(min_length=CONFIRM_REASON_MIN, max_length=500),
                          AfterValidator(_confirm_reason)]


class ConfirmIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: ConfirmReason
    summary: Optional[str] = Field(default=None, min_length=3, max_length=300)


class ClientIncidentsResponse(BaseModel):
    items: list[dict[str, Any]]


class ClientDecisionResponse(BaseModel):
    confirmation: str
    decision: dict[str, Any]


class DecisionResponse(BaseModel):
    incident: IncidentOut
    decision: dict[str, Any]


class ReclassifyResponse(BaseModel):
    closed: IncidentOut
    opened: IncidentOut


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _tier(info: sessions.SessionInfo) -> int:
    return operator_max_tier(info.operator_id)


def _admin(info: sessions.SessionInfo) -> bool:
    return _tier(info) >= ROLE_TIER["admin"]


# What an admin may do on a RESTRICTED incident (B7): look, acknowledge,
# assign (to another admin+), note, close (the normal Black close: step-up, a
# reason, the checklist) and keep its evidence window. Nothing that touches
# the device — no containment, lockdown, allow, raise or reclassify.
RESTRICTED_ACTIONS = ("incident.view", "incident.ack", "incident.assign", "incident.note",
                      "incident.close", "incident.evidence_window_add",
                      "incident.evidence_window_extend", "incident.evidence_window_widen",
                      "incident.evidence_window_release")


def _label(inc: store.Incident) -> str:
    """How a notice names an incident: its summary — never a RESTRICTED
    one's (a notice names no category, device or domain)."""
    return restricted.NEUTRAL_SUMMARY if inc.restricted else inc.summary


def _restricted_gate(info: sessions.SessionInfo, inc: store.Incident, action: str) -> None:
    """A RESTRICTED incident (B7): admin+ only — anyone else is refused AND
    the attempt audited (who, when, what); an admin's action that would
    touch the device is refused (409). No-op for every other incident."""
    if not inc.restricted:
        return
    if not _admin(info):
        try:
            _audit(info, "incident.restricted_denied", inc.slug, str(inc.id),
                   after={"action": action, "role_tier": _tier(info)},
                   reason="a restricted incident is for admins only")
        except Exception:  # noqa: BLE001 — refused either way
            logger.error("[incidents] a refused restricted access could not be audited")
        raise APIError("ISOLATION_VIOLATION", "a restricted incident is for admins only")
    if action not in RESTRICTED_ACTIONS:
        raise APIError("CONFLICT", store.RESTRICTED_NO_ACTION)


def _in_scope(scope: list[str], slug: str) -> bool:
    return scope == ["*"] or slug in scope


def _tenant_names() -> dict[str, str]:
    try:
        return {s: t.name for s, t in sources.tenants().items()}
    except sqlite3.Error:
        return {}


def _scoped_slug(info: sessions.SessionInfo, slug: str) -> str:
    """The tenant if the caller's scope holds it and it is active — else the
    same 404 as no such incident."""
    if not paths.SLUG_RE.match(slug or ""):
        raise APIError("NOT_FOUND", "no such incident in your scope")
    scope = resolve_caller_scope(info.operator_id)
    if not _in_scope(scope, slug) or slug not in _tenant_names():
        raise APIError("NOT_FOUND", "no such incident in your scope")
    return slug


def _load(slug: str, incident_id: int) -> store.Incident:
    try:
        return store.get(slug, incident_id)
    except store.NotFound:
        raise APIError("NOT_FOUND", "no such incident in your scope") from None
    except sqlite3.Error:
        raise APIError("SERVICE_UNAVAILABLE", "the incident store could not be read") from None


def _held_ids(slug: str) -> set[int]:
    """Incident ids of the tenant with a held evidence window ({} when the
    store cannot be read — the flag is informational; the retention job
    reads the windows itself, fail closed)."""
    try:
        return store.held_window_incidents(slug)
    except sqlite3.Error:
        return set()


def _out(inc: store.Incident, *, names: dict[str, str], tenant_names: dict[str, str],
         now: datetime, held: Optional[set[int]] = None, admin: bool = False) -> IncidentOut:
    """The incident as an operator reads it. A RESTRICTED one (B7) is shown
    in full to an admin+ (`admin`) only; anyone else gets "Restricted
    incident" at the tenant — no rule, summary, device, site or opener."""
    r = rules.rule(inc.rule_id)
    held = held if held is not None else _held_ids(inc.slug)
    if inc.restricted and not admin:
        return IncidentOut(
            tenant_slug=inc.slug, tenant_name=tenant_names.get(inc.slug, inc.slug), id=inc.id,
            tier=inc.tier, status=inc.status, open=inc.is_open, rule_id="restricted",
            rule_version=0, rule_title=restricted.ANALYST_LINE,
            summary=restricted.NEUTRAL_SUMMARY, opened_at=inc.detected_at,
            age_s=inc.age_s(now), scope="tenant", acked=inc.acked,
            acknowledged_at=inc.acknowledged_at, contained=False, closed_at=inc.closed_at,
            reopened_count=inc.reopened_count, escalation_step=inc.escalation_step,
            evidence_held=inc.id in held, restricted=True)
    return IncidentOut(
        tenant_slug=inc.slug, tenant_name=tenant_names.get(inc.slug, inc.slug), id=inc.id,
        tier=inc.tier, status=inc.status, open=inc.is_open, rule_id=inc.rule_id,
        rule_version=inc.rule_version, rule_title=r.title if r else inc.rule_id,
        summary=inc.summary, opened_at=inc.detected_at, age_s=inc.age_s(now),
        site_key=inc.site_key, device_ref=inc.device_ref, device_label=inc.device_label,
        scope=inc.scope, acked=inc.acked, acked_by=inc.acknowledged_by,
        acked_by_name=names.get(inc.acknowledged_by or ""),
        acknowledged_at=inc.acknowledged_at, assigned_to=inc.assigned_to,
        assigned_to_name=names.get(inc.assigned_to or ""), contained=inc.contained,
        contained_at=inc.contained_at, closed_at=inc.closed_at,
        close_reason_code=inc.close_reason_code, reclassified_from=inc.reclassified_from,
        reopened_count=inc.reopened_count, escalation_step=inc.escalation_step,
        client_visible=client_view.visible(inc, now, watch_days=_watch_days(inc.slug)),
        opened_by=inc.opened_by, ready_to_close=ready_to_close(inc, now),
        evidence_held=inc.id in held, restricted=inc.restricted,
    )


def ready_to_close(inc: store.Incident, now: datetime) -> bool:
    """Design 6.4: a contained Black older than 72 h with no new evidence
    since its containment prompts "ready to close?"."""
    if not (inc.is_open and inc.tier == store.BLACK and inc.contained):
        return False
    contained = store.parse(inc.contained_at)
    last = store.parse(inc.last_evidence_at)
    if contained is None or now - contained < READY_TO_CLOSE_AFTER:
        return False
    return last is None or last <= contained


def _watch_days(slug: str) -> int:
    return int(registry.settings(slug).get("watch_days") or 7)


def _names(incs: list[store.Incident]) -> dict[str, str]:
    ids = set()
    for i in incs:
        ids.update(x for x in (i.acknowledged_by, i.assigned_to, i.opened_by) if x)
    return sources.operator_display_names(ids)


def _audit(info: sessions.SessionInfo, action: str, slug: str, target_id: Optional[str], *,
           before: Any = None, after: Any = None, reason: Optional[str] = None) -> None:
    taudit.human(info.operator_id, action, slug, "incident", target_id, before=before,
                 after=after, reason=reason)


def _failed(info: sessions.SessionInfo, action: str, slug: str, target_id: Optional[str],
            exc: BaseException) -> None:
    """The change audited above did NOT happen: say so (the error class only)."""
    try:
        _audit(info, f"{action}_failed", slug, target_id,
               after={"error": type(exc).__name__},
               reason=f"the recorded {action} was not written: {type(exc).__name__}")
    except Exception:  # noqa: BLE001
        logger.error("[incidents] %s_failed could not be audited", action)


def _changed(slug: str) -> None:
    build.invalidate()
    engine.poke(slug)


def _store_error(exc: Exception) -> APIError:
    if isinstance(exc, store.NotFound):
        return APIError("NOT_FOUND", "no such incident in your scope")
    if isinstance(exc, store.Refused):
        return APIError("CONFLICT", str(exc))
    return APIError("SERVICE_UNAVAILABLE", "the incident store could not be written")


def _require_step_up(request: Request, info: sessions.SessionInfo) -> None:
    from apps.octo.api.routers.search import require_step_up

    require_step_up(request, info)


def _page(inc: store.Incident) -> None:
    engine.page_now(inc, tenant_name=_tenant_names().get(inc.slug, inc.slug))


def _model(request: Request) -> build.FleetModel:
    manager = getattr(request.app.state, "instance_manager", None)
    return build.get_model(manager)


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------

@router.get("", response_model=IncidentListResponse)
def list_incidents(
    response: Response,
    status: Literal["open", "closed", "all"] = Query(default="open"),
    tier: Optional[Literal["red", "black"]] = Query(default=None),
    info: sessions.SessionInfo = Depends(session_analyst_plus),
) -> IncidentListResponse:
    response.headers["Cache-Control"] = "no-store"
    scope = resolve_caller_scope(info.operator_id)
    names = _tenant_names()
    statuses = store.OPEN_STATUSES if status == "open" else \
        store.CLOSED_STATUSES if status == "closed" else None
    found: list[store.Incident] = []
    held: dict[str, set[int]] = {}
    for slug in sorted(names):
        if not _in_scope(scope, slug):
            continue
        try:
            found.extend(store.list_incidents(slug, statuses=statuses,
                                              tiers=(tier,) if tier else None))
        except sqlite3.Error:
            continue
        held[slug] = _held_ids(slug)
    now = _now()
    ops = _names(found)
    found.sort(key=lambda i: (0 if i.is_open and i.tier == "black" else 1,
                              1 if i.acked else 0, i.detected_at))
    # A RESTRICTED incident is listed as "Restricted incident" for EVERY
    # role, admins included: its detail is read only through the audited
    # detail route (every view audited — B5).
    return IncidentListResponse(items=[_out(i, names=ops, tenant_names=names, now=now,
                                            held=held.get(i.slug, set()), admin=False)
                                       for i in found])


@router.get("/summary", response_model=SummaryResponse, response_model_exclude_none=True)
def incidents_summary(
    request: Request,
    response: Response,
    info: sessions.SessionInfo = Depends(session_viewer_plus),
) -> SummaryResponse:
    """The global strip (every route, 15 s). Operators: from the fleet model
    (rebuilt on every incident change). A client user: the NEUTRAL counts of
    what they may see — no acknowledgement state, no pulse."""
    response.headers["Cache-Control"] = "no-store"
    scope = resolve_caller_scope(info.operator_id)
    if _tier(info) >= ROLE_TIER["analyst"]:
        items = [i for i in _model(request).threat_incidents if _in_scope(scope, i["tenant"])]
        return SummaryResponse(
            view="operator", black=sum(1 for i in items if i["tier"] == "black"),
            red=sum(1 for i in items if i["tier"] == "red"),
            black_unacked=sum(1 for i in items if i["tier"] == "black" and not i["acked"]),
            items=items)
    visible = _client_items(scope)
    return SummaryResponse(view="client",
                           black=sum(1 for v in visible if v.get("tier") == "black"),
                           red=sum(1 for v in visible if v.get("tier") == "red"),
                           status_neutral=client_view.worst_line(
                               [v for v in visible if v.get("tier")]))


def _client_items(scope: list[str]) -> list[dict[str, Any]]:
    if scope == ["*"] or not scope:
        return []                              # a legacy '*' viewer sees nothing
    now = _now()
    out = []
    for slug in scope:
        try:
            incs = store.open_and_recent(slug, now) or []
        except sqlite3.Error:
            continue
        watch = _watch_days(slug)
        for inc in incs:
            item = client_view.payload(inc, now, decisions=store.decisions(slug, inc.id),
                                       watch_days=watch)
            if item is not None:
                out.append(item)
    return out


@router.get("/client", response_model=ClientIncidentsResponse)
def client_incidents(
    response: Response,
    info: sessions.SessionInfo = Depends(session_viewer_plus),
) -> ClientIncidentsResponse:
    """A client user's own visible incidents — the neutral line and the two
    actions. Operators use the operator routes (403 here: this is the
    client's surface, and nothing in it is theirs to act on)."""
    response.headers["Cache-Control"] = "no-store"
    if _tier(info) >= ROLE_TIER["analyst"]:
        raise APIError("ISOLATION_VIOLATION", "the client view is for client users")
    return ClientIncidentsResponse(items=_client_items(resolve_caller_scope(info.operator_id)))


@router.post("/client/{ref}/decision", response_model=ClientDecisionResponse)
def client_decision(
    body: ClientDecisionIn,
    ref: str = Path(..., pattern=r"^i-[0-9a-f]{20}$"),
    info: sessions.SessionInfo = Depends(session_viewer_plus),
) -> ClientDecisionResponse:
    """"Lock down my network and contact my analyst" / "Allow this traffic".
    RECORDED only (slice 1): audited with the client user's id BEFORE the
    write, the analysts in scope paged, a confirmation returned. A lockdown
    carves every 911 / life-safety asset out. On Black, "allow" is a
    request an analyst must confirm; on Red it is the client's decision."""
    if _tier(info) >= ROLE_TIER["analyst"]:
        raise APIError("ISOLATION_VIOLATION", "client decisions are for client users")
    scope = resolve_caller_scope(info.operator_id)
    if scope == ["*"] or not scope:
        raise APIError("NOT_FOUND", "no such incident")
    now = _now()
    found: Optional[store.Incident] = None
    for slug in scope:
        try:
            for inc in store.open_and_recent(slug, now) or []:
                if client_view.ref(slug, inc.id) == ref:
                    found = inc
                    break
        except sqlite3.Error:
            continue
        if found:
            break
    if found is None or not client_view.visible(found, now) or not found.is_open \
            or found.restricted:
        # A restricted incident (B7) offers neither action — nothing is done
        # to the device, the user involved is not tipped off.
        raise APIError("NOT_FOUND", "no such incident")
    inc = found
    me = str(info.operator_id)
    try:
        again = store.recent_decision(inc.slug, inc.id, requested_by=me, kind=body.kind,
                                      since=now - DECISION_THROTTLE)
    except sqlite3.Error:
        raise APIError("SERVICE_UNAVAILABLE", "the incident store could not be read") from None
    if again is not None:
        # Already recorded (and paged) a moment ago: the same answer — no new
        # row, no new page.
        return ClientDecisionResponse(
            confirmation="Already recorded. " + client_view.confirmation(
                body.kind, again["tier_at_request"]),
            decision={"kind": again["kind"], "status": again["status"],
                      "created_at": again["created_at"]})
    status = client_view.decision_status(body.kind, inc.tier)
    scope_list: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    notice = ""
    if body.kind == "lockdown":
        try:
            req = lockdown.build(inc.slug, device_ref=inc.device_ref, site_key=inc.site_key)
            if not lockdown.never_includes_life_safety(req, inc.slug):
                raise lockdown.LockdownRefused("a life-safety asset was in the request — "
                                               "911 / life-safety systems are never blocked")
        except lockdown.LockdownRefused as exc:
            raise APIError("SERVICE_UNAVAILABLE", str(exc)) from None
        scope_list, excluded, notice = req.scope, req.excluded, req.notice
    after = {"kind": body.kind, "status": status, "tier": inc.tier, "client_user": info.operator_id,
             "scope": scope_list, "excluded": excluded, "notice": notice, "executes": False}
    _audit(info, "incident.client_decision", inc.slug, str(inc.id), after=after,
           reason=f"client user #{info.operator_id} chose '{body.kind}'"
                  + (f": {body.note}" if body.note else ""))
    try:
        decision = store.record_decision(
            inc.slug, inc.id, kind=body.kind, requested_by=me,
            requested_role="client", status=status, scope=scope_list, excluded=excluded,
            notice=notice, note=body.note, now=now)
    except (store.StoreError, sqlite3.Error) as exc:
        _failed(info, "incident.client_decision", inc.slug, str(inc.id), exc)
        raise _store_error(exc) from None
    notify.notify_client_decision(inc, decision,
                                  tenant_name=_tenant_names().get(inc.slug, inc.slug))
    _changed(inc.slug)
    return ClientDecisionResponse(
        confirmation=client_view.confirmation(body.kind, inc.tier),
        decision={"kind": decision["kind"], "status": decision["status"],
                  "created_at": decision["created_at"]})


@router.get("/{slug}/{incident_id}", response_model=IncidentDetail)
def incident_detail(
    response: Response,
    slug: str = Path(..., min_length=1, max_length=64),
    incident_id: int = Path(..., ge=1),
    info: sessions.SessionInfo = Depends(session_analyst_plus),
) -> IncidentDetail:
    response.headers["Cache-Control"] = "no-store"
    _scoped_slug(info, slug)
    inc = _load(slug, incident_id)
    if inc.restricted:
        return _restricted_detail(info, inc)
    now = _now()
    names = _names([inc])
    tnames = _tenant_names()
    rule = rules.rule(inc.rule_id)
    tags = sorted(registry.tags_for(slug, inc.device_ref))
    ev = inc.evidence if isinstance(inc.evidence, dict) else {}
    why = [{"condition": "a person's declaration" if rule and rule.kind == rules.HUMAN
            else (rule.title if rule else inc.rule_id),
            "met": True, "detail": inc.open_reason or ev.get("reason") or inc.summary,
            "event_ids": inc.event_ids}]
    for s in inc.stages:
        if s.get("kind") == "raise":
            why.append({"condition": f"raised to BLACK ({s.get('rule')})", "met": True,
                        "detail": s.get("by"), "event_ids": []})
    phases = set(ev.get("phases") or [])
    life = "life_safety" in tags
    mode = {"mode": "propose_only",
            "source": "slice 1 — nothing executes; a person carries out every step",
            "caps": (["Analyze-only (life-safety asset: never blocked)"] if life else [])
            + [f"Analyze-only ({t} asset cap)" for t in tags
               if t in ("cjis", "patient_care", "server", "dc")]}
    steps = [
        "Block C2: a NextDNS denylist entry for the relay root, a UniFi block of the client "
        "to that destination, or a single-device job to stop the service (a person does it)",
        "Rescue point: confirm a Datto Rollback / DEB rescue point exists — or establish one "
        "first",
        "Human approval",
        "Prefilled isolation request (typed hostname, reason, 24 h auto-restore, the "
        "reversal path, the client told out of band)",
        "Monitor",
    ]
    if life:
        steps.insert(0, lockdown.LIFE_SAFETY_NOTICE + ": this asset is carved out of any "
                     "lockdown — protect it, never cut it")
    cov = [c.as_dict() for c in coverage.tenant_coverage(slug, now).values()]
    fresh = ev.get("freshness")
    return IncidentDetail(
        why_device=_why_device(inc, rule, ev),
        freshness=[f for f in fresh if isinstance(f, dict)] if isinstance(fresh, list) else [],
        incident=_out(inc, names=names, tenant_names=tnames, now=now, admin=_admin(info)),
        timeline=store.notes(slug, incident_id), evidence=store.evidence_events(slug, incident_id),
        snapshot=ev, stages=inc.stages, why=why, ruled_out=[],
        ruled_out_note=("A person's declaration (B6 / R8): no automated attribution checks "
                        "apply — the declaration and its reason are the evidence."
                        if rule is None or rule.kind == rules.HUMAN else None),
        kill_chain=[{"phase": p, "seen": p in phases} for p in KILL_CHAIN],
        coverage=cov, mode=mode, proposed_steps=steps,
        decisions=store.decisions(slug, incident_id),
        client_view=client_view.payload(inc, now, decisions=store.decisions(slug, incident_id),
                                        watch_days=_watch_days(slug)),
        asset_tags=tags,
        evidence_windows=_incident_windows(slug, incident_id, admin=_admin(info)),
    )


def _restricted_detail(info: sessions.SessionInfo, inc: store.Incident) -> IncidentDetail:
    """A RESTRICTED incident (B7, CSAM), opened by an admin+ — the read is
    audited (who, when) BEFORE anything is returned; an analyst is refused
    (and that is audited too). No proposed step and no action touches the
    device: the panel carries the fixed checklist and the "DO NOT OPEN"
    warning, and the lookups' domains DEFANGED."""
    _restricted_gate(info, inc, "incident.view")
    slug = inc.slug
    try:
        evidence = restricted.for_incident(slug, inc.id)
        # The other sensors' records naming the same domain (a buoy's
        # Pi-hole / Suricata) — hidden from every other surface, here
        # defanged.
        related = restricted.related_records(slug, inc.id)
    except sqlite3.Error:
        raise APIError("SERVICE_UNAVAILABLE", "the restricted evidence could not be read") \
            from None
    # Audit BEFORE the read is served: who opened it, when (the row's time),
    # how much it showed — never a domain.
    try:
        _audit(info, "incident.restricted_view", slug, str(inc.id),
               after={"rule": inc.rule_id, "lookups_shown": len(evidence),
                      "related_shown": len(related)},
               reason="a restricted incident was opened")
    except Exception:  # noqa: BLE001 — never served unaudited
        raise APIError("SERVICE_UNAVAILABLE", "the view could not be audited, so it is not "
                                              "shown") from None
    now = _now()
    rule = rules.rule(inc.rule_id)
    ev = inc.evidence if isinstance(inc.evidence, dict) else {}
    times = [e["observed_at"] for e in evidence if e.get("observed_at")]
    fresh = ev.get("freshness")
    return IncidentDetail(
        incident=_out(inc, names=_names([inc]), tenant_names=_tenant_names(), now=now,
                      admin=True),
        timeline=store.notes(slug, inc.id), evidence=[], snapshot=ev, stages=inc.stages,
        why=[{"condition": rule.title if rule else inc.rule_id, "met": True,
              "detail": inc.open_reason or ev.get("why") or inc.summary, "event_ids": []}],
        ruled_out=[], ruled_out_note="An automated restricted rule: a CSAM-category block by "
                                     "DNS protection is the evidence.",
        kill_chain=[], coverage=[c.as_dict() for c in coverage.tenant_coverage(slug, now).values()
                                 if c.rule_id == inc.rule_id],
        mode={"mode": "restricted", "caps": [],
              "source": "no device action of any kind — the evidence is preserved and the user "
                        "involved is not tipped off"},
        proposed_steps=[], decisions=[],
        client_view=client_view.payload(inc, now, watch_days=_watch_days(slug)),
        asset_tags=sorted(registry.tags_for(slug, inc.device_ref)),
        why_device=["the device NextDNS named for the lookup: "
                    f"{inc.device_label or inc.device_ref}",
                    "not checked against an inventory (entity resolution is off)"],
        freshness=[f for f in fresh if isinstance(f, dict)] if isinstance(fresh, list) else [],
        evidence_windows=_incident_windows(slug, inc.id, admin=True),
        restricted={
            "category": restricted.CSAM, "warning": restricted.WARNING,
            "checklist": list(restricted.CHECKLIST), "lookups": len(evidence),
            "first_at": min(times) if times else None, "last_at": max(times) if times else None,
            "client_notice": registry.csam_client_notice(), "evidence": evidence,
            "related": related,
        },
    )


def _why_device(inc: store.Incident, rule: Optional[rules.Rule],
                ev: dict[str, Any]) -> list[str]:
    """"Why this device?" — the chain that named it (design 6.8). Slice 1
    has no resolver: a device is named by a person, or by the one event a
    person confirmed; never inferred."""
    if not inc.device_ref:
        if inc.site_key:
            return ["no device named: the incident is the whole SITE's"]
        return ["no device or site named: it is painted on every site of the client "
                "(device location unknown)"]
    if rule is not None and rule.id == "B6" and ev.get("event_id") is None:
        return [f"named by the person who declared it (operator #{inc.opened_by}) — typed, "
                "not resolved", "not checked against an inventory (entity resolution is off)"]
    if rule is not None and rule.kind == rules.HUMAN:
        return [f"the host field of the event a person confirmed (event #{ev.get('event_id')})",
                f"{inc.device_ref} — as the vendor reported it; not checked against an "
                "inventory (entity resolution is off)"]
    return [f"the rule's own evidence: {inc.device_ref}",
            "not checked against an inventory (entity resolution is off)"]


# ---------------------------------------------------------------------------
# The human lifecycle
# ---------------------------------------------------------------------------

def _act(info: sessions.SessionInfo, slug: str, incident_id: int, action: str, *,
         reason: Optional[str], after: dict[str, Any], write) -> store.Incident:  # noqa: ANN001
    inc = _load(slug, incident_id)
    _restricted_gate(info, inc, action)
    _audit(info, action, slug, str(incident_id),
           before={"tier": inc.tier, "status": inc.status, "acked": inc.acked},
           after=after, reason=reason)
    try:
        out = write()
    except (store.StoreError, sqlite3.Error, ValueError) as exc:
        _failed(info, action, slug, str(incident_id), exc)
        raise _store_error(exc) if not isinstance(exc, ValueError) else \
            APIError("VALIDATION_FAILED", str(exc)) from None
    _changed(slug)
    return out


@router.post("/{slug}/{incident_id}/ack", response_model=IncidentOut)
def ack_incident(
    body: AckIn,
    slug: str = Path(..., min_length=1, max_length=64),
    incident_id: int = Path(..., ge=1),
    info: sessions.SessionInfo = Depends(session_analyst_plus),
) -> IncidentOut:
    """One click: stops the ladder and the pulse, not the pin."""
    _scoped_slug(info, slug)
    inc = _act(info, slug, incident_id, "incident.ack", reason=body.note or "acknowledged",
               after={"acknowledged_by": info.operator_id},
               write=lambda: store.ack(slug, incident_id, by=str(info.operator_id),
                                       note=body.note))
    return _out(inc, names=_names([inc]), tenant_names=_tenant_names(), now=_now(),
                admin=_admin(info))


@router.post("/{slug}/{incident_id}/assign", response_model=IncidentOut)
def assign_incident(
    body: AssignIn,
    slug: str = Path(..., min_length=1, max_length=64),
    incident_id: int = Path(..., ge=1),
    info: sessions.SessionInfo = Depends(session_analyst_plus),
) -> IncidentOut:
    """An analyst assigns to SELF; an admin+ to anyone who may see it."""
    _scoped_slug(info, slug)
    if _tier(info) < ROLE_TIER["admin"] and body.to != info.operator_id:
        raise APIError("ISOLATION_VIOLATION", "an analyst may only assign an incident to "
                                              "themselves")
    target_scope = resolve_caller_scope(body.to)
    if operator_max_tier(body.to) < ROLE_TIER["analyst"] or not _in_scope(target_scope, slug):
        raise APIError("VALIDATION_FAILED", "that operator cannot work this tenant's incidents")
    current = _load(slug, incident_id)
    _restricted_gate(info, current, "incident.assign")
    if current.restricted and operator_max_tier(body.to) < ROLE_TIER["admin"]:
        raise APIError("VALIDATION_FAILED", "a restricted incident is assigned to an admin only")
    inc = _act(info, slug, incident_id, "incident.assign", reason=f"assigned to #{body.to}",
               after={"assigned_to": body.to},
               write=lambda: store.assign(slug, incident_id, by=str(info.operator_id),
                                          to=str(body.to)))
    return _out(inc, names=_names([inc]), tenant_names=_tenant_names(), now=_now(),
                admin=_admin(info))


@router.post("/{slug}/{incident_id}/note", response_model=IncidentOut)
def note_incident(
    body: NoteIn,
    slug: str = Path(..., min_length=1, max_length=64),
    incident_id: int = Path(..., ge=1),
    info: sessions.SessionInfo = Depends(session_analyst_plus),
) -> IncidentOut:
    _scoped_slug(info, slug)
    inc = _act(info, slug, incident_id, "incident.note", reason="note added",
               after={"chars": len(body.text)},
               write=lambda: store.add_note(slug, incident_id, by=str(info.operator_id),
                                            text=body.text))
    return _out(inc, names=_names([inc]), tenant_names=_tenant_names(), now=_now(),
                admin=_admin(info))


@router.post("/{slug}/{incident_id}/contain", response_model=IncidentOut)
def contain_incident(
    body: ContainIn,
    slug: str = Path(..., min_length=1, max_length=64),
    incident_id: int = Path(..., ge=1),
    info: sessions.SessionInfo = Depends(session_analyst_plus),
) -> IncidentOut:
    """Marked contained (a receipt or a reason): the static double ring.
    Records only — nothing is executed."""
    _scoped_slug(info, slug)
    inc = _act(info, slug, incident_id, "incident.contain", reason=body.receipt,
               after={"contained_by": info.operator_id},
               write=lambda: store.contain(slug, incident_id, by=str(info.operator_id),
                                           receipt=body.receipt))
    return _out(inc, names=_names([inc]), tenant_names=_tenant_names(), now=_now(),
                admin=_admin(info))


@router.post("/{slug}/{incident_id}/raise", response_model=IncidentOut)
def raise_incident(
    body: RaiseIn,
    slug: str = Path(..., min_length=1, max_length=64),
    incident_id: int = Path(..., ge=1),
    info: sessions.SessionInfo = Depends(session_analyst_plus),
) -> IncidentOut:
    """B6: a Red raised to BLACK in the same incident (a reason). Its
    acknowledgement is cleared and the ladder restarts at T0."""
    _scoped_slug(info, slug)
    inc = _act(info, slug, incident_id, "incident.raise", reason=body.reason,
               after={"tier": "black", "rule": "B6"},
               write=lambda: store.raise_to_black(slug, incident_id, by=str(info.operator_id),
                                                  reason=body.reason))
    _page(inc)
    return _out(inc, names=_names([inc]), tenant_names=_tenant_names(), now=_now(),
                admin=_admin(info))


@router.post("/{slug}/{incident_id}/close", response_model=IncidentOut)
def close_incident(
    body: CloseIn,
    request: Request,
    slug: str = Path(..., min_length=1, max_length=64),
    incident_id: int = Path(..., ge=1),
    info: sessions.SessionInfo = Depends(session_analyst_plus),
) -> IncidentOut:
    """Red: analyst+, a code and a reason. Black: admin+ with step-up; a
    true-positive close needs the checklist; a false-positive close writes
    the analyst verdict for the exact key and tells every admin."""
    _scoped_slug(info, slug)
    inc = _load(slug, incident_id)
    _restricted_gate(info, inc, "incident.close")
    if not inc.is_open:
        raise APIError("CONFLICT", "the incident is closed")
    admin = _tier(info) >= ROLE_TIER["admin"]
    if inc.tier == store.BLACK:
        if not admin:
            raise APIError("ISOLATION_VIOLATION", "closing a Black needs an admin")
        if body.code != "false_positive" and body.checklist is None:
            raise APIError("VALIDATION_FAILED", "closing a Black needs the checklist: C2 "
                                                "blocked or n/a, rescue point verified, the "
                                                "device's state, and who notified the client "
                                                "and when")
        _require_step_up(request, info)
    rule = rules.rule(inc.rule_id)
    # G10: a verdict only for an AUTOMATED rule's key, only from an admin+
    # with step-up. A person's declaration is never what a verdict blocks.
    # Nor a RESTRICTED rule's (B7, CSAM): every CSAM lookup opens a Black
    # (B1) — a false-positive close never silences the device for a year.
    verdict = (body.code == "false_positive" and admin and rule is not None and rule.automated
               and not rule.restricted)
    if verdict and inc.tier != store.BLACK:
        _require_step_up(request, info)
    after = {"code": body.code, "tier": inc.tier, "verdict": verdict,
             "checklist": body.checklist.model_dump() if body.checklist else None}
    # The tier the checks above were made for is re-checked INSIDE the write:
    # a Red raised to Black meanwhile is never closed by a Red's rules.
    closed = _act(info, slug, incident_id, "incident.close", reason=body.text, after=after,
                  write=lambda: store.close(
                      slug, incident_id, by=str(info.operator_id), code=body.code,
                      text=body.text, expected_tier=inc.tier,
                      checklist=body.checklist.model_dump() if body.checklist else None))
    if verdict:
        _verdict(info, closed, body.text)
    if inc.tier == store.BLACK:
        notify.notify_admins(
            kind="threat_registry", slug=slug, exclude=info.operator_id,
            title=f"Black #{inc.id} closed as {body.code} — peer review within 24 h",
            body=f"Operator #{info.operator_id} closed BLACK incident #{inc.id} "
                 f"({_label(inc)}) as {body.code}: {body.text}",
            request_id=f"inc:{slug}:{inc.id}:closed")
    return _out(closed, names=_names([closed]), tenant_names=_tenant_names(), now=_now(),
                admin=_admin(info))


def _verdict(info: sessions.SessionInfo, inc: store.Incident, reason: str) -> None:
    """A false-positive close blocks that exact key from re-firing or
    reopening (365 d) — audited before it is written."""
    from apps.octo.db import connect, transaction

    after = {"key": inc.dedupe_key, "rule": inc.rule_id, "incident": inc.id}
    taudit.human(info.operator_id, "verdict.create", inc.slug, "analyst_verdict",
                 inc.dedupe_key, after=after, reason=reason)
    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            vid = registry.add_verdict(reg, slug=inc.slug, device_ref=inc.device_ref,
                                       key=inc.dedupe_key, rule_id=inc.rule_id,
                                       incident_id=inc.id, reason=reason, by=info.operator_id)
    except sqlite3.Error as exc:
        _failed(info, "verdict.create", inc.slug, inc.dedupe_key, exc)
        return
    finally:
        reg.close()
    # A verdict suppresses a rule on that key for a year: every other admin
    # is told (registry edits that can suppress a tier — design 6.7).
    notify.notify_admins(
        kind="threat_registry", slug=inc.slug, exclude=info.operator_id,
        title=f"Analyst verdict: {inc.rule_id} will not re-fire on #{inc.id}'s key for "
              f"{registry.VERDICT_DAYS} days",
        body=f"Operator #{info.operator_id} closed incident #{inc.id} ({_label(inc)}) as a "
             f"false positive; {inc.rule_id} is blocked on that exact key: {reason}",
        request_id=f"verdict:{vid}")


@router.post("/{slug}/{incident_id}/reclassify", response_model=ReclassifyResponse)
def reclassify_incident(
    body: ReclassifyIn,
    request: Request,
    slug: str = Path(..., min_length=1, max_length=64),
    incident_id: int = Path(..., ge=1),
    info: sessions.SessionInfo = Depends(session_analyst_plus),
) -> ReclassifyResponse:
    """Close a Black as reclassified: the Black stays Black (immutable) and
    CLOSED; a linked Red opens. admin+ with step-up."""
    _scoped_slug(info, slug)
    if _tier(info) < ROLE_TIER["admin"]:
        raise APIError("ISOLATION_VIOLATION", "reclassifying a Black needs an admin")
    inc = _load(slug, incident_id)
    _restricted_gate(info, inc, "incident.reclassify")
    if inc.tier != store.BLACK or not inc.is_open:
        raise APIError("CONFLICT", "only an open Black is reclassified")
    _require_step_up(request, info)
    pair = _act(info, slug, incident_id, "incident.reclassify", reason=body.reason,
                after={"from": "black", "to": "red (linked, new record)"},
                write=lambda: store.reclassify(slug, incident_id, by=str(info.operator_id),
                                               reason=body.reason))
    closed, opened = pair  # type: ignore[misc]
    notify.notify_admins(
        kind="threat_registry", slug=slug, exclude=info.operator_id,
        title=f"Black #{inc.id} reclassified to Red #{opened.id} — peer review within 24 h",
        body=f"Operator #{info.operator_id}: {body.reason}",
        request_id=f"inc:{slug}:{inc.id}:reclassified")
    _page(opened)
    names, tn, now = _names([closed, opened]), _tenant_names(), _now()
    return ReclassifyResponse(
        closed=_out(closed, names=names, tenant_names=tn, now=now, admin=True),
        opened=_out(opened, names=names, tenant_names=tn, now=now, admin=True))


# ---------------------------------------------------------------------------
# Evidence windows (Rick, 2026-10-05) — the former legal hold
# ---------------------------------------------------------------------------

def _all_tenants() -> dict[str, tuple[str, str]]:
    """Every tenant on record: slug → (name, status). An offboarded or
    archived tenant's windows still hold its data — an admin must be able
    to see and release them."""
    from apps.octo.db import connect

    try:
        reg = connect(paths.registry_db_path(), read_only=True)
        try:
            return {r["slug"]: (r["display_name"] or r["slug"], r["status"] or "active")
                    for r in reg.execute("SELECT slug, display_name, status FROM clients")}
        finally:
            reg.close()
    except sqlite3.Error:
        return {}


def _scoped_any(info: sessions.SessionInfo, slug: str) -> str:
    """The tenant if the caller's scope holds it — whatever its status."""
    if not paths.SLUG_RE.match(slug or ""):
        raise APIError("NOT_FOUND", "no such incident in your scope")
    if not _in_scope(resolve_caller_scope(info.operator_id), slug) or slug not in _all_tenants():
        raise APIError("NOT_FOUND", "no such incident in your scope")
    return slug


def _window_out(w: Any, *, slug: str, tenant_name: str, inc: Optional[store.Incident],
                names: dict[str, str], admin: bool = False) -> EvidenceWindowOut:
    try:
        events = store.events_in_window(slug, w.start, w.end)
    except sqlite3.Error:
        events = None
    # A RESTRICTED incident's window (B7) outside its audited admin detail:
    # no summary, and none of the free text or names an admin wrote on it
    # (a reason may say why it is held, for whom, on which device).
    hidden = inc is not None and inc.restricted and not admin
    summary = None if inc is None else restricted.NEUTRAL_SUMMARY if hidden else inc.summary
    return EvidenceWindowOut(
        id=w.id, tenant_slug=slug, tenant_name=tenant_name, incident_id=w.incident_id,
        origin_incident_id=w.origin_incident_id,
        incident_tier=inc.tier if inc else None, incident_status=inc.status if inc else None,
        incident_open=inc.is_open if inc else None, incident_summary=summary,
        kind=w.kind, start=w.start, end=w.end, open=w.is_open, held=w.held,
        opened_by="restricted" if hidden else w.opened_by,
        opened_by_name=None if hidden else names.get(w.opened_by),
        opened_at=w.opened_at, reason="restricted" if hidden else w.reason,
        released_at=w.released_at,
        released_by=("restricted" if w.released_by else None) if hidden else w.released_by,
        released_by_name=None if hidden else names.get(w.released_by or ""),
        release_reason=None if hidden else w.release_reason, kept_rows=w.kept_rows,
        kept_counted_at=w.kept_counted_at,
        events_in_window=events[0] if events else None,
        events_capped=bool(events and events[1]),
    )


def _windows_out(slug: str, tenant_name: str, wins: list[Any],
                 admin: bool = False) -> list[EvidenceWindowOut]:
    incs: dict[int, Optional[store.Incident]] = {}
    for w in wins:
        if w.incident_id not in incs:
            try:
                incs[w.incident_id] = store.get(slug, w.incident_id)
            except (store.StoreError, sqlite3.Error):
                incs[w.incident_id] = None
    ids = {x for w in wins for x in (w.opened_by, w.released_by) if x}
    names = sources.operator_display_names(ids)
    return [_window_out(w, slug=slug, tenant_name=tenant_name, inc=incs.get(w.incident_id),
                        names=names, admin=admin) for w in wins]


def _incident_windows(slug: str, incident_id: int,
                      admin: bool = False) -> list[EvidenceWindowOut]:
    try:
        wins = store.evidence_windows(slug, incident_id=incident_id)
    except sqlite3.Error:
        return []
    name = _all_tenants().get(slug, (slug, ""))[0]
    return _windows_out(slug, name, wins, admin=admin)


@router.get("/evidence-windows", response_model=EvidenceWindowListResponse)
def list_evidence_windows(
    response: Response,
    state: Literal["held", "released", "all"] = Query(default="held"),
    info: sessions.SessionInfo = Depends(session_analyst_plus),
) -> EvidenceWindowListResponse:
    """Settings → Threats: every evidence window of the tenants in scope
    (offboarded and archived ones included — their windows still hold).
    Operators only: a client user never sees a window."""
    response.headers["Cache-Control"] = "no-store"
    scope = resolve_caller_scope(info.operator_id)
    out: list[EvidenceWindowOut] = []
    for slug, (name, _status) in sorted(_all_tenants().items()):
        if not _in_scope(scope, slug):
            continue
        try:
            wins = store.evidence_windows(slug, state=state)
        except sqlite3.Error:
            continue
        # A restricted incident's window names it neutrally here, for every
        # role: its summary is read through its audited detail only.
        out.extend(_windows_out(slug, name, wins, admin=False))
    out.sort(key=lambda w: (0 if w.held else 1, w.start), reverse=False)
    return EvidenceWindowListResponse(items=out)


def _window_act(info: sessions.SessionInfo, slug: str, incident_id: int, action: str, *,
                reason: str, after: dict[str, Any], write) -> Any:  # noqa: ANN001
    """Audit BEFORE the write (the window's change, with its reason), then
    write; a write that fails appends `<action>_failed`."""
    inc = _load(slug, incident_id)
    _restricted_gate(info, inc, action)
    _audit(info, action, slug, str(incident_id),
           before={"tier": inc.tier, "status": inc.status}, after=after, reason=reason)
    try:
        out = write()
    except (store.StoreError, sqlite3.Error, ValueError) as exc:
        _failed(info, action, slug, str(incident_id), exc)
        raise _store_error(exc) if not isinstance(exc, ValueError) else \
            APIError("VALIDATION_FAILED", str(exc)) from None
    _changed(slug)
    return out


def _require_admin(info: sessions.SessionInfo, what: str) -> None:
    if _tier(info) < ROLE_TIER["admin"]:
        raise APIError("ISOLATION_VIOLATION", f"{what} needs an admin")


def _window_before(slug: str, incident_id: int, window_id: int) -> dict[str, Any]:
    try:
        for w in store.evidence_windows(slug, incident_id=incident_id):
            if w.id == window_id:
                return {"start": w.start, "end": w.end, "held": w.held, "kind": w.kind}
    except sqlite3.Error:
        raise APIError("SERVICE_UNAVAILABLE", "the incident store could not be read") from None
    raise APIError("NOT_FOUND", "no such evidence window on this incident")


@router.post("/{slug}/{incident_id}/evidence-window", response_model=EvidenceWindowOut)
def add_or_extend_window(
    body: EvidenceWindowIn,
    request: Request,
    slug: str = Path(..., min_length=1, max_length=64),
    incident_id: int = Path(..., ge=1),
    info: sessions.SessionInfo = Depends(session_analyst_plus),
) -> EvidenceWindowOut:
    """admin+ with step-up (the former legal hold). No `window_id`: a NEW
    manual window — an explicit start, an optional end (none: held open
    until an admin releases it). `window_id`: EXTEND that window — the start
    the same or earlier, the end (if given) the same or later; never a
    shrink. Open or closed incidents alike (a claim often follows the
    close). Audited before the write; the other admins are told."""
    _scoped_any(info, slug)
    _require_admin(info, "adding or extending an evidence window")
    _require_step_up(request, info)
    inc = _load(slug, incident_id)
    by = str(info.operator_id)
    if body.window_id is None:
        action = "incident.evidence_window_add"
        after = {"start": body.start, "end": body.end, "kind": "manual"}
        w = _window_act(info, slug, incident_id, action, reason=body.reason, after=after,
                        write=lambda: store.add_window(slug, incident_id, start=body.start,
                                                       end=body.end, by=by,
                                                       reason=body.reason))
        verb = "added"
    else:
        before = _window_before(slug, incident_id, body.window_id)
        action = "incident.evidence_window_extend"
        after = {"window": body.window_id, "before": before, "start": body.start,
                 "end": body.end}
        w = _window_act(info, slug, incident_id, action, reason=body.reason, after=after,
                        write=lambda: store.extend_window(slug, incident_id, body.window_id,
                                                          start=body.start, end=body.end,
                                                          by=by, reason=body.reason))
        verb = "extended"
    notify.notify_admins(
        kind="threat_registry", slug=slug, exclude=info.operator_id,
        title=f"Evidence window {verb}: incident #{incident_id}",
        body=f"Operator #{info.operator_id} {verb} evidence window #{w.id} of incident "
             f"#{incident_id} ({_label(inc)}): {w.start} → {w.end or 'open'} — everything of "
             f"this client inside it is kept until an admin releases it: {body.reason}",
        request_id=f"evw:{slug}:{w.id}:{verb}:{_now().isoformat()}")
    name = _all_tenants().get(slug, (slug, ""))[0]
    return _windows_out(slug, name, [w], admin=_admin(info))[0]


@router.post("/{slug}/{incident_id}/evidence-window/{window_id}/widen",
             response_model=EvidenceWindowOut)
def widen_window(
    body: WidenIn,
    slug: str = Path(..., min_length=1, max_length=64),
    incident_id: int = Path(..., ge=1),
    window_id: int = Path(..., ge=1),
    info: sessions.SessionInfo = Depends(session_analyst_plus),
) -> EvidenceWindowOut:
    """analyst+ — an EARLIER start (dwell time found later), a reason;
    audited before the write; the admins are told (a widened window holds
    more of the client's data until an admin releases it — a slip of a year
    is theirs to catch). Never a later one: nobody shrinks a window."""
    _scoped_any(info, slug)
    before = _window_before(slug, incident_id, window_id)
    inc = _load(slug, incident_id)
    w = _window_act(info, slug, incident_id, "incident.evidence_window_widen",
                    reason=body.reason,
                    after={"window": window_id, "before": before, "start": body.start},
                    write=lambda: store.widen_window(slug, incident_id, window_id,
                                                     start=body.start,
                                                     by=str(info.operator_id),
                                                     reason=body.reason))
    name = _all_tenants().get(slug, (slug, ""))[0]
    out = _windows_out(slug, name, [w], admin=_admin(info))[0]
    approx = (f"; about {out.events_in_window}{'+' if out.events_capped else ''} event(s) "
              "arrived inside it" if out.events_in_window is not None else "")
    notify.notify_admins(
        kind="threat_registry", slug=slug, exclude=info.operator_id,
        title=f"Evidence window widened: incident #{incident_id}",
        body=f"Operator #{info.operator_id} widened evidence window #{w.id} of incident "
             f"#{incident_id} ({_label(inc)}) from {before['start']} back to {w.start}{approx}. "
             f"Everything of this client inside it is kept until an admin releases it: "
             f"{body.reason}",
        request_id=f"evw:{slug}:{w.id}:widened:{w.start}")
    return out


@router.post("/{slug}/{incident_id}/evidence-window/{window_id}/release",
             response_model=EvidenceWindowOut)
def release_window(
    body: ReleaseIn,
    request: Request,
    slug: str = Path(..., min_length=1, max_length=64),
    incident_id: int = Path(..., ge=1),
    window_id: int = Path(..., ge=1),
    info: sessions.SessionInfo = Depends(session_analyst_plus),
) -> EvidenceWindowOut:
    """admin+ with step-up and a reason — only after the all-clear (the
    incident closed). Audited BEFORE the write; every other admin is told.
    The window's rows then age out under normal retention."""
    _scoped_any(info, slug)
    _require_admin(info, "releasing an evidence window")
    _require_step_up(request, info)
    before = _window_before(slug, incident_id, window_id)
    inc = _load(slug, incident_id)
    w = _window_act(info, slug, incident_id, "incident.evidence_window_release",
                    reason=body.reason, after={"window": window_id, "before": before,
                                               "released": True},
                    write=lambda: store.release_window(slug, incident_id, window_id,
                                                       by=str(info.operator_id),
                                                       reason=body.reason))
    notify.notify_admins(
        kind="threat_registry", slug=slug, exclude=info.operator_id,
        title=f"Evidence released: window #{window_id} of incident #{incident_id}",
        body=f"Operator #{info.operator_id} released evidence window #{window_id} of incident "
             f"#{incident_id} ({_label(inc)}): {before['start']} → "
             f"{before['end'] or 'open'}. Its rows age out under normal retention from the "
             f"next nightly run: {body.reason}",
        request_id=f"evw:{slug}:{window_id}:released")
    name = _all_tenants().get(slug, (slug, ""))[0]
    return _windows_out(slug, name, [w], admin=_admin(info))[0]


@router.post("/{slug}/{incident_id}/lockdown-request", response_model=DecisionResponse)
def lockdown_request(
    body: LockdownIn,
    slug: str = Path(..., min_length=1, max_length=64),
    incident_id: int = Path(..., ge=1),
    info: sessions.SessionInfo = Depends(session_analyst_plus),
) -> DecisionResponse:
    """An analyst's lockdown request — RECORDED (slice 1 executes nothing).
    Every life-safety asset and path is carved out and the record says so,
    whatever targets were asked for."""
    _scoped_slug(info, slug)
    inc = _load(slug, incident_id)
    _restricted_gate(info, inc, "incident.lockdown_request")
    try:
        req = lockdown.build(slug, device_ref=inc.device_ref, site_key=inc.site_key,
                             extra_targets=body.targets)
        if not lockdown.never_includes_life_safety(req, slug):
            raise lockdown.LockdownRefused("a life-safety asset was in the request")
    except (lockdown.LockdownRefused, registry.RegistryUnavailable) as exc:
        raise APIError("SERVICE_UNAVAILABLE", str(exc)) from None
    _audit(info, "incident.lockdown_request", slug, str(incident_id),
           after=req.as_dict(), reason=body.note)
    try:
        decision = store.record_decision(
            slug, incident_id, kind="lockdown", requested_by=str(info.operator_id),
            requested_role="analyst", status="recorded", scope=req.scope,
            excluded=req.excluded, notice=req.notice, note=body.note)
    except (store.StoreError, sqlite3.Error) as exc:
        _failed(info, "incident.lockdown_request", slug, str(incident_id), exc)
        raise _store_error(exc) from None
    _changed(slug)
    inc = _load(slug, incident_id)
    return DecisionResponse(incident=_out(inc, names=_names([inc]),
                                          tenant_names=_tenant_names(), now=_now(),
                                          admin=_admin(info)),
                            decision=decision)


@router.post("/{slug}/{incident_id}/decisions/{decision_id}/answer",
             response_model=DecisionResponse)
def answer_decision(
    body: AnswerIn,
    slug: str = Path(..., min_length=1, max_length=64),
    incident_id: int = Path(..., ge=1),
    decision_id: int = Path(..., ge=1),
    info: sessions.SessionInfo = Depends(session_analyst_plus),
) -> DecisionResponse:
    """Confirm / decline a client's pending request (a Black "allow"):
    recorded; nothing is unblocked in slice 1."""
    _scoped_slug(info, slug)
    _restricted_gate(info, _load(slug, incident_id), "incident.decision_answer")
    _audit(info, "incident.decision_answer", slug, str(incident_id),
           after={"decision": decision_id, "confirm": body.confirm}, reason=body.note)
    try:
        decision = store.answer_decision(slug, incident_id, decision_id,
                                         by=str(info.operator_id), confirm=body.confirm,
                                         note=body.note)
    except (store.StoreError, sqlite3.Error) as exc:
        _failed(info, "incident.decision_answer", slug, str(incident_id), exc)
        raise _store_error(exc) from None
    _changed(slug)
    inc = _load(slug, incident_id)
    return DecisionResponse(incident=_out(inc, names=_names([inc]),
                                          tenant_names=_tenant_names(), now=_now(),
                                          admin=_admin(info)),
                            decision=decision)


# ---------------------------------------------------------------------------
# Declare (B6) and confirm (R8)
# ---------------------------------------------------------------------------

def _open_human(info: sessions.SessionInfo, slug: str, *, tier: str, summary: str,
                reason: str, site_key: Optional[str], device_ref: Optional[str],
                device_label: Optional[str], event_id: Optional[int]) -> store.Incident:
    rule = rules.human_rule(tier)
    if event_id is not None:
        row = store.event_row(slug, event_id)
        if row is None:
            raise APIError("NOT_FOUND", "no such signal in your scope")
        if row.get("source") == store.EVENT_SOURCE:
            raise APIError("VALIDATION_FAILED", "an incident's own record is not a signal — "
                                                "act on the incident instead")
    if site_key is not None and site_key not in sources.tenant_site_keys(slug):
        # Another client's site would put THAT site's perimeter in a later
        # lockdown request while only this client's life-safety assets are
        # carved out.
        raise APIError("VALIDATION_FAILED", "that site is not one of this client's sites")
    key = store.dedupe_key(slug, device_ref=device_ref, site_key=site_key, family=rule.family,
                           anchor=f"event:{event_id}" if event_id is not None else "")
    scope = "device" if device_ref else "site" if site_key else "tenant"
    now = _now()
    from apps.octo.threat import intake

    blind = []
    try:
        blind = [b.as_dict() for b in intake.blind_sources(None, now) if b.covers(slug)
                 or b.source == "tier_worker"]
    except Exception:  # noqa: BLE001
        blind = []
    # G8: the per-source freshness matrix, frozen with the evidence.
    evidence = {"declared_by": info.operator_id, "event_id": event_id,
                "freshness": intake.freshness(slug, now), "blind": blind}
    # Audit BEFORE the write, naming what is about to happen on this key
    # (open, or append / raise / reopen the record already there).
    try:
        action = f"incident.{store.predict(slug, key, tier, now)}"
    except sqlite3.Error:
        raise APIError("SERVICE_UNAVAILABLE", "the incident store could not be read") from None
    _audit(info, action, slug, None,
           after={"tier": tier, "rule": rule.id, "key": key, "site_key": site_key,
                  "device_ref": device_ref, "event_id": event_id}, reason=reason)
    try:
        opened = store.open_incident(
            slug, tier=tier, rule_id=rule.id, rule_version=rule.version, key=key,
            summary=summary, scope=scope, opened_by=str(info.operator_id), reason=reason,
            site_key=site_key, device_ref=device_ref, device_label=device_label or device_ref,
            evidence=evidence, event_ids=[event_id] if event_id is not None else [],
            now=now)
    except (store.StoreError, sqlite3.Error, ValueError) as exc:
        _failed(info, action, slug, None, exc)
        raise _store_error(exc) if not isinstance(exc, ValueError) else \
            APIError("VALIDATION_FAILED", str(exc)) from None
    if opened.incident is None:
        # A person's declaration is never blocked by a verdict (store); kept
        # so a future path that is blocked says so in the audit log too.
        _failed(info, action, slug, None, store.Refused("an analyst verdict blocks this key"))
        raise APIError("CONFLICT", "an analyst verdict blocks this exact key (a false-positive "
                                   "close) — it is not opened again")
    actual = f"incident.{store.OUTCOME_ACTION.get(opened.outcome, opened.outcome)}"
    if actual != action:
        # A race changed what happened between the prediction and the write.
        taudit.human(info.operator_id, actual, slug, "incident", str(opened.incident.id),
                     after={"tier": opened.incident.tier, "rule": rule.id},
                     reason=f"the same key: {opened.outcome} (not {action})")
    _changed(slug)
    _page(opened.incident)
    return opened.incident


@router.post("/declare", response_model=IncidentOut)
def declare_black(
    body: DeclareIn,
    info: sessions.SessionInfo = Depends(session_analyst_plus),
) -> IncidentOut:
    """B6 — "the client calls: someone is controlling my screen": a bare
    device, a site or a signal declared BLACK, with a reason. Pulse, page
    and audit within seconds."""
    _scoped_slug(info, body.tenant)
    inc = _open_human(info, body.tenant, tier=store.BLACK, summary=body.summary,
                      reason=body.reason, site_key=body.site_key, device_ref=body.device_ref,
                      device_label=body.device_label, event_id=body.event_id)
    return _out(inc, names=_names([inc]), tenant_names=_tenant_names(), now=_now(),
                admin=_admin(info))


@signals_router.post("/{slug}/{event_id}/confirm", response_model=IncidentOut)
def confirm_signal(
    body: ConfirmIn,
    slug: str = Path(..., min_length=1, max_length=64),
    event_id: int = Path(..., ge=1),
    info: sessions.SessionInfo = Depends(session_analyst_plus),
) -> IncidentOut:
    """R8 — "Confirm as threat" on a Yellow signal: RED, reason ≥ 20
    characters."""
    _scoped_slug(info, slug)
    row = store.event_row(slug, event_id)
    if row is None:
        raise APIError("NOT_FOUND", "no such signal in your scope")
    summary = body.summary or f"confirmed threat: {row.get('event_type') or 'signal'}"
    device = (row.get("source_host") or "").strip() or None
    inc = _open_human(info, slug, tier=store.RED, summary=summary, reason=body.reason,
                      site_key=None, device_ref=device, device_label=device,
                      event_id=event_id)
    _confirmed_label(info, slug, event_id, inc, body.reason)
    return _out(inc, names=_names([inc]), tenant_names=_tenant_names(), now=_now(),
                admin=_admin(info))


def _confirmed_label(info: sessions.SessionInfo, slug: str, event_id: int,
                     inc: store.Incident, reason: str) -> None:
    """R8's human verdict as a training label (`alert_verdict`, v0.17.2):
    audited before it is written; never fails the confirmation (the Red is
    open whatever happens here)."""
    from apps.octo.db import connect, transaction
    from apps.octo.verdicts import annotate, occurrences
    from apps.octo.verdicts import store as vstore

    try:
        row = occurrences.event_rows(slug, [event_id]).get(event_id)
        if row is None:
            return
        a = annotate.one(slug, row)
        taudit.human(info.operator_id, "alert.confirmed", slug, "alert", f"{slug}:{event_id}",
                     after={"event_id": event_id, "signature_key": a.key.signature_key,
                            "incident_id": inc.id}, reason=reason)
        reg = connect(paths.registry_db_path())
        try:
            with transaction(reg):
                vstore.record(reg, slug=slug, event_id=event_id, key=a.key,
                              verdict=vstore.CONFIRMED, actor=info.operator_id, note=reason,
                              hits_at=a.hits, last_seen_at=a.last_seen, incident_id=inc.id)
        finally:
            reg.close()
    except Exception as exc:  # noqa: BLE001
        logger.warning("[incidents] the R8 verdict label of %s:%s not written (%s)", slug,
                       event_id, type(exc).__name__)
        try:
            taudit.human(info.operator_id, "alert.confirmed_failed", slug, "alert",
                         f"{slug}:{event_id}", after={"error": type(exc).__name__},
                         reason="the verdict label was not written")
        except Exception:  # noqa: BLE001
            pass
