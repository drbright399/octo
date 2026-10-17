"""NextDNS — the profile mapping panel and the on-demand investigation.

  GET  /api/v1/integrations/nextdns/{instance_id}/profiles   admin+, no-store
  PUT  /api/v1/integrations/nextdns/{instance_id}/profiles   admin+, audited
  POST /api/v1/search/nextdns                                analyst+, step-up,
                                                             scoped, audited

PROFILES. What the wizard's mapping step and the card's "Tenant mapping"
show for NextDNS: every profile the account lists (from the LAST discovery —
the poller's, first thing after a start and then every 10 min while nothing
is watched / every 6 h once profiles are, or the panel's Reload through the
generic vendor-tenants route; this route never contacts NextDNS), each with its
mapping, its ignore mark, a name-match SUGGESTION for an unmapped one (legal
suffixes kept; confirmed row by row — PUT refuses a NEW 'auto-name' mapping,
the same-name rule), and
the protection state the poller last saw (active / pending / lapsed, queries
in 24 h). Many profiles may map to one tenant. A profile is never mapped and
ignored at once. Unmapped and ignored profiles are never polled.

PUT replaces the instance's mappings (the generic route's rules: frozen rows
of inactive tenants are kept verbatim, a client must exist) AND its ignore
list, both audited (`adapter_tenant_map_replace`, `adapter_vendor_tenants_
ignore`) before anything is written; saving nudges the poller (the first
import starts at once).

SEARCH (on-demand investigation, API only this release). A live NextDNS
logs query for ONE tenant's mapped profiles — domain (and its subdomains)
and/or device (id, name or client IP), a window of at most 7 days, any
status — through the SAME per-key rate limiter as the poller, at
investigation priority, bounded pages. The gate is exactly POST /search/dns:
analyst+ checked BEFORE the step-up (a viewer gets 403, not a re-auth
prompt), the tenant must be a valid slug in the caller's scope ('*' is never
a tenant), step-up required, one audit row per call (`search.nextdns`; the
query recorded as hashes). Results are NOT stored. Domains come back
MASKED by the IOC rule (`api.indicator_mask` — the same rule as the pulse
and the alert detail); device names, models and client IPs are shown.
RESTRICTED (v0.17.1): a line with a CSAM reason — or naming a domain the
tenant holds as restricted evidence — is never returned (not even masked;
only an ADMIN's note counts the lines withheld), and such a domain (or a
name under it) is never searched for: no vendor call; an admin gets a 422
saying why, anyone else exactly the answer of a search with no hits —
nothing confirms a guess or names a device. Audited either way
(`restricted_refused`, `restricted_withheld`).
"""
from __future__ import annotations

import hashlib
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, Path, Request, Response
from pydantic import BaseModel, Field

from apps.octo import paths
from apps.octo.api.errors import APIError
from apps.octo.api.indicator_mask import mask_indicator
from apps.octo.api.role_gates import (
    ROLE_TIER,
    operator_max_tier,
    resolve_caller_scope,
    session_admin_plus,
)
from apps.octo.api.routers.dns_summary import _analyst_step_up, _is_active
from apps.octo.auth import audit, sessions
from apps.octo.db import connect
from apps.octo.ingest import tiering
from apps.octo.instances import ignored_tenants, tenant_map, vendor_tenants

router = APIRouter(prefix="/integrations/nextdns", tags=["integrations"])
search_router = APIRouter(prefix="/search", tags=["search"])

VENDOR = "nextdns"
MAX_PROFILES = 2_000
SEARCH_MAX_PROFILES = 10
SEARCH_MAX_PAGES = 5
SEARCH_MAX_WAIT_SEC = 30.0
MAX_WINDOW_HOURS = 168


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class SuggestionOut(BaseModel):
    tenant_slug: str
    tenant_name: str
    rule: Literal["same-name", "name-prefix"]
    bulk: bool = True
    """False: the profile's name reads like a personal / test profile
    ("Acme Corp Home", "… Test") — offered on its row only, never by the
    panel's "Use N suggestions"."""


class ProfileOut(BaseModel):
    profile_id: str
    name: str
    listed: bool
    """Still in NextDNS's profile list (False = mapped / ignored earlier and
    gone since, or no discovery yet)."""
    tenant_slug: Optional[str] = None
    tenant_name: Optional[str] = None
    tenant_status: Optional[str] = None
    match_source: Optional[str] = None
    ignored: bool = False
    suggestion: Optional[SuggestionOut] = None
    state: Optional[str] = None
    """Protection as the poller last saw it: new | pending | active | lapsed
    (None = not polled — unmapped / ignored)."""
    state_since: Optional[str] = None
    queries_24h: Optional[int] = None
    missing: bool = False
    """NextDNS no longer shows this mapped profile to the key (HTTP 404)."""
    problem: Optional[str] = None
    """The poller's current problem with this profile (operator text), if any."""


class ProfileCountsOut(BaseModel):
    known: Optional[int]
    mapped: int
    ignored: int
    unmapped: Optional[int]
    active: int
    pending: int
    lapsed: int
    missing: int = 0


class ProfilesResponse(BaseModel):
    instance_id: int
    discovered: bool
    """False: no profile listing since the service started — press Reload
    (one NextDNS call) to list them."""
    fetched_at: Optional[str] = None
    profiles: list[ProfileOut]
    counts: ProfileCountsOut


class ProfileMappingIn(BaseModel):
    profile_id: str = Field(min_length=1, max_length=64)
    tenant_slug: str = Field(min_length=1, max_length=64)
    # 'auto-name' only for a stored name-matched row sent back UNCHANGED (it
    # stays unconfirmed); a new one is refused — a confirmed suggestion is
    # the operator's decision, 'manual' (`integration_mappings._validated`).
    match_source: Literal["manual", "auto-name"] = "manual"


class SetProfilesRequest(BaseModel):
    mappings: list[ProfileMappingIn] = Field(default_factory=list, max_length=MAX_PROFILES)
    ignored: list[str] = Field(default_factory=list, max_length=MAX_PROFILES)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _record(instance_id: int):
    from apps.octo.instances.manager import get_instance

    record = get_instance(instance_id)
    if record is None or record.vendor_slug != VENDOR:
        raise APIError("NOT_FOUND", f"no NextDNS integration with id {instance_id}")
    if record.disabled_at is not None:
        raise APIError("CONFLICT", f"NextDNS integration {instance_id} is disabled")
    return record


def _running_adapter(request: Request, instance_id: int) -> Any:
    manager = getattr(request.app.state, "instance_manager", None)
    return manager.running_adapter(instance_id) if manager is not None else None


def _clients() -> dict[str, tuple[str, str]]:
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        return {
            r["slug"]: (r["display_name"], r["status"])
            for r in reg.execute("SELECT slug, display_name, status FROM clients")
        }
    finally:
        reg.close()


# Words that mark a profile as someone's own / a test rather than a site: such
# a profile may still be suggested on its row, never in a bulk accept.
_PERSONAL_WORDS = frozenset({
    "test", "testing", "home", "personal", "lab", "sandbox", "demo", "dev", "staging",
    "family", "kids", "private", "mine", "temp",
})


def _words(value: str) -> tuple[str, ...]:
    """Casefolded words of a name, legal suffixes KEPT (so "Acme Corp" is
    two words, like the start of "Acme Corp Office"), a leading "the"
    dropped."""
    import re
    import unicodedata

    text = unicodedata.normalize("NFKD", value[:256])
    text = "".join(c for c in text if not unicodedata.combining(c)).casefold()
    words = [w for w in re.split(r"[^0-9a-z]+", text.replace("&", " and ")) if w]
    if len(words) > 1 and words[0] == "the":
        words = words[1:]
    return tuple(words)


def suggest(
    profile_name: str, clients: dict[str, tuple[str, str]],
) -> Optional[tuple[str, str, str]]:
    """The ACTIVE client a profile's name points at, or None: the same name
    (`exact_name_key` — case, accents, punctuation; legal suffixes KEPT, so
    "Acme Pharmacy LLC" never suggests "Acme Pharmacy, Inc."), else the one
    client whose name as written — at least DUPLICATE_MIN_PREFIX_WORDS
    words, the platform's own floor — is the leading part of the profile's
    ("Acme Corp" for "Acme Corp Office"; a lone "Globex" is too generic to
    pair with "Globex Home"). Never a guess between two: an ambiguous name
    has no suggestion. A suggestion is only offered: the operator confirms
    it ROW BY ROW (it is then saved as their decision, 'manual'); nothing is
    ever saved from a name by itself."""
    from apps.octo.instances.tenant_lifecycle import (
        DUPLICATE_MIN_PREFIX_WORDS,
        exact_name_key,
    )

    key = exact_name_key(profile_name)
    if not key:
        return None
    active = [(slug, name) for slug, (name, status) in clients.items() if status == "active"]
    same = [(s, n) for s, n in active if exact_name_key(n) == key]
    if len(same) == 1:
        return same[0][0], same[0][1], "same-name"
    if same:
        return None
    words = _words(profile_name)
    prefix = []
    for slug, name in active:
        # The client's words as written: legal suffixes kept.
        ck = _words(name)
        if (len(ck) >= DUPLICATE_MIN_PREFIX_WORDS and len(ck) < len(words)
                and words[: len(ck)] == ck):
            prefix.append((slug, name, len(ck)))
    if not prefix:
        return None
    longest = max(p[2] for p in prefix)
    best = [p for p in prefix if p[2] == longest]
    if len(best) != 1:
        return None
    return best[0][0], best[0][1], "name-prefix"


def _profiles_response(request: Request, record: Any) -> ProfilesResponse:
    discovery = vendor_tenants.latest(record.id, record.cred_ref)
    listed = {t.id: t.label for t in discovery.tenants} if discovery else {}
    try:
        mappings = {m.vendor_tenant_id: m for m in tenant_map.get_mappings(record.id)}
    except sqlite3.OperationalError:
        mappings = {}
    ignored = {t.vendor_tenant_id: t for t in ignored_tenants.get_ignored(record.id)}
    clients = _clients()
    adapter = _running_adapter(request, record.id)
    states: dict[str, dict] = {}
    if adapter is not None and getattr(adapter, "poller", None) is not None:
        try:
            states = adapter.poller.profile_states()
        except Exception:  # noqa: BLE001 — a panel never fails for a snapshot
            states = {}
    out: list[ProfileOut] = []
    for pid in sorted(set(listed) | set(mappings) | set(ignored)):
        m = mappings.get(pid)
        ig = ignored.get(pid)
        name = listed.get(pid) or (m.vendor_tenant_label if m else None) or (
            ig.vendor_tenant_label if ig else None) or f"Profile {pid}"
        st = states.get(pid) or {}
        tenant_name, tenant_status = (clients.get(m.octo_client_slug, (None, "missing"))
                                      if m else (None, None))
        sug = None
        if m is None and ig is None:
            found = suggest(name, clients)
            if found:
                sug = SuggestionOut(
                    tenant_slug=found[0], tenant_name=found[1], rule=found[2],
                    bulk=not (set(_words(name)) & _PERSONAL_WORDS),
                )
        out.append(ProfileOut(
            profile_id=pid, name=name, listed=pid in listed,
            tenant_slug=m.octo_client_slug if m else None,
            tenant_name=tenant_name, tenant_status=tenant_status,
            match_source=m.match_source if m else None,
            ignored=ig is not None and m is None,
            suggestion=sug,
            state=st.get("state") if m else None,
            state_since=st.get("since") if m else None,
            queries_24h=st.get("queries_24h") if m else None,
            missing=bool(st.get("missing")) if m else False,
            problem=st.get("problem") if m else None,
        ))
    order = {True: 0, False: 1}
    out.sort(key=lambda p: (
        order[p.tenant_slug is None and not p.ignored],   # needs attention first
        1 if p.ignored else 0, p.name.lower(), p.profile_id,
    ))
    counts = ProfileCountsOut(
        known=len(listed) if discovery else None,
        mapped=sum(1 for p in out if p.tenant_slug),
        ignored=sum(1 for p in out if p.ignored),
        unmapped=(sum(1 for p in out if p.listed and not p.tenant_slug and not p.ignored)
                  if discovery else None),
        active=sum(1 for p in out if p.state == "active"),
        pending=sum(1 for p in out if p.state == "pending"),
        lapsed=sum(1 for p in out if p.state == "lapsed"),
        missing=sum(1 for p in out if p.missing),
    )
    return ProfilesResponse(
        instance_id=record.id, discovered=discovery is not None,
        fetched_at=discovery.fetched_at if discovery else None,
        profiles=out, counts=counts,
    )


# ---------------------------------------------------------------------------
# Profiles
# ---------------------------------------------------------------------------

@router.get("/{instance_id}/profiles", response_model=ProfilesResponse)
def get_profiles(
    request: Request,
    response: Response,
    instance_id: int = Path(...),
    caller: sessions.SessionInfo = Depends(session_admin_plus),
) -> ProfilesResponse:
    """Local state only — never a NextDNS call. Profile names are client
    names: no-store."""
    response.headers["Cache-Control"] = "no-store"
    return _profiles_response(request, _record(instance_id))


@router.put("/{instance_id}/profiles", response_model=ProfilesResponse)
def put_profiles(
    body: SetProfilesRequest,
    request: Request,
    response: Response,
    instance_id: int = Path(...),
    caller: sessions.SessionInfo = Depends(session_admin_plus),
) -> ProfilesResponse:
    from apps.octo.adapters.nextdns.client import valid_profile_id
    from apps.octo.api.routers.integration_mappings import (
        SetTenantMappingsRequest,
        TenantMappingIn,
        _audit_replace,
        _stored_mappings,
        _validated,
    )

    response.headers["Cache-Control"] = "no-store"
    record = _record(instance_id)
    mapped_ids: list[str] = []
    for n, m in enumerate(body.mappings, start=1):
        if valid_profile_id(m.profile_id) is None:
            raise APIError("VALIDATION_FAILED",
                           f"mapping {n}: {m.profile_id[:32]!r} is not a NextDNS profile id")
        mapped_ids.append(m.profile_id)
    if len(set(mapped_ids)) != len(mapped_ids):
        raise APIError("VALIDATION_FAILED",
                       "a profile maps to exactly one tenant — it is listed twice")
    ignored_ids: list[str] = []
    for pid in body.ignored:
        if valid_profile_id(pid) is None:
            raise APIError("VALIDATION_FAILED", f"{pid[:32]!r} is not a NextDNS profile id")
        if pid not in ignored_ids:
            ignored_ids.append(pid)
    both = sorted(set(mapped_ids) & set(ignored_ids))
    if both:
        raise APIError(
            "VALIDATION_FAILED",
            f"profile {both[0]!r} cannot be both mapped and ignored — map it, or ignore it",
        )
    discovery = vendor_tenants.latest(record.id, record.cred_ref)
    labels = {t.id: t.label for t in discovery.tenants} if discovery else {}
    before = _stored_mappings(record.id)
    stored_labels = {m.vendor_tenant_id: m.vendor_tenant_label for m in before}
    for t in ignored_tenants.get_ignored(record.id):
        stored_labels.setdefault(t.vendor_tenant_id, t.vendor_tenant_label)
    generic = SetTenantMappingsRequest(mappings=[
        TenantMappingIn(
            vendor_tenant_id=m.profile_id, octo_client_slug=m.tenant_slug,
            vendor_tenant_label=labels.get(m.profile_id) or stored_labels.get(m.profile_id),
            match_source=m.match_source,
        )
        for m in body.mappings
    ])
    clients = {slug: (name, status) for slug, (name, status) in _clients().items()}
    mappings = _validated(generic, VENDOR, record.id, clients=clients, stored=before)
    # A frozen row the body did not carry is kept by _validated; it must not
    # also be ignored.
    frozen_and_ignored = sorted({m.vendor_tenant_id for m in mappings} & set(ignored_ids))
    if frozen_and_ignored:
        raise APIError(
            "VALIDATION_FAILED",
            f"profile {frozen_and_ignored[0]!r} is mapped to a departed tenant (a frozen "
            "mapping) and cannot be ignored",
        )
    before_ignored = sorted(ignored_tenants.ignored_ids(record.id))
    # Audit FIRST (a failed audit write changes nothing).
    _audit_replace(operator_id=caller.operator_id, vendor_slug=VENDOR,
                   instance_id=record.id, before=before, after=mappings)
    g_audit = connect(paths.global_audit_db_path())
    try:
        audit.append(g_audit, audit.AuditEntry(
            actor=str(caller.operator_id), actor_kind="human",
            action="adapter_vendor_tenants_ignore",
            target_kind="adapter_instance", target_id=str(record.id), client_slug="global",
            before_state={"vendor_slug": VENDOR, "ignored": before_ignored},
            after_state={"vendor_slug": VENDOR, "ignored": sorted(ignored_ids)},
            reason="NextDNS profiles ignored via the mapping panel",
            request_id=str(uuid.uuid4()),
        ))
    finally:
        g_audit.close()
    tenant_map.set_mappings(record.id, mappings, operator_id=caller.operator_id)
    ignored_tenants.set_ignored(
        record.id, [(pid, labels.get(pid) or stored_labels.get(pid)) for pid in ignored_ids],
        operator_id=caller.operator_id,
    )
    manager = getattr(request.app.state, "instance_manager", None)
    if manager is not None:
        manager.nudge(record.id)
    return _profiles_response(request, record)


# ---------------------------------------------------------------------------
# On-demand investigation
# ---------------------------------------------------------------------------

class NextDnsSearchRequest(BaseModel):
    tenant: str = Field(min_length=1, max_length=64)
    domain: Optional[str] = Field(default=None, max_length=253)
    device: Optional[str] = Field(default=None, max_length=128)
    hours: int = Field(default=24, ge=1, le=MAX_WINDOW_HOURS)
    status: Literal["any", "blocked", "allowed", "default"] = "any"
    limit: int = Field(default=200, ge=1, le=1000)


class ReasonOut(BaseModel):
    id: str
    name: str
    signal_level: Optional[str]
    """high / medium / low when the reason is a security signal, else None."""


class NextDnsLogOut(BaseModel):
    timestamp: str
    profile_id: str
    profile_name: str
    masked_domain: str
    masked_root: Optional[str] = None
    status: str
    reasons: list[ReasonOut]
    signal_level: Optional[str] = None
    device_name: Optional[str] = None
    device_id: Optional[str] = None
    device_model: Optional[str] = None
    client_ip: Optional[str] = None
    protocol: Optional[str] = None


class NextDnsSearchResponse(BaseModel):
    tenant: str
    window_hours: int
    status: str
    query_domain: Optional[str]
    query_device: Optional[str]
    profiles_searched: list[str]
    results: list[NextDnsLogOut]
    truncated: bool
    masked: bool = True
    stored: bool = False
    note: str


def _sha16(text: Optional[str]) -> Optional[str]:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16] if text else None


def _clean(value: Any, limit: int) -> Optional[str]:
    if not isinstance(value, str):
        return None
    text = " ".join("".join(c if c.isprintable() else " " for c in value).split())[:limit]
    return text or None


def _log_out(pid: str, name: str, line: dict[str, Any]) -> NextDnsLogOut:
    from apps.octo.adapters.nextdns.classification import classify_line, classify_reason

    device = line.get("device") if isinstance(line.get("device"), dict) else {}
    reasons_raw = line.get("reasons") if isinstance(line.get("reasons"), list) else []
    reasons = []
    for r in reasons_raw[:16]:
        if not isinstance(r, dict):
            continue
        rid = _clean(r.get("id"), 96) or ""
        reasons.append(ReasonOut(id=rid, name=_clean(r.get("name"), 96) or rid,
                                 signal_level=classify_reason(rid, r.get("name")).level))
    domain = _clean(line.get("domain"), 253) or ""
    root = _clean(line.get("root"), 253)
    status = _clean(line.get("status"), 16) or "unknown"
    return NextDnsLogOut(
        timestamp=_clean(line.get("timestamp"), 40) or "",
        profile_id=pid, profile_name=name,
        masked_domain=mask_indicator(domain, "domain"),
        masked_root=mask_indicator(root, "domain") if root else None,
        status=status,
        reasons=reasons,
        signal_level=classify_line(reasons_raw).level if status == "blocked" else None,
        device_name=_clean(device.get("name"), 96),
        device_id=_clean(device.get("id"), 64),
        device_model=_clean(device.get("model"), 96),
        client_ip=_clean(line.get("clientIp"), 64),
        protocol=_clean(line.get("protocol"), 32),
    )


@search_router.post("/nextdns", response_model=NextDnsSearchResponse)
def search_nextdns(
    body: NextDnsSearchRequest,
    request: Request,
    response: Response,
    info: sessions.SessionInfo = Depends(_analyst_step_up),
) -> NextDnsSearchResponse:
    from apps.octo.adapters.nextdns.client import (
        NextDNSAuthError,
        NextDNSBusyError,
        NextDNSClientError,
        NextDNSThrottledError,
    )
    from apps.octo.api.routers.auth import _audit_append

    response.headers["Cache-Control"] = "no-store"
    if operator_max_tier(info.operator_id) < ROLE_TIER["analyst"]:   # defence in depth
        raise APIError("ISOLATION_VIOLATION", "this action requires at least the 'analyst' role")
    try:
        paths.validate_slug(body.tenant)
    except paths.SlugError:
        raise APIError("ISOLATION_VIOLATION")
    scope = resolve_caller_scope(info.operator_id)
    allowed = (body.tenant != "*" and body.tenant in scope) or (
        scope == ["*"] and _is_active(body.tenant))
    if not allowed:
        raise APIError("ISOLATION_VIOLATION")
    domain = tiering.normalize_domain(body.domain) if body.domain else None
    device = tiering.normalize_device(body.device) if body.device else None
    if body.domain and not domain:
        raise APIError("VALIDATION_FAILED", "domain is not a usable DNS name")
    if body.device and not device:
        raise APIError("VALIDATION_FAILED", "device is not a usable device name / address")
    if not domain and not device:
        raise APIError("VALIDATION_FAILED",
                       "give a domain and/or a device — a whole tenant's DNS log is never "
                       "pulled into Athena")
    from apps.octo.threat import restricted

    admin = operator_max_tier(info.operator_id) >= ROLE_TIER["admin"]
    refused = False
    if domain:
        # RESTRICTED (rule B7, CSAM): a domain the tenant holds as restricted
        # evidence (or a name under it) is never looked up — not even in DNS
        # logs. The list unreadable: 503 for everyone (tenant-wide, it names
        # nothing).
        try:
            known = restricted.restricted_domains(body.tenant)
        except (sqlite3.Error, OSError):
            raise APIError("SERVICE_UNAVAILABLE", "the tenant's event store could not be "
                                                  "read; nothing was searched") from None
        refused = restricted.matches(domain, known)
    manager = getattr(request.app.state, "instance_manager", None)
    running = [
        r for r in (manager.list_running() if manager is not None else [])
        if r.vendor_slug == VENDOR
    ]
    if not running:
        raise APIError("CONFLICT", "no NextDNS integration is running")
    record = running[0]
    adapter = manager.running_adapter(record.id)
    try:
        mapped = [m for m in tenant_map.get_mappings(record.id)
                  if m.octo_client_slug == body.tenant]
    except sqlite3.OperationalError:
        mapped = []
    if not mapped:
        raise APIError("NOT_FOUND", "no NextDNS profile is mapped to this tenant")
    profiles = [(m.vendor_tenant_id, m.vendor_tenant_label or m.vendor_tenant_id)
                for m in mapped][:SEARCH_MAX_PROFILES]
    now = datetime.now(timezone.utc)
    request_id = str(uuid.uuid4())
    outcome, results, truncated, calls, withheld = "ok", [], False, 0, 0
    error: Optional[APIError] = None
    if refused:
        # A restricted domain: NO vendor call. An admin is told why (and may
        # open the incident); anyone else gets exactly what a search with no
        # hits returns — nothing confirms a guess. Audited either way.
        outcome = "restricted_refused"
        if admin:
            error = APIError("VALIDATION_FAILED", "a domain from a restricted incident is never "
                                                  "resolved, fetched, enriched or previewed — "
                                                  "open the restricted incident instead")
    else:
        try:
            found, truncated, calls = adapter.investigate(
                profiles, since=now - timedelta(hours=body.hours), until=now,
                domain=domain, device=device,
                status=None if body.status == "any" else body.status,
                limit=body.limit, max_pages_per_profile=SEARCH_MAX_PAGES,
                max_wait_sec=SEARCH_MAX_WAIT_SEC,
            )
            from apps.octo.adapters.nextdns.classification import line_is_csam

            # A RESTRICTED (CSAM) line — or any line naming a domain the
            # tenant holds as restricted evidence — is never shown here, not
            # even masked: it is restricted evidence, seen only in its
            # admin-only incident.
            gate = restricted.Gate.for_tenant(body.tenant)

            def _hidden(line: dict[str, Any]) -> bool:
                return line_is_csam(line.get("reasons")) or gate.hits(
                    line.get("domain"), line.get("root"))

            withheld = sum(1 for _p, _n, line in found if _hidden(line))
            results = [_log_out(pid, name, line) for pid, name, line in found
                       if not _hidden(line)]
        except (NextDNSThrottledError, NextDNSBusyError) as exc:
            outcome = "throttled"
            error = APIError("SERVICE_UNAVAILABLE",
                             f"{exc}. Nothing was searched; try again then.")
        except NextDNSAuthError:
            outcome = "auth"
            error = APIError("VENDOR_CREDENTIALS_REJECTED",
                             "NextDNS rejected the stored API key — see Settings → Integrations.")
        except NextDNSClientError as exc:
            outcome = "error"
            error = APIError("VENDOR_UNREACHABLE", f"NextDNS could not be searched: {exc}")
    _audit_append(
        "search.nextdns",
        actor=f"operator:{info.operator_id}",
        target_id=info.id[:8],
        before=None,
        after={
            "tenants": [body.tenant],
            "hours": body.hours,
            "status": body.status,
            "limit": body.limit,
            "profiles_searched": len(profiles),
            "vendor_calls": calls,
            "outcome": outcome,
            "rows_returned": len(results),
            "restricted_refused": refused,
            "restricted_withheld": withheld,
            "truncated": truncated,
            "has_domain_query": bool(domain),
            "domain_query_hash": _sha16(domain),
            "has_device_query": bool(device),
            "device_query_hash": _sha16(device),
            "ip": request.client.host if request.client else None,
        },
        reason="NextDNS live logs investigation (masked domains, not stored)",
        request_id=request_id,
    )
    if error is not None:
        raise error
    return NextDnsSearchResponse(
        tenant=body.tenant, window_hours=body.hours, status=body.status,
        query_domain=domain, query_device=device,
        profiles_searched=[pid for pid, _ in profiles],
        results=results, truncated=truncated,
        note=(
            "Live from NextDNS, not stored in Athena. Domains are masked (the IOC rule); "
            "the domain you searched for is echoed as typed. Newest first, at most "
            f"{SEARCH_MAX_PAGES} pages per profile."
            # Only an admin reads that lines were withheld: for anyone else
            # it would say which device (or name) a restricted incident is
            # about. The count is in the audit row either way.
            + (f" {withheld} restricted-category line{'' if withheld == 1 else 's'} withheld "
               "(open the restricted incident)."
               if withheld and admin else "")
        ),
    )
