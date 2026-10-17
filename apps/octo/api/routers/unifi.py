"""UniFi — the site mapping panel.

  GET /api/v1/integrations/unifi/{instance_id}/sites   admin+, no-store
  PUT /api/v1/integrations/unifi/{instance_id}/sites   admin+, audited

What the wizard's mapping step and the card's "Tenant mapping" show for
UniFi: every site of every console (from the LAST fleet poll / discovery —
this route never contacts UniFi; the panel's Reload goes through the generic
vendor-tenants route, two calls), keyed "<hostId>/<siteId>" (site ids collide
across consoles), each with its console, its LOCATION text and time zone (two
businesses with one name separate on geography), its WAN addresses and ISP,
whether its gateway is online, its mapping, its ignore mark, and — for an
unmapped one — a same-name SUGGESTION (legal suffixes kept, one client only).

NO BULK ACCEPT (the same-name rule, 2026-10-01): a mapping is the operator's
decision for that site, saved as 'manual'; PUT takes no match source at all.
Many sites may map to one tenant; a site is never mapped and ignored at once;
unmapped and ignored sites are never polled. Mappings of the retired
local-controller adapter (a bare site id) are listed read-only and kept.

PUT replaces the instance's mappings (the generic route's rules: frozen rows
of inactive tenants are kept verbatim, the client must exist) AND its ignore
list, both audited before anything is written; saving nudges the poller.
"""
from __future__ import annotations

import sqlite3
import uuid
from typing import Any, Optional

from fastapi import APIRouter, Depends, Path, Request, Response
from pydantic import BaseModel, Field

from apps.octo import paths
from apps.octo.api.errors import APIError
from apps.octo.api.role_gates import session_admin_plus
from apps.octo.auth import audit, sessions
from apps.octo.db import connect
from apps.octo.instances import ignored_tenants, tenant_map, vendor_tenants

router = APIRouter(prefix="/integrations/unifi", tags=["integrations"])

VENDOR = "unifi"
MAX_SITES = 5_000


class SuggestionOut(BaseModel):
    tenant_slug: str
    tenant_name: str
    rule: str = "same-name"


class WanOut(BaseModel):
    wan: str
    external_ip: Optional[str] = None
    isp: Optional[str] = None
    asn: Optional[int] = None
    shared_external: bool = False


class SiteOut(BaseModel):
    scope: str
    host_id: str
    site_id: str
    name: str
    console_name: str = ""
    location_text: Optional[str] = None
    timezone: Optional[str] = None
    wans: list[WanOut] = Field(default_factory=list)
    gateway_online: Optional[bool] = None
    host_connected: Optional[bool] = None
    listed: bool
    """In UniFi's site list at the last fleet poll / discovery."""
    tenant_slug: Optional[str] = None
    tenant_name: Optional[str] = None
    tenant_status: Optional[str] = None
    match_source: Optional[str] = None
    ignored: bool = False
    suggestion: Optional[SuggestionOut] = None
    problem: Optional[str] = None
    last_syslog_at: Optional[str] = None
    clients: Optional[int] = None


class LegacyMappingOut(BaseModel):
    vendor_tenant_id: str
    tenant_slug: str
    tenant_name: Optional[str] = None


class SiteCountsOut(BaseModel):
    known: Optional[int]
    mapped: int
    ignored: int
    unmapped: Optional[int]
    gateways_offline: int = 0
    problems: int = 0


class SitesResponse(BaseModel):
    instance_id: int
    discovered: bool
    fetched_at: Optional[str] = None
    sites: list[SiteOut]
    legacy: list[LegacyMappingOut] = Field(default_factory=list)
    counts: SiteCountsOut


class SiteMappingIn(BaseModel):
    scope: str = Field(min_length=3, max_length=320)
    tenant_slug: str = Field(min_length=1, max_length=64)


class SetSitesRequest(BaseModel):
    mappings: list[SiteMappingIn] = Field(default_factory=list, max_length=MAX_SITES)
    ignored: list[str] = Field(default_factory=list, max_length=MAX_SITES)


def _record(instance_id: int):
    from apps.octo.instances.manager import get_instance

    record = get_instance(instance_id)
    if record is None or record.vendor_slug != VENDOR:
        raise APIError("NOT_FOUND", f"no UniFi integration with id {instance_id}")
    if record.disabled_at is not None:
        raise APIError("CONFLICT", f"UniFi integration {instance_id} is disabled")
    return record


def _running_adapter(request: Request, instance_id: int) -> Any:
    manager = getattr(request.app.state, "instance_manager", None)
    return manager.running_adapter(instance_id) if manager is not None else None


def _clients() -> dict[str, tuple[str, str]]:
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        return {r["slug"]: (r["display_name"], r["status"])
                for r in reg.execute("SELECT slug, display_name, status FROM clients")}
    finally:
        reg.close()


def suggest(site_name: str, clients: dict[str, tuple[str, str]]) -> Optional[tuple[str, str]]:
    """The ONE active client whose name is the SAME NAME as the site's
    (`exact_name_key`, legal suffixes kept) — offered on its row, never
    applied, never in bulk. None for no match or two."""
    from apps.octo.instances.tenant_lifecycle import exact_name_key

    key = exact_name_key(site_name)
    if not key:
        return None
    hits = [(slug, name) for slug, (name, status) in clients.items()
            if status == "active" and exact_name_key(name) == key]
    return hits[0] if len(hits) == 1 else None


def _sites_response(request: Request, record: Any) -> SitesResponse:
    from apps.octo.adapters.unifi.poller import split_scope

    discovery = vendor_tenants.latest(record.id, record.cred_ref)
    listed = {t.id: t.label for t in discovery.tenants} if discovery else {}
    try:
        stored = tenant_map.get_mappings(record.id)
    except sqlite3.OperationalError:
        stored = []
    mappings = {m.vendor_tenant_id: m for m in stored if split_scope(m.vendor_tenant_id)}
    legacy = [m for m in stored if not split_scope(m.vendor_tenant_id)]
    ignored = {t.vendor_tenant_id: t for t in ignored_tenants.get_ignored(record.id)}
    clients = _clients()
    adapter = _running_adapter(request, record.id)
    poller = getattr(adapter, "poller", None) if adapter is not None else None
    fleet: dict[str, dict[str, Any]] = {}
    states: dict[str, dict[str, Any]] = {}
    if poller is not None:
        try:
            fleet = poller.fleet_view()
            states = poller.site_states()
        except Exception:  # noqa: BLE001 — a panel never fails for a snapshot
            fleet, states = {}, {}
    out: list[SiteOut] = []
    for scope in sorted(set(listed) | set(fleet) | set(mappings) | set(ignored)):
        parts = split_scope(scope)
        if parts is None:
            continue
        info = fleet.get(scope) or {}
        m = mappings.get(scope)
        ig = ignored.get(scope)
        name = (info.get("name") or (m.vendor_tenant_label if m else None)
                or (ig.vendor_tenant_label if ig else None) or listed.get(scope) or parts[1])
        tenant_name, tenant_status = (clients.get(m.octo_client_slug, (None, "missing"))
                                      if m else (None, None))
        sug = None
        if m is None and ig is None:
            found = suggest(str(info.get("name") or name), clients)
            if found:
                sug = SuggestionOut(tenant_slug=found[0], tenant_name=found[1])
        st = states.get(scope) or {}
        loc = info.get("location") if isinstance(info.get("location"), dict) else {}
        out.append(SiteOut(
            scope=scope, host_id=parts[0], site_id=parts[1], name=str(name),
            console_name=str(info.get("console_name") or ""),
            location_text=loc.get("text") or None, timezone=info.get("timezone") or None,
            wans=[WanOut(wan=str(w.get("wan") or ""), external_ip=w.get("external_ip"),
                         isp=w.get("isp"), asn=w.get("asn"),
                         shared_external=bool(w.get("shared_external")))
                  for w in (info.get("wans") or []) if isinstance(w, dict)],
            gateway_online=info.get("gateway_online"),
            host_connected=info.get("host_connected"),
            listed=scope in listed or scope in fleet,
            tenant_slug=m.octo_client_slug if m else None,
            tenant_name=tenant_name, tenant_status=tenant_status,
            match_source=m.match_source if m else None,
            ignored=ig is not None and m is None,
            suggestion=sug,
            problem=st.get("problem") if m else None,
            last_syslog_at=st.get("last_syslog_at") if m else None,
            clients=st.get("clients") if m else None,
        ))
    out.sort(key=lambda s: (0 if (s.tenant_slug is None and not s.ignored) else 1,
                            1 if s.ignored else 0, s.name.lower(), s.scope))
    known = len(listed or fleet) if (discovery or fleet) else None
    counts = SiteCountsOut(
        known=known,
        mapped=sum(1 for s in out if s.tenant_slug),
        ignored=sum(1 for s in out if s.ignored),
        unmapped=(sum(1 for s in out if s.listed and not s.tenant_slug and not s.ignored)
                  if known is not None else None),
        gateways_offline=sum(1 for s in out if s.tenant_slug and s.gateway_online is False),
        problems=sum(1 for s in out if s.problem),
    )
    return SitesResponse(
        instance_id=record.id, discovered=bool(discovery or fleet),
        fetched_at=discovery.fetched_at if discovery else None,
        sites=out,
        legacy=[LegacyMappingOut(vendor_tenant_id=m.vendor_tenant_id,
                                 tenant_slug=m.octo_client_slug,
                                 tenant_name=clients.get(m.octo_client_slug, (None, ""))[0])
                for m in legacy],
        counts=counts,
    )


@router.get("/{instance_id}/sites", response_model=SitesResponse)
def get_sites(
    request: Request,
    response: Response,
    instance_id: int = Path(...),
    caller: sessions.SessionInfo = Depends(session_admin_plus),
) -> SitesResponse:
    """Local state only — never a UniFi call. Site names, locations and WAN
    addresses are client data: no-store."""
    response.headers["Cache-Control"] = "no-store"
    return _sites_response(request, _record(instance_id))


@router.put("/{instance_id}/sites", response_model=SitesResponse)
def put_sites(
    body: SetSitesRequest,
    request: Request,
    response: Response,
    instance_id: int = Path(...),
    caller: sessions.SessionInfo = Depends(session_admin_plus),
) -> SitesResponse:
    from apps.octo.adapters.unifi.poller import split_scope
    from apps.octo.api.routers.integration_mappings import (
        SetTenantMappingsRequest,
        TenantMappingIn,
        _audit_replace,
        _stored_mappings,
        _validated,
    )

    response.headers["Cache-Control"] = "no-store"
    record = _record(instance_id)
    mapped: list[str] = []
    for n, m in enumerate(body.mappings, start=1):
        if split_scope(m.scope) is None:
            raise APIError("VALIDATION_FAILED",
                           f"mapping {n}: {m.scope[:80]!r} is not a UniFi site "
                           "('<hostId>/<siteId>')")
        mapped.append(m.scope)
    if len(set(mapped)) != len(mapped):
        raise APIError("VALIDATION_FAILED", "a site maps to exactly one tenant — it is listed twice")
    ignored_ids: list[str] = []
    for scope in body.ignored:
        if split_scope(scope) is None:
            raise APIError("VALIDATION_FAILED", f"{scope[:80]!r} is not a UniFi site")
        if scope not in ignored_ids:
            ignored_ids.append(scope)
    both = sorted(set(mapped) & set(ignored_ids))
    if both:
        raise APIError("VALIDATION_FAILED",
                       f"site {both[0]!r} cannot be both mapped and ignored — map it, or ignore it")
    discovery = vendor_tenants.latest(record.id, record.cred_ref)
    labels = {t.id: t.label for t in discovery.tenants} if discovery else {}
    adapter = _running_adapter(request, record.id)
    poller = getattr(adapter, "poller", None) if adapter is not None else None
    fleet = {}
    if poller is not None:
        try:
            fleet = poller.fleet_view()
        except Exception:  # noqa: BLE001
            fleet = {}
    before = _stored_mappings(record.id)
    stored_labels = {m.vendor_tenant_id: m.vendor_tenant_label for m in before}
    for t in ignored_tenants.get_ignored(record.id):
        stored_labels.setdefault(t.vendor_tenant_id, t.vendor_tenant_label)

    def label_of(scope: str) -> Optional[str]:
        name = (fleet.get(scope) or {}).get("name") or labels.get(scope) or stored_labels.get(scope)
        return str(name)[:200] if name else None

    rows = [TenantMappingIn(vendor_tenant_id=m.scope, octo_client_slug=m.tenant_slug,
                            vendor_tenant_label=label_of(m.scope), match_source="manual")
            for m in body.mappings]
    # A retired local-controller mapping (a bare site id) rides along as it is.
    rows += [TenantMappingIn(vendor_tenant_id=m.vendor_tenant_id,
                             octo_client_slug=m.octo_client_slug,
                             vendor_tenant_label=m.vendor_tenant_label,
                             match_source=m.match_source)
             for m in before if split_scope(m.vendor_tenant_id) is None]
    mappings = _validated(SetTenantMappingsRequest(mappings=rows), VENDOR, record.id,
                          clients=_clients(), stored=before)
    frozen_and_ignored = sorted({m.vendor_tenant_id for m in mappings} & set(ignored_ids))
    if frozen_and_ignored:
        raise APIError("VALIDATION_FAILED",
                       f"site {frozen_and_ignored[0]!r} is mapped to a departed tenant (a frozen "
                       "mapping) and cannot be ignored")
    before_ignored = sorted(ignored_tenants.ignored_ids(record.id))
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
            reason="UniFi sites ignored via the mapping panel",
            request_id=str(uuid.uuid4()),
        ))
    finally:
        g_audit.close()
    tenant_map.set_mappings(record.id, mappings, operator_id=caller.operator_id)
    ignored_tenants.set_ignored(record.id, [(s, label_of(s)) for s in ignored_ids],
                                operator_id=caller.operator_id)
    manager = getattr(request.app.state, "instance_manager", None)
    if manager is not None:
        manager.nudge(record.id)
    return _sites_response(request, record)
