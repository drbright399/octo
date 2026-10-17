"""Combined /integrations endpoint — read-back layer the Integrations
settings UI consumes.

Returns the legacy `{definitions, instances}` shape the front-end's
`listIntegrations()` expects. Internally joins the adapter catalog
(metadata for every CONFIGURED vendor) with the persisted instance rows.

The CATALOG endpoint at /admin/adapters/catalog is what the
`+ Add integration` popout uses to browse the full catalog. This
endpoint is narrower: it only surfaces the vendors that have a
configured instance, so the main page renders cards for what's actually
wired up.

Admin-tier gated.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from apps.octo.api.models import WebhookReceiptOut, webhook_receipt_out
from apps.octo.api.role_gates import session_admin_plus
from apps.octo.auth import sessions

router = APIRouter(prefix="/integrations", tags=["integrations"])


class IntegrationDefinitionOut(BaseModel):
    slug: str
    name: str
    category: str
    description: str
    fields: list = []


class ProfileSummaryOut(BaseModel):
    """The integration card's per-profile counts (NextDNS). `known` /
    `unmapped` are null until the profile list has been read once since the
    service started (the poller reads it first thing after a start)."""
    known: int | None = None
    known_at: str | None = None
    mapped: int = 0
    ignored: int = 0
    unmapped: int | None = None
    active: int = 0
    pending: int = 0
    lapsed: int = 0
    checking: int = 0
    # NextDNS no longer shows the profile to the key (HTTP 404).
    missing: int = 0
    # Profiles whose polling has a problem of their own (failing calls, a
    # tenant's store, logging off at NextDNS) — the others go on.
    problems: int = 0
    # Hours the hourly roll-ups are behind (the polling does not fit).
    rollup_lag_hours: int = 0
    # Recent hours read as a NextDNS-side analytics gap (at most 2 in a row;
    # no lapse alerts for them).
    analytics_gaps: int = 0
    # A fleet-wide outage in progress: sites dark at once, of how many
    # watched, and the tenant its ONE signal went to (None: no internal one).
    fleet_outage_sites: int = 0
    fleet_outage_watched: int = 0
    fleet_outage_tenant: str | None = None
    throttled: bool = False
    throttled_for_sec: int = 0
    stretched: bool = False
    calls_per_hour_planned: float | None = None


class SiteSummaryOut(BaseModel):
    """Per-site integrations (UniFi): the fleet's sites — mapped / ignored /
    needing a decision — consoles and gateways offline, per-site problems,
    mappings of the retired local-controller adapter, the vendor's rate
    limiting. Local state only."""
    known: int | None = None
    known_at: str | None = None
    consoles: int = 0
    consoles_offline: int = 0
    mapped: int = 0
    ignored: int = 0
    unmapped: int | None = None
    gateways_offline: int = 0
    problems: int = 0
    legacy_mappings: int = 0
    throttled: bool = False
    throttled_for_sec: int = 0
    calls_per_hour_planned: float | None = None


class IntegrationInstanceOut(BaseModel):
    slug: str
    # Persisted instance id — the console needs it to address the instance
    # (Disable integration).
    id: int
    status: str
    status_detail: str | None = None
    configured_at: str
    last_test_at: str | None = None
    # Last completed vendor round-trip by this instance's poller. In-memory:
    # null until the first success after a restart, and for adapters whose
    # pollers do not report contact yet.
    last_contact_ok_at: str | None = None
    # WHY status is 'error', when the poller observed it (forbidden / auth /
    # transport / internal); null for a start failure. And whether inbound
    # webhooks are a separate path that CAN deliver for this instance (route +
    # not poll-only + a usable secret — never claimed on intent alone).
    contact_failure_kind: str | None = None
    receives_webhooks: bool = False
    # Whether anything has actually ARRIVED on that path, and why not.
    webhook_receipt: WebhookReceiptOut = WebhookReceiptOut()
    warnings: list[str] = []
    # Neutral, informational lines (e.g. poll-only by choice) — not faults.
    notes: list[str] = []
    # Legacy drop counters — nothing is dropped any more (unattributable
    # traffic is held in quarantine); kept for the console's older cards.
    unmapped_dropped: int = 0
    unmapped_last_dropped_at: str | None = None
    unmapped_vendor_tenant_ids: list[str] = []
    # Tenant lifecycle: tenants this instance created from its own traffic
    # that still await a human's tag, events held in quarantine for it, and
    # whether its auto-create bound is currently reached (further new sites
    # quarantine as 'autocreate-limit' until a human reviews).
    auto_created_pending: int = 0
    quarantined: int = 0
    autocreate_limited: bool = False
    # Saved tenant mappings whose vendor tenant id is not one the vendor
    # lists — they can never match an event. Known only after an admin has
    # opened the mapping panel since the last restart (the vendor is never
    # contacted to build this payload): null = not checked, 0 = all match.
    mappings_unmatched: int | None = None
    mappings_checked_at: str | None = None
    # This adapter can build "Open in <vendor>" links, so the card offers the
    # portal-link settings (…/vendor-links).
    supports_vendor_links: bool = False
    # A new instance whose first import WAITS for the operator's tenant
    # mapping (RocketCyber): when it starts on its own — sooner, the moment a
    # mapping is saved. Null when not waiting (from the running adapter's
    # health; never a vendor call).
    first_import_waiting_until: str | None = None
    # A new instance whose first import waits for the tenant mapping with NO
    # deadline (NextDNS: nothing is imported until a profile is mapped — it
    # never starts on its own). The card says "waiting", never "until when".
    waiting_for_tenant_mapping: bool = False
    # Per-profile integrations (NextDNS): profile counts, protection states,
    # the vendor's rate limiting. Null for other adapters.
    profiles: ProfileSummaryOut | None = None
    # Per-site integrations (UniFi): site counts, consoles / gateways
    # offline. Null for other adapters.
    sites: SiteSummaryOut | None = None


class IntegrationsResponse(BaseModel):
    definitions: list[IntegrationDefinitionOut]
    instances: dict[str, IntegrationInstanceOut]


@router.get("", response_model=IntegrationsResponse)
def list_integrations(
    request: Request,
    caller: sessions.SessionInfo = Depends(session_admin_plus),
) -> IntegrationsResponse:
    """Return the configured vendors + their live status, one entry each
    in `definitions` and `instances` keyed by vendor_slug.
    """
    from apps.octo.instances import (
        list_instances, mapping_review, quarantine, tenant_autocreate, unmapped,
        vendor_contact, vendor_tenants,
    )
    from apps.octo.api.vendor_links import supports_links
    from apps.octo.instances.webhook_auth import webhook_status

    registry = getattr(request.app.state, "adapter_registry", None)
    manager = getattr(request.app.state, "instance_manager", None)
    rows = list_instances(include_disabled=False)

    definitions: list[IntegrationDefinitionOut] = []
    instances: dict[str, IntegrationInstanceOut] = {}
    for rec in rows:
        adapter_cls = registry.get_adapter_class(rec.vendor_slug) if registry else None
        name = adapter_cls.vendor_display_name if adapter_cls else rec.vendor_slug
        category = getattr(adapter_cls, "vendor_category", "other") if adapter_cls else "other"
        definitions.append(IntegrationDefinitionOut(
            slug=rec.vendor_slug,
            name=name,
            category=category,
            description=getattr(adapter_cls, "__doc__", "") or "",
        ))
        drops = unmapped.snapshot(rec.id)
        unmatched = vendor_tenants.unmatched_mappings(rec.id, rec.cred_ref)
        contact = vendor_contact.snapshot(rec.id)
        hooks = webhook_status(rec, name)  # one vault read for all of it
        autocreate = tenant_autocreate.autocreate_status(rec.id)
        held = quarantine.counts(rec.id)
        instances[rec.vendor_slug] = IntegrationInstanceOut(
            slug=rec.vendor_slug,
            id=rec.id,
            status=rec.status,
            status_detail=rec.status_detail,
            configured_at=rec.configured_at,
            last_test_at=rec.last_test_at,
            last_contact_ok_at=contact["last_ok_at"],
            contact_failure_kind=(
                contact["failure_kind"] if rec.status == "error" else None
            ),
            receives_webhooks=hooks.usable,
            webhook_receipt=webhook_receipt_out(rec, hooks),
            warnings=(
                hooks.warnings
                + unmapped.unmapped_warnings(rec.id)
                + quarantine.card_warnings(rec.id, name)
                + tenant_autocreate.card_warnings(rec.id, name, status=autocreate)
                + mapping_review.card_warnings(rec.id, name)
                + vendor_tenants.unmatched_warnings(
                    rec, adapter_cls, name, found=unmatched,
                )
            ),
            notes=hooks.notes,
            unmapped_dropped=drops["dropped"],
            unmapped_last_dropped_at=drops["last_dropped_at"],
            unmapped_vendor_tenant_ids=drops["vendor_tenant_ids"],
            auto_created_pending=autocreate["pending"],
            quarantined=held["held"],
            autocreate_limited=autocreate["limited"],
            mappings_unmatched=unmatched["count"] if unmatched else None,
            mappings_checked_at=unmatched["checked_at"] if unmatched else None,
            supports_vendor_links=bool(adapter_cls) and supports_links(adapter_cls),
            first_import_waiting_until=_first_import_wait(manager, rec.id),
            waiting_for_tenant_mapping=_waits_without_deadline(manager, rec.id),
            profiles=_profile_summary(manager, rec.id),
            sites=_site_summary(manager, rec.id),
        )
    return IntegrationsResponse(definitions=definitions, instances=instances)


def _first_import_wait(manager, instance_id: int) -> str | None:
    """`health().detail` of the running adapter: its first import waiting
    for the tenant mapping, and until when. Best effort — an adapter
    without it, not running, or whose health() fails reads as not waiting."""
    adapter = manager.running_adapter(instance_id) if manager is not None else None
    if adapter is None or not hasattr(adapter, "health"):
        return None
    try:
        detail = getattr(adapter.health(), "detail", None) or {}
    except Exception:  # noqa: BLE001 — a card never fails for a health read
        return None
    if not detail.get("waiting_for_tenant_mapping"):
        return None
    at = detail.get("first_import_at")
    return at if isinstance(at, str) and at else None


def _running(manager, instance_id: int):
    return manager.running_adapter(instance_id) if manager is not None else None


def _waits_without_deadline(manager, instance_id: int) -> bool:
    """The running adapter's first import waits for a mapping and will NOT
    start on its own (no `first_import_at`)."""
    adapter = _running(manager, instance_id)
    if adapter is None or not hasattr(adapter, "health"):
        return False
    try:
        detail = getattr(adapter.health(), "detail", None) or {}
    except Exception:  # noqa: BLE001
        return False
    return bool(detail.get("waiting_for_tenant_mapping")) and not detail.get("first_import_at")


def _profile_summary(manager, instance_id: int) -> ProfileSummaryOut | None:
    """An adapter's per-profile card counts (`card_summary`), local state
    only — never a vendor call; None for adapters without it."""
    adapter = _running(manager, instance_id)
    summary = getattr(adapter, "card_summary", None) if adapter is not None else None
    if not callable(summary):
        return None
    try:
        return ProfileSummaryOut(**summary(instance_id))
    except Exception:  # noqa: BLE001 — a card never fails for a summary
        return None


def _site_summary(manager, instance_id: int) -> SiteSummaryOut | None:
    """An adapter's per-site card counts (`site_summary`), local state only —
    never a vendor call; None for adapters without it."""
    adapter = _running(manager, instance_id)
    summary = getattr(adapter, "site_summary", None) if adapter is not None else None
    if not callable(summary):
        return None
    try:
        return SiteSummaryOut(**summary(instance_id))
    except Exception:  # noqa: BLE001 — a card never fails for a summary
        return None
