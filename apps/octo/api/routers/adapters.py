"""Admin endpoints: adapter catalog + smoke-test.

These two are the V1 surface that the Integrations settings UI calls.
Instance lifecycle is create / list / disable: credentials are create-only
(no read-back, no edit), so replacing an integration is disable → create.
The ONE exception to "never returned": a webhook token the PLATFORM generated
during create is returned in that create response, once, so the operator can
copy it to the vendor side. No other route can produce it again.
Pause / resume land in a follow-up pass when the V3 UI wiring catches up.

Catalog endpoint exposes the discovered adapter classes — vendor metadata
plus the credential_shape and tenant_mapping_shape the wizard renders.
No credentials in the response (catalog is metadata-only).

Smoke-test endpoint accepts a candidate set of credentials, runs the
adapter's smoke_test() in a background-thread wrapper, returns the
{ok, message} result. Credentials passed to this endpoint MUST NOT be
persisted — the endpoint is a one-shot test, not a save.

Vendor-tenants endpoint lists what the VENDOR calls its tenants (Datto
sites, …) for a saved instance, so the mapping panel offers a picker instead
of free text. On demand only, served from a short in-process cache.

All routes admin+ tier. Audit log records every smoke-test call with
operator + adapter slug + outcome (NOT the credential values); a vendor-tenant
listing is audited the same way whenever it actually contacts the vendor.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Any

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field

from apps.octo.api.errors import APIError
from apps.octo.api.models import WebhookReceiptOut, webhook_receipt_out
from apps.octo.api.role_gates import session_admin_plus
from apps.octo.auth import audit
from apps.octo.auth import sessions
from apps.octo import paths
from apps.octo.db import connect


router = APIRouter(prefix="/admin/adapters", tags=["admin-adapters"])
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pydantic shapes
# ---------------------------------------------------------------------------

class CredentialFieldOut(BaseModel):
    name: str
    label: str
    kind: str
    description: str | None = None
    required: bool = True
    choices: list[str] | None = None
    show_when: dict[str, list[str]] | None = None
    required_when: dict[str, list[str]] | None = None
    # Webhook-secret fields only. "platform": leave it blank with
    # `enable_webhook` and the platform generates it; "vendor": issued on the
    # vendor side and pasted in. `webhook_header` is the header a platform
    # token is presented in. Both None for ordinary credentials.
    secret_origin: str | None = None
    webhook_header: str | None = None


class TenantMappingShapeOut(BaseModel):
    fetch_method: str
    fetch_endpoint: str | None = None
    vendor_tenant_id_field: str
    vendor_tenant_label_field: str
    # How the mapping UI words its field: what one tenant is called ("site")
    # and which vendor value the id is ("the site's UID, not its name").
    tenant_noun: str = "tenant"
    id_help: str | None = None


class OnboardingStepOut(BaseModel):
    title: str
    body: str
    copy_value: str | None = None
    code_sample: str | None = None


class OnboardingOut(BaseModel):
    summary: str
    webhook_url: str | None = None
    # Why a webhook-receiving vendor has NO webhook_url (no public ingest
    # hostname configured). The UI shows this instead of a URL; never both.
    webhook_url_problem: str | None = None
    steps: list[OnboardingStepOut]


class CatalogEntry(BaseModel):
    """One row in the GET /catalog response.

    Everything the Integrations settings UI needs to render an adapter
    card and (when picked) the credential wizard.
    """
    vendor_slug: str
    vendor_display_name: str
    vendor_logo_path: str
    vendor_category: str
    auth_model: str
    delivery_mode: str
    availability: str
    compliance_categories: list[str]
    contract_version: str
    credential_shape: list[CredentialFieldOut]
    tenant_mapping_shape: TenantMappingShapeOut | None = None
    onboarding: OnboardingOut | None = None


class CatalogCategoryGroup(BaseModel):
    """Adapters grouped by `vendor_category` for catalog UI rendering.

    The sidebar popout uses one section per category; widgets within the
    section render in `vendor_display_name` order.
    """
    category: str
    display_label: str
    adapters: list[CatalogEntry]


class CatalogResponse(BaseModel):
    adapters: list[CatalogEntry]
    categories: list[CatalogCategoryGroup]


class SmokeTestRequest(BaseModel):
    """Candidate credentials to validate. NOT persisted by this endpoint."""
    credentials: dict[str, Any] = Field(default_factory=dict)


class SmokeTestResponse(BaseModel):
    ok: bool
    message: str


# ---------------------------------------------------------------------------
# Instance create / list shapes
# ---------------------------------------------------------------------------

class CreateInstanceRequest(BaseModel):
    """POST /admin/adapters/{slug}/instances body.

    `display_name` defaults to the adapter's vendor_display_name if absent.
    `instance_config` carries non-credential runtime overrides (poll interval,
    region toggles, etc.). Credentials live in `credentials` and are persisted
    encrypted; the server re-runs smoke_test before persisting so bad creds
    never reach storage.
    """
    credentials: dict[str, Any] = Field(default_factory=dict)
    instance_config: dict[str, Any] = Field(default_factory=dict)
    display_name: str | None = None
    default_tenant_slug: str | None = None
    # The operator's explicit answer to "real-time webhooks?".
    #   true  — webhook secret blank + platform-defined token → the platform
    #           generates one (returned once, see CreateInstanceResponse);
    #           a supplied value is used as-is. Vendor-issued secrets
    #           (Resend) must be supplied — they cannot be generated here.
    #   false — poll-only; supplying a webhook secret as well is refused.
    #   null  — legacy callers: blank means poll-only, nothing is generated.
    enable_webhook: bool | None = None


class InstanceOut(BaseModel):
    """One configured adapter instance — what the Integrations UI renders
    as a card on the main page. Never contains credential values."""
    id: int
    vendor_slug: str
    vendor_display_name: str
    display_name: str
    status: str
    status_detail: str | None = None
    default_tenant_slug: str | None = None
    configured_at: str
    last_test_at: str | None = None
    last_event_at: str | None = None
    # When this instance's poller last completed a vendor round-trip (in
    # memory; null until the first success after a restart, or when the
    # adapter does not report contact yet).
    last_contact_ok_at: str | None = None
    # WHY status is 'error', when the poller observed it: forbidden / auth /
    # transport / internal. Null for a start failure (nothing is running) —
    # the card words its headline by this, never claiming more than was seen.
    contact_failure_kind: str | None = None
    # True when this instance also takes inbound webhooks AND can accept them
    # (a usable secret is stored). They are accepted whatever the poller's
    # state, so a polling failure does not stop them — but an instance with no
    # usable secret rejects every one, and must not be described as receiving.
    receives_webhooks: bool = False
    # Whether anything has actually ARRIVED on that path, and why not.
    webhook_receipt: WebhookReceiptOut = Field(default_factory=WebhookReceiptOut)
    # Operator-facing config problems that don't flip `status` — today: a
    # webhook-receiving vendor with no webhook secret (inbound is rejected).
    warnings: list[str] = Field(default_factory=list)
    # Neutral, informational lines — a deliberate choice, not a fault (today:
    # the operator picked poll-only). Rendered without alert styling.
    notes: list[str] = Field(default_factory=list)
    # This adapter can build "Open in <vendor>" links, so the card offers the
    # portal-link settings (…/vendor-links). Same field as /integrations.
    supports_vendor_links: bool = False
    # Tenant lifecycle counters — same fields as /integrations.
    auto_created_pending: int = 0
    quarantined: int = 0
    autocreate_limited: bool = False


class InstanceListResponse(BaseModel):
    instances: list[InstanceOut]


class GeneratedWebhookSecretOut(BaseModel):
    """A webhook token the platform generated during THIS create. Present in
    this one response only — it is vaulted with the instance credentials and
    no route returns it again. Lost → disable the instance and create anew."""
    credential_field: str
    # The wizard label of that field ('Webhook Token') — what the console shows.
    credential_label: str = ""
    header_name: str
    header_value: str
    webhook_url: str | None = None
    webhook_url_problem: str | None = None
    shown_once: bool = True


class CreateInstanceResponse(BaseModel):
    instance: InstanceOut
    smoke_test_message: str
    # Only when the platform generated the token; an operator-supplied secret
    # is never echoed back.
    generated_webhook_secret: GeneratedWebhookSecretOut | None = None


class DisableInstanceRequest(BaseModel):
    """POST /admin/adapters/instances/{id}/disable body. `reason` is recorded
    on the row and in the audit chain — say WHY (wrong webhook secret, vendor
    offboarded, …), never paste a credential here."""
    reason: str = Field(min_length=3, max_length=500)


class DisableInstanceResponse(BaseModel):
    instance_id: int
    vendor_slug: str
    status: str
    disabled_at: str | None = None
    already_disabled: bool = False
    # Tenant mappings hang off the instance id, so a replacement instance
    # starts with NONE — the operator must re-map before enabling its feed.
    tenant_mappings_not_carried_over: int = 0
    message: str


class VendorTenantOut(BaseModel):
    id: str
    label: str


class VendorTenantsResponse(BaseModel):
    """POST /admin/adapters/instances/{id}/vendor-tenants.

    `supported=false` → this adapter cannot list its tenants; the UI keeps
    manual entry and says so. A vendor-side FAILURE is never folded into an
    empty list: it is an error response carrying the reason.
    """
    instance_id: int
    vendor_slug: str
    vendor_display_name: str
    supported: bool
    tenants: list[VendorTenantOut] = Field(default_factory=list)
    # True when the adapter stopped at its page cap: `tenants` is a prefix,
    # so an id missing from it is NOT proven wrong.
    truncated: bool = False
    fetched_at: str | None = None
    cached: bool = False
    tenant_mapping_shape: TenantMappingShapeOut | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_registry(request: Request):
    """Pull the AdapterRegistry off the FastAPI app state.

    main.create_app() should stash the registry on app.state.adapter_registry;
    if it hasn't, the discovery step couldn't have run either, so the catalog
    is empty — return None and let the caller render that as `adapters=[]`.
    """
    return getattr(request.app.state, "adapter_registry", None)


def _get_instance_manager(request: Request):
    """Pull the InstanceManager off app.state, or None if not configured."""
    return getattr(request.app.state, "instance_manager", None)


def _instance_to_out(
    rec, *, vendor_display_name: str, adapter_cls: type | None = None,
) -> InstanceOut:
    """Materialize an InstanceRecord into the JSON-friendly shape."""
    from apps.octo.api.vendor_links import supports_links
    from apps.octo.instances import (
        quarantine, tenant_autocreate, unmapped, vendor_contact, vendor_tenants,
    )
    from apps.octo.instances.webhook_auth import webhook_status

    contact = vendor_contact.snapshot(rec.id)
    hooks = webhook_status(rec, vendor_display_name)  # one vault read
    autocreate = tenant_autocreate.autocreate_status(rec.id)
    held = quarantine.counts(rec.id)
    return InstanceOut(
        id=rec.id,
        vendor_slug=rec.vendor_slug,
        vendor_display_name=vendor_display_name,
        display_name=rec.display_name,
        status=rec.status,
        status_detail=rec.status_detail,
        default_tenant_slug=rec.default_tenant_slug,
        configured_at=rec.configured_at,
        last_test_at=rec.last_test_at,
        last_event_at=rec.last_event_at,
        last_contact_ok_at=contact["last_ok_at"],
        contact_failure_kind=contact["failure_kind"] if rec.status == "error" else None,
        receives_webhooks=hooks.usable,
        webhook_receipt=webhook_receipt_out(rec, hooks),
        warnings=(
            hooks.warnings
            + unmapped.unmapped_warnings(rec.id)
            + quarantine.card_warnings(rec.id, vendor_display_name)
            + tenant_autocreate.card_warnings(rec.id, vendor_display_name, status=autocreate)
            + vendor_tenants.unmatched_warnings(rec, adapter_cls, vendor_display_name)
        ),
        notes=hooks.notes,
        supports_vendor_links=bool(adapter_cls) and supports_links(adapter_cls),
        auto_created_pending=autocreate["pending"],
        quarantined=held["held"],
        autocreate_limited=autocreate["limited"],
    )


def _audit_instance_create(
    *,
    operator_id: int,
    vendor_slug: str,
    instance_id: int,
    request_id: str,
) -> None:
    g_audit = connect(paths.global_audit_db_path())
    try:
        audit.append(g_audit, audit.AuditEntry(
            actor=str(operator_id),
            actor_kind="human",
            action="adapter_instance_create",
            target_kind="adapter_instance",
            target_id=str(instance_id),
            client_slug="global",
            after_state={"vendor_slug": vendor_slug, "instance_id": instance_id},
            reason="adapter instance configured via admin API",
            request_id=request_id,
        ))
    finally:
        g_audit.close()


def _audit_instance_disable(
    *,
    operator_id: int,
    vendor_slug: str,
    instance_id: int,
    previous_status: str,
    reason: str,
    request_id: str,
) -> None:
    """Audit a disable. Records WHO, WHICH instance and WHY — the row's
    credentials are never read, so nothing credential-shaped can land here."""
    g_audit = connect(paths.global_audit_db_path())
    try:
        audit.append(g_audit, audit.AuditEntry(
            actor=str(operator_id),
            actor_kind="human",
            action="adapter_instance_disable",
            target_kind="adapter_instance",
            target_id=str(instance_id),
            client_slug="global",
            before_state={"vendor_slug": vendor_slug, "status": previous_status},
            after_state={"vendor_slug": vendor_slug, "status": "disabled"},
            reason=reason,
            request_id=request_id,
        ))
    finally:
        g_audit.close()


def _tenant_shape_out(adapter: Any) -> TenantMappingShapeOut | None:
    tm = adapter.tenant_mapping_shape()
    if tm is None:
        return None
    return TenantMappingShapeOut(
        fetch_method=tm.fetch_method,
        fetch_endpoint=tm.fetch_endpoint,
        vendor_tenant_id_field=tm.vendor_tenant_id_field,
        vendor_tenant_label_field=tm.vendor_tenant_label_field,
        tenant_noun=getattr(tm, "tenant_noun", None) or "tenant",
        id_help=getattr(tm, "id_help", None),
    )


def _adapter_to_catalog_entry(cls: type) -> CatalogEntry:
    """Materialize one adapter class into a JSON-friendly catalog entry."""
    from apps.octo.instances import public_urls, webhook_receipt
    from apps.octo.instances.webhook_auth import SECRET_SPECS, WEBHOOK_SECRET_FIELDS

    instance = cls()  # adapters are cheap to instantiate; needed for shape methods
    cred_fields = [
        CredentialFieldOut(
            name=f.name,
            label=f.label,
            kind=f.kind,
            description=getattr(f, "description", None),
            required=getattr(f, "required", True),
            choices=getattr(f, "choices", None),
            show_when=getattr(f, "show_when", None),
            required_when=getattr(f, "required_when", None),
            secret_origin=getattr(SECRET_SPECS.get(f.name), "origin", None),
            webhook_header=getattr(SECRET_SPECS.get(f.name), "header", None),
        )
        for f in instance.credential_shape()
    ]
    tm_out = _tenant_shape_out(instance)

    # Compose the inbound webhook URL for push/hybrid adapters from the
    # deploy's public INGEST origin — never the console origin, which a vendor
    # cannot reach through the access gate — then let the adapter render its
    # guided-setup steps + sample payloads. No ingest hostname → no URL, and
    # the operator is told why (a wrong URL is worse than none).
    webhook_url = None
    webhook_url_problem = None
    if cls.delivery_mode in ("push", "hybrid"):
        webhook_url = public_urls.webhook_url(cls.vendor_slug)
        if webhook_url is None:
            webhook_url_problem = public_urls.NO_INGEST_HOST_PROBLEM
    ob = instance.onboarding(webhook_url)
    ob_out = None
    if ob is not None:
        steps = [
            OnboardingStepOut(
                title=s.title,
                body=s.body,
                copy_value=s.copy_value,
                code_sample=s.code_sample,
            )
            for s in ob.steps
        ]
        # PLATFORM-authored, appended for EVERY adapter with an inbound
        # webhook route — an adapter cannot forget it, and a new one gets it
        # for free: how to tell "rejected by Athena" from "never reached
        # Athena" (an edge problem), which no vendor's test result shows.
        if cls.vendor_slug in WEBHOOK_SECRET_FIELDS:
            steps.append(OnboardingStepOut(
                title=f"{len(steps) + 1} · {webhook_receipt.EDGE_STEP_TITLE}",
                body=webhook_receipt.edge_step_body(),
            ))
        ob_out = OnboardingOut(
            summary=ob.summary,
            webhook_url=ob.webhook_url,
            webhook_url_problem=webhook_url_problem,
            steps=steps,
        )

    return CatalogEntry(
        vendor_slug=cls.vendor_slug,
        vendor_display_name=cls.vendor_display_name,
        vendor_logo_path=cls.vendor_logo_path,
        vendor_category=getattr(cls, "vendor_category", "other"),
        auth_model=cls.auth_model,
        delivery_mode=cls.delivery_mode,
        availability=getattr(cls, "availability", "available"),
        compliance_categories=list(cls.compliance_categories or []),
        contract_version=cls.contract_version,
        credential_shape=cred_fields,
        tenant_mapping_shape=tm_out,
        onboarding=ob_out,
    )


# Display labels for each category slug. Anything not in this map falls
# back to a title-cased slug so a new adapter can declare a new category
# without a code change here — but adding a row here gives a nicer label.
_CATEGORY_LABELS: dict[str, str] = {
    "siem": "SIEM",
    "rmm": "RMM",
    "soc": "Managed SOC",
    "network": "Network",
    "edr": "EDR",
    "psa": "PSA",
    "ticketing": "Ticketing",
    "asset-mgmt": "Asset Management",
    "other": "Other",
}


def _category_label(slug: str) -> str:
    return _CATEGORY_LABELS.get(slug, slug.replace("-", " ").title())


def _group_by_category(entries: list[CatalogEntry]) -> list[CatalogCategoryGroup]:
    """Bucket catalog entries by `vendor_category`. Categories are sorted
    by their human label; adapters within a category retain the caller-
    provided order (which is `vendor_display_name`-sorted)."""
    buckets: dict[str, list[CatalogEntry]] = {}
    for entry in entries:
        buckets.setdefault(entry.vendor_category, []).append(entry)
    return sorted(
        (
            CatalogCategoryGroup(
                category=slug,
                display_label=_category_label(slug),
                adapters=items,
            )
            for slug, items in buckets.items()
        ),
        key=lambda g: g.display_label.lower(),
    )


def _audit_smoke_test(
    *,
    operator_id: int,
    vendor_slug: str,
    outcome_ok: bool,
    request_id: str,
) -> None:
    """Audit the smoke-test attempt. Records WHO tried, WHICH adapter, +
    whether it succeeded — never the credentials themselves."""
    g_audit = connect(paths.global_audit_db_path())
    try:
        audit.append(g_audit, audit.AuditEntry(
            actor=str(operator_id),
            actor_kind="human",
            action="adapter_smoke_test",
            target_kind="adapter",
            target_id=vendor_slug,
            client_slug="global",
            after_state={"vendor_slug": vendor_slug, "ok": outcome_ok},
            reason="adapter onboarding smoke test",
            request_id=request_id,
        ))
    finally:
        g_audit.close()


def _audit_vendor_tenant_list(
    *,
    operator_id: int,
    vendor_slug: str,
    instance_id: int,
    outcome: str,
    tenant_count: int | None,
    request_id: str,
) -> None:
    """Audit a vendor-tenant listing that CONTACTED THE VENDOR (it decrypts
    the instance's credentials to do so). Cache hits are not audited — they
    touch neither. Records who / which instance / outcome / how many; never a
    credential and never the tenant names (they are customer names)."""
    g_audit = connect(paths.global_audit_db_path())
    try:
        audit.append(g_audit, audit.AuditEntry(
            actor=str(operator_id),
            actor_kind="human",
            action="adapter_vendor_tenant_list",
            target_kind="adapter_instance",
            target_id=str(instance_id),
            client_slug="global",
            after_state={
                "vendor_slug": vendor_slug,
                "outcome": outcome,
                "tenant_count": tenant_count,
            },
            reason="vendor tenant discovery for the tenant-mapping panel",
            request_id=request_id,
        ))
    finally:
        g_audit.close()


# Vendor failure kind (shared_adapter_contract.VendorTenantFailureKind) → the
# API error code the mapping panel shows the message of.
_VENDOR_FAILURE_CODES: dict[str, str] = {
    "forbidden": "VENDOR_ACCESS_FORBIDDEN",
    "auth": "VENDOR_CREDENTIALS_REJECTED",
    "transport": "VENDOR_UNREACHABLE",
}
_MAX_VENDOR_MESSAGE_CHARS = 800


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/catalog", response_model=CatalogResponse)
def list_catalog(
    request: Request,
    caller: sessions.SessionInfo = Depends(session_admin_plus),
) -> CatalogResponse:
    """Return every adapter class the framework discovered at boot.

    Used by the Integrations settings UI to render the catalog popout.
    Filterable client-side by category, search across vendor_display_name.
    """
    registry = _get_registry(request)
    if registry is None:
        return CatalogResponse(adapters=[], categories=[])
    entries = [
        _adapter_to_catalog_entry(cls)
        for cls in registry.list_adapter_classes()
    ]
    # Stable sort by display name so the catalog order is predictable
    entries.sort(key=lambda e: e.vendor_display_name.lower())
    return CatalogResponse(
        adapters=entries,
        categories=_group_by_category(entries),
    )


@router.post("/{vendor_slug}/smoke-test", response_model=SmokeTestResponse)
async def smoke_test_adapter(
    vendor_slug: str,
    body: SmokeTestRequest,
    request: Request,
    caller: sessions.SessionInfo = Depends(session_admin_plus),
) -> SmokeTestResponse:
    """Run the adapter's smoke_test() with the candidate credentials.

    Credentials are passed in the request body, used once for validation,
    and discarded. They are NEVER persisted by this endpoint — the
    /instances POST is what actually saves a configuration after the
    operator confirms.
    """
    request_id = str(uuid.uuid4())
    registry = _get_registry(request)
    if registry is None:
        raise APIError(
            "ADAPTER_NOT_FOUND",
            "adapter framework not initialized in this process",
        )
    adapter_cls = registry.get_adapter_class(vendor_slug)
    if adapter_cls is None:
        raise APIError(
            "ADAPTER_NOT_FOUND",
            f"no adapter registered with slug {vendor_slug!r}",
        )
    adapter = adapter_cls()
    # smoke_test may do blocking network IO; run on a thread.
    result = await asyncio.to_thread(adapter.smoke_test, body.credentials)
    _audit_smoke_test(
        operator_id=caller.operator_id,
        vendor_slug=vendor_slug,
        outcome_ok=bool(result.ok),
        request_id=request_id,
    )
    return SmokeTestResponse(
        ok=bool(result.ok),
        message=result.message,
    )


# ---------------------------------------------------------------------------
# Instance create / list
# ---------------------------------------------------------------------------

@router.post(
    "/{vendor_slug}/instances",
    response_model=CreateInstanceResponse,
)
async def create_instance_endpoint(
    vendor_slug: str,
    body: CreateInstanceRequest,
    request: Request,
    response: Response,
    caller: sessions.SessionInfo = Depends(session_admin_plus),
) -> CreateInstanceResponse:
    """Persist a configured adapter instance and start its poller.

    Flow:
      1. Resolve the adapter class from the registry.
      2. Re-run smoke_test(credentials) — fail fast before persistence so
         bad creds never reach the vault. The UI may have smoke-tested
         already but the server doesn't trust that; persistence has to be
         the authoritative gate. "Bad" includes a key the vendor accepts
         but authorizes for nothing (Datto: token issued, every read 403):
         that create is REFUSED with the adapter's fix-it message, not saved
         as a degraded instance — nothing is vaulted, no webhook token is
         minted, and the one-per-vendor slot stays free for the retry. The
         time the test passed is stored as the row's `last_test_at`.
      3. If the operator asked for real-time webhooks and left a
         platform-defined token blank, generate it now (after the smoke test,
         so no failed attempt ever mints one). Encrypt+store credentials,
         insert the adapter_instances row.
      4. Hand the row to the InstanceManager to spin up the adapter's
         poller. Adapter lifecycle errors flip the row's status to 'error'
         but do not roll back the row (so the operator can fix and retry
         via a future re-test endpoint).
      5. Audit + return the IntegrationInstance shape the UI renders. A
         webhook-receiving vendor saved without its webhook secret is still
         created (polling works) but the response carries a `warnings` entry:
         the receiver fails closed, so inbound webhooks will be rejected.
         A platform-generated token rides in THIS response only
         (`generated_webhook_secret`, Cache-Control: no-store); it is never
         audited, logged, or returned by any other route or error path.
      6. If anything in 4–5 fails unexpectedly, the just-inserted row is
         disabled again (vendor slot freed, poller stopped) and the operator
         gets a clean "try again" error — never an active instance whose
         generated token was not shown.
    """
    from apps.octo.instances import create_instance as create_instance_row

    request_id = str(uuid.uuid4())
    registry = _get_registry(request)
    if registry is None:
        raise APIError(
            "ADAPTER_NOT_FOUND",
            "adapter framework not initialized in this process",
        )
    adapter_cls = registry.get_adapter_class(vendor_slug)
    if adapter_cls is None:
        raise APIError(
            "ADAPTER_NOT_FOUND",
            f"no adapter registered with slug {vendor_slug!r}",
        )

    # Webhook secrets guard session-less public routes and can't be edited
    # after creation, so refuse a weak or unusable one NOW (blank stays
    # allowed: poll-only, with a warning). Checked before the smoke test so a
    # typo costs no upstream call. Messages never echo the value.
    from apps.octo.instances.webhook_auth import (
        WEBHOOK_CHOICE_KEY,
        WEBHOOK_SECRET_FIELDS,
        credential_errors,
        generate_token,
        recovery_path,
        should_generate,
        webhook_choice_errors,
    )
    # The success body may carry a generated token: never cacheable. (Error
    # responses are built by the APIError handler and carry no secret.)
    response.headers["Cache-Control"] = "no-store"
    secret_errors = credential_errors(vendor_slug, body.credentials) + (
        webhook_choice_errors(vendor_slug, body.credentials, body.enable_webhook)
    )
    if secret_errors:
        raise APIError("VALIDATION_FAILED", "; ".join(secret_errors))

    # Pre-flight: re-run smoke_test against the candidate credentials.
    adapter_for_smoke = adapter_cls()
    smoke_result = await asyncio.to_thread(
        adapter_for_smoke.smoke_test, body.credentials,
    )
    if not smoke_result.ok:
        # The adapter's message stands alone: a fixed "rejected the
        # credentials" prefix contradicted "Datto accepted the API key but …"
        # and sent operators off to regenerate a key pair that was fine.
        raise APIError(
            "SMOKE_TEST_FAILED", f"Not saved — {smoke_result.message}",
        )
    from apps.octo.ingest.timestamps import utcnow_iso
    smoke_passed_at = utcnow_iso()

    display_name = body.display_name or adapter_cls.vendor_display_name

    # Mint the webhook token only now: validation and the smoke test passed,
    # so the only later failure is a duplicate instance (whose error never
    # touches this value). It goes to the vault with the other credentials.
    credentials_to_store = body.credentials
    generated_spec = should_generate(
        vendor_slug, body.credentials, body.enable_webhook,
    )
    generated_token: str | None = None
    if generated_spec is not None:
        generated_token = generate_token()
        credentials_to_store = {
            **body.credentials, generated_spec.field: generated_token,
        }

    # Record the operator's explicit webhook answer on the row, so a chosen
    # poll-only instance reads as a choice (neutral note) and not as a fault.
    # Server-owned: a caller-supplied value for the key is never trusted.
    # The PSA writes switch is server-owned too: an instance is always born
    # with writes OFF, and only the super_admin + step-up settings route
    # (audited first) may turn them on — never a create body, and never a
    # key riding in the credential blob (which wins a start-config merge).
    from apps.octo.adapters.autotask.writes_switch import WRITES_ENABLED_KEY

    instance_config = {
        k: v for k, v in body.instance_config.items()
        if k not in (WEBHOOK_CHOICE_KEY, WRITES_ENABLED_KEY)
    }
    if WRITES_ENABLED_KEY in credentials_to_store:
        credentials_to_store = {
            k: v for k, v in credentials_to_store.items() if k != WRITES_ENABLED_KEY
        }
    if body.enable_webhook is not None and vendor_slug in WEBHOOK_SECRET_FIELDS:
        instance_config[WEBHOOK_CHOICE_KEY] = "on" if body.enable_webhook else "off"

    # Persist. The unique index on vendor_slug raises IntegrityError if an
    # active instance for this vendor already exists; translate to a clean
    # 409-style API error.
    import sqlite3
    try:
        record = create_instance_row(
            vendor_slug=vendor_slug,
            display_name=display_name,
            credentials_dict=credentials_to_store,
            instance_config=instance_config,
            default_tenant_slug=body.default_tenant_slug,
            configured_by_operator_id=caller.operator_id,
            last_test_at=smoke_passed_at,
        )
    except sqlite3.IntegrityError as exc:
        raise APIError(
            "INSTANCE_ALREADY_EXISTS",
            f"{adapter_cls.vendor_display_name} is already connected, and only "
            "one active integration per vendor is allowed. To replace it: "
            f"{recovery_path(adapter_cls.vendor_display_name)}.",
        ) from exc

    # Everything from here to the built response runs AFTER the row (and, for
    # a generated token, the vaulted secret) exists. If any of it fails
    # unexpectedly the operator would be left with an active instance whose
    # token nobody ever saw, and a vendor slot that refuses a retry (409). So:
    # switch the row off again and say "try again".
    try:
        result = _finish_create(
            request=request,
            registry=registry,
            record=record,
            adapter_cls=adapter_cls,
            operator_id=caller.operator_id,
            request_id=request_id,
            smoke_message=smoke_result.message,
            generated_spec=generated_spec,
            generated_token=generated_token,
        )
    except Exception as exc:  # noqa: BLE001 — anything; the row must not linger
        # Class name ONLY: a validation error's text can embed its input, and
        # the input here may be the generated token.
        logger.error(
            "[adapters] create of %s instance id=%s failed after insert (%s) — "
            "rolling the instance back",
            vendor_slug, record.id, type(exc).__name__,
        )
        freed = _rollback_incomplete_create(
            request=request,
            record=record,
            operator_id=caller.operator_id,
            request_id=request_id,
        )
        name = adapter_cls.vendor_display_name
        raise APIError(
            "INSTANCE_CREATE_INCOMPLETE",
            (
                f"{name} was not connected: an internal step failed after the "
                "integration was saved, so it was switched off again and "
                "nothing is left half-configured. No webhook token was issued. "
                "Please try again."
            ) if freed else (
                f"{name} was not connected: an internal step failed after the "
                "integration was saved, and it could not be switched off "
                f"automatically. {recovery_path(name)}."
            ),
            request_id=request_id,
        ) from None
    return result


def _finish_create(
    *,
    request: Request,
    registry: Any,
    record: Any,
    adapter_cls: type,
    operator_id: int,
    request_id: str,
    smoke_message: str,
    generated_spec: Any,
    generated_token: str | None,
) -> CreateInstanceResponse:
    """Post-insert half of create: audit, start the poller, build the response.
    Raises on any unexpected failure — the caller rolls the row back."""
    from apps.octo.instances import InstanceLifecycleError, InstanceManager, public_urls

    # Audit BEFORE starting — start failures get their own row via the
    # status update on the persisted record.
    _audit_instance_create(
        operator_id=operator_id,
        vendor_slug=record.vendor_slug,
        instance_id=record.id,
        request_id=request_id,
    )

    # Hand off to the InstanceManager (auto-construct one if the app didn't
    # provision one — tests that exercise this endpoint will usually provide
    # their own).
    manager = _get_instance_manager(request)
    if manager is None:
        manager = InstanceManager(adapter_registry=registry)
        request.app.state.instance_manager = manager

    try:
        manager.start_instance(record)
    except InstanceLifecycleError:
        # The manager persists the error status onto the row; we re-read it
        # below into `fresh`, so there's nothing to capture here.
        pass

    # Re-read the row so the response reflects the post-start status the
    # manager just wrote.
    from apps.octo.instances.manager import get_instance
    fresh = get_instance(record.id) or record

    generated_out = None
    if generated_spec is not None and generated_token is not None:
        url = public_urls.webhook_url(record.vendor_slug)
        generated_out = GeneratedWebhookSecretOut(
            credential_field=generated_spec.field,
            credential_label=generated_spec.label or generated_spec.field,
            header_name=generated_spec.header or "",
            header_value=generated_token,
            webhook_url=url,
            webhook_url_problem=(
                None if url else public_urls.NO_INGEST_HOST_PROBLEM
            ),
        )

    return CreateInstanceResponse(
        instance=_instance_to_out(
            fresh,
            vendor_display_name=adapter_cls.vendor_display_name,
            adapter_cls=adapter_cls,
        ),
        smoke_test_message=smoke_message,
        generated_webhook_secret=generated_out,
    )


def _rollback_incomplete_create(
    *, request: Request, record: Any, operator_id: int, request_id: str,
) -> bool:
    """Switch off an instance whose create did not finish. True when the row
    is disabled (vendor slot free). Best-effort and never raises: the caller
    is already on an error path. Reads no credentials."""
    from apps.octo.instances import (
        device_links, doorbell, unmapped, vendor_contact, vendor_tenants,
        webhook_receipt,
    )
    from apps.octo.instances.manager import disable_instance

    reason = "create did not complete — rolled back automatically"
    manager = _get_instance_manager(request)
    if manager is not None:
        try:
            manager.stop_instance(record.id)
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "[adapters] rollback: stopping instance id=%s failed (%s)",
                record.id, type(exc).__name__,
            )
    try:
        disable_instance(
            record.id, disabled_by_operator_id=operator_id, reason=reason,
        )
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "[adapters] rollback: disabling instance id=%s FAILED (%s) — it is "
            "still active and must be disabled by hand",
            record.id, type(exc).__name__,
        )
        return False
    unmapped.reset(record.id)
    vendor_contact.reset(record.id)
    vendor_tenants.reset(record.id)
    device_links.reset(record.id)
    doorbell.reset(record.id)
    webhook_receipt.reset(record.id, record.vendor_slug)
    try:
        _audit_instance_disable(
            operator_id=operator_id,
            vendor_slug=record.vendor_slug,
            instance_id=record.id,
            previous_status=record.status,
            reason=reason,
            request_id=request_id,
        )
    except Exception as exc:  # noqa: BLE001 — the audit DB may be what failed
        logger.error(
            "[adapters] rollback: instance id=%s disabled but the audit row "
            "could not be written (%s)", record.id, type(exc).__name__,
        )
    return True


@router.get("/instances", response_model=InstanceListResponse)
def list_instances_endpoint(
    request: Request,
    caller: sessions.SessionInfo = Depends(session_admin_plus),
) -> InstanceListResponse:
    """Return every persisted, non-disabled adapter instance with its
    current status. The Integrations UI renders one card per row.
    """
    from apps.octo.instances import list_instances as list_records

    registry = _get_registry(request)
    records = list_records(include_disabled=False)
    out: list[InstanceOut] = []
    for rec in records:
        adapter_cls = (
            registry.get_adapter_class(rec.vendor_slug) if registry else None
        )
        display = (
            adapter_cls.vendor_display_name if adapter_cls else rec.vendor_slug
        )
        out.append(_instance_to_out(
            rec, vendor_display_name=display, adapter_cls=adapter_cls,
        ))
    return InstanceListResponse(instances=out)


# ---------------------------------------------------------------------------
# Vendor tenant discovery — feeds the tenant-mapping picker
# ---------------------------------------------------------------------------

def _vendor_tenant_flight(request: Request, instance_id: int) -> asyncio.Lock:
    """One lock per instance, so concurrent cache misses share ONE vendor
    call (a drain is up to 40 pages on the thread pool the pollers use). Kept
    on app.state: an asyncio.Lock belongs to the loop that serves the app."""
    locks = getattr(request.app.state, "vendor_tenant_flights", None)
    if locks is None:
        locks = request.app.state.vendor_tenant_flights = {}
    return locks.setdefault(instance_id, asyncio.Lock())


# POST, not GET: every cache miss decrypts the instance's credentials,
# contacts the vendor and writes an audit row. The session cookie is
# SameSite=Lax, which a cross-site top-level GET navigation still carries — a
# page an admin merely visits could have driven all three. Lax never sends the
# cookie on a cross-site POST. (It also lands in the stricter admin_write
# rate-limit class.)
@router.post(
    "/instances/{instance_id}/vendor-tenants",
    response_model=VendorTenantsResponse,
)
async def list_vendor_tenants_endpoint(
    instance_id: int,
    request: Request,
    response: Response,
    refresh: bool = False,
    caller: sessions.SessionInfo = Depends(session_admin_plus),
) -> VendorTenantsResponse:
    """What the VENDOR calls its tenants for this instance — `[{id, label}]`,
    `id` being the exact routing key — so the mapping panel offers a picker
    and can flag saved rows that match nothing.

    On demand only (panel open / Reload). Served from a 60 s in-process cache
    keyed by instance id + cred_ref; `refresh=true` re-asks the vendor unless
    the answer is only seconds old. The cache is dropped on disable, and a
    disabled instance is refused here, so nothing outlives its instance.

    `supported=false` (200) → the adapter has no such capability; no
    credential is decrypted. A vendor FAILURE is an error response with the
    adapter's operator-actionable message — the same text test-connection and
    the instance card use — never an empty list. A failure is never served as
    a listing; it IS replayed for a few seconds (`vendor_tenants.
    FAILURE_THROTTLE_SEC`) without contacting the vendor or auditing again,
    so a retry loop cannot turn into a stream of credential grants that
    locks the API user out. Concurrent misses share one vendor call.

    A successful listing proves the vendor side works, so the instance's
    poller is nudged to poll now rather than sit out its failure backoff.
    """
    from apps.octo.instances import vendor_tenants
    from apps.octo.instances.manager import get_instance

    request_id = str(uuid.uuid4())
    # Tenant labels are customer names: keep the listing out of any cache.
    response.headers["Cache-Control"] = "no-store"

    record = get_instance(instance_id)
    if record is None:
        raise APIError("NOT_FOUND", f"no adapter instance with id {instance_id}")
    name = _vendor_display_name(request, record.vendor_slug)
    if record.disabled_at is not None:
        vendor_tenants.reset(instance_id)
        raise APIError(
            "CONFLICT",
            f"{name} instance {instance_id} is disabled — there is nothing to "
            "map. Connect it again with + Add integration.",
        )
    registry = _get_registry(request)
    adapter_cls = (
        registry.get_adapter_class(record.vendor_slug) if registry is not None else None
    )
    if adapter_cls is None:
        raise APIError(
            "ADAPTER_NOT_FOUND",
            f"no adapter registered with slug {record.vendor_slug!r}",
        )
    adapter = adapter_cls()
    shape = _tenant_shape_out(adapter)

    def _out(*, supported: bool, discovery: Any = None, cached: bool = False):
        return VendorTenantsResponse(
            instance_id=record.id,
            vendor_slug=record.vendor_slug,
            vendor_display_name=name,
            supported=supported,
            tenants=[
                VendorTenantOut(id=t.id, label=t.label)
                for t in (discovery.tenants if discovery else ())
            ],
            truncated=bool(discovery and discovery.truncated),
            fetched_at=discovery.fetched_at if discovery else None,
            cached=cached,
            tenant_mapping_shape=shape,
        )

    if not getattr(adapter_cls, "supports_tenant_discovery", False) or not callable(
        getattr(adapter, "list_vendor_tenants", None)
    ):
        return _out(supported=False)

    max_age = (
        vendor_tenants.MIN_REFRESH_INTERVAL_SEC if refresh
        else vendor_tenants.CACHE_TTL_SEC
    )

    def _from_memory() -> VendorTenantsResponse | None:
        """A fresh listing, or the recent failure replayed (raises) — either
        way without touching the vault, the vendor or the audit log."""
        hit = vendor_tenants.lookup(instance_id, record.cred_ref, max_age_sec=max_age)
        if hit is not None:
            return _out(supported=True, discovery=hit, cached=True)
        failed = vendor_tenants.recent_failure(instance_id, record.cred_ref)
        if failed is not None:
            raise APIError(
                failed.code,
                f"{failed.message} (Not asked again: {name} answered this "
                f"moments ago — retry in {failed.retry_in_sec}s.)",
                request_id=request_id,
            )
        return None

    remembered = _from_memory()
    if remembered is not None:
        return remembered

    async with _vendor_tenant_flight(request, instance_id):
        # Whoever held the lock may just have produced the answer.
        remembered = _from_memory()
        if remembered is not None:
            return remembered
        return await _discover_vendor_tenants(
            request=request, record=record, adapter=adapter, name=name,
            operator_id=caller.operator_id, request_id=request_id, out=_out,
        )


async def _discover_vendor_tenants(
    *, request: Request, record: Any, adapter: Any, name: str,
    operator_id: int, request_id: str, out: Any,
) -> VendorTenantsResponse:
    """The vendor-contacting half of discovery (caller holds the flight lock)."""
    from shared_adapter_contract.types import VendorTenantListError

    from apps.octo import credentials
    from apps.octo.instances import vendor_tenants
    from apps.octo.instances.manager import get_instance
    from apps.octo.instances.webhook_auth import recovery_path

    instance_id = record.id

    def _fail(code: str, outcome: str, message: str) -> APIError:
        vendor_tenants.remember_failure(
            instance_id, record.cred_ref, code=code, kind=outcome, message=message,
        )
        try:
            _audit_vendor_tenant_list(
                operator_id=operator_id, vendor_slug=record.vendor_slug,
                instance_id=instance_id, outcome=outcome, tenant_count=None,
                request_id=request_id,
            )
        except Exception as exc:  # noqa: BLE001
            # Nothing was listed, so nothing goes unaudited that matters more
            # than the operator learning WHY — keep the actionable message.
            logger.error(
                "[adapters] vendor-tenants: failure outcome=%s for instance "
                "id=%s could not be audited (%s)",
                outcome, instance_id, type(exc).__name__,
            )
        return APIError(code, message, request_id=request_id)

    # Class names only below: an exception's text can embed what it was given.
    try:
        creds = credentials.load(record.cred_ref)
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "[adapters] vendor-tenants: credentials of instance id=%s could "
            "not be decrypted (%s)", instance_id, type(exc).__name__,
        )
        raise _fail(
            "INTERNAL_ERROR", "credentials_unreadable",
            f"The stored {name} credentials could not be read, so {name} was "
            "not contacted. Check the server log; if the credential key was "
            f"replaced: {recovery_path(name)}.",
        ) from None
    merged = {**record.instance_config, **creds}  # same precedence as start()
    try:
        # Blocking network IO (several pages) — run on a thread.
        listing = await asyncio.to_thread(adapter.list_vendor_tenants, merged)
    except VendorTenantListError as exc:
        kind = exc.kind if exc.kind in _VENDOR_FAILURE_CODES else "transport"
        message = " ".join(str(exc.message).split())[:_MAX_VENDOR_MESSAGE_CHARS]
        raise _fail(_VENDOR_FAILURE_CODES[kind], kind, message) from None
    except Exception as exc:  # noqa: BLE001 — an adapter bug, not a vendor answer
        logger.error(
            "[adapters] vendor-tenants: %s adapter raised %s for instance id=%s",
            record.vendor_slug, type(exc).__name__, instance_id,
        )
        raise _fail(
            "INTERNAL_ERROR", "internal",
            f"Listing {name} tenants failed unexpectedly "
            f"({type(exc).__name__}). Check the server log.",
        ) from None

    # Audit FIRST, like every other route here: cache hits are not audited,
    # so a listing cached before a failed audit write would stay servable —
    # every client name — with no audit row at all.
    _audit_vendor_tenant_list(
        operator_id=operator_id, vendor_slug=record.vendor_slug,
        instance_id=instance_id, outcome="ok",
        tenant_count=len(vendor_tenants.clean(listing)[0]), request_id=request_id,
    )
    # The instance may have been disabled while the vendor was answering: do
    # not leave a listing behind for it.
    current = get_instance(instance_id)
    discovery = vendor_tenants.store(instance_id, record.cred_ref, listing)
    if current is None or current.disabled_at is not None:
        vendor_tenants.reset(instance_id)
    else:
        manager = _get_instance_manager(request)
        if manager is not None:
            manager.nudge(instance_id)
    return out(supported=True, discovery=discovery)


# ---------------------------------------------------------------------------
# Instance disable — the supported way to replace an integration
# ---------------------------------------------------------------------------

def _vendor_display_name(request: Request, vendor_slug: str) -> str:
    """Operator-facing vendor name ('Datto RMM'), falling back to the slug."""
    try:
        registry = getattr(request.app.state, "adapter_registry", None)
        cls = registry.get_adapter_class(vendor_slug) if registry is not None else None
        name = getattr(cls, "vendor_display_name", None) or getattr(cls, "display_name", None)
        return str(name) if name else vendor_slug
    except Exception:  # noqa: BLE001 — cosmetic
        return vendor_slug


@router.post(
    "/instances/{instance_id}/disable",
    response_model=DisableInstanceResponse,
)
def disable_instance_endpoint(
    instance_id: int,
    body: DisableInstanceRequest,
    request: Request,
    caller: sessions.SessionInfo = Depends(session_admin_plus),
) -> DisableInstanceResponse:
    """Stop an instance's poller and mark it disabled.

    Credentials are create-only (there is deliberately no read-back or edit
    route), and the partial unique index allows ONE active instance per
    vendor — so correcting or rotating anything credential-shaped (a missing
    webhook secret, a rotated API key) means: disable here, then create a
    corrected instance. Disabling sets `disabled_at`, which takes the row out
    of that index and frees the vendor slot.

    Order matters: the poller is stopped BEFORE the row flips, so a disabled
    row never has a live writer. The webhook receivers only consider
    non-disabled instances, so inbound webhooks for the vendor are rejected
    from the moment the row flips until a replacement exists.

    The stored credential ciphertext is never decrypted on this path, and
    nothing credential-shaped is returned or audited. Idempotent: disabling
    an already-disabled instance is a no-op success with no second audit row.
    """
    from apps.octo.instances import (
        device_links, doorbell, tenant_map, unmapped, vendor_contact,
        vendor_tenants, webhook_receipt,
    )
    from apps.octo.instances.manager import disable_instance, get_instance

    request_id = str(uuid.uuid4())
    record = get_instance(instance_id)
    if record is None:
        raise APIError("NOT_FOUND", f"no adapter instance with id {instance_id}")

    import sqlite3
    try:
        mappings = len(tenant_map.get_mappings(instance_id))
    except sqlite3.OperationalError:  # tenant-map migration not applied yet
        mappings = 0
    if record.disabled_at is not None:
        return DisableInstanceResponse(
            instance_id=record.id,
            vendor_slug=record.vendor_slug,
            status=record.status,
            disabled_at=record.disabled_at,
            already_disabled=True,
            tenant_mappings_not_carried_over=mappings,
            message="instance was already disabled; nothing changed",
        )

    manager = _get_instance_manager(request)
    # Audit FIRST (failure to audit is fatal, so nothing changes unaudited) —
    # same order as the create route.
    _audit_instance_disable(
        operator_id=caller.operator_id,
        vendor_slug=record.vendor_slug,
        instance_id=instance_id,
        previous_status=record.status,
        reason=body.reason,
        request_id=request_id,
    )
    if manager is not None:
        manager.stop_instance(instance_id)  # idempotent; swallows stop() errors

    disable_instance(
        instance_id,
        disabled_by_operator_id=caller.operator_id,
        reason=body.reason,
    )
    unmapped.reset(instance_id)
    vendor_contact.reset(instance_id)
    vendor_tenants.reset(instance_id)  # a listing never outlives its instance
    device_links.reset(instance_id)    # nor do resolved device page addresses
    doorbell.reset(instance_id)        # nor fetched alerts / the fetch budget
    # A replacement instance has a new token and a new id: it starts at
    # "no webhook has reached Athena yet", not with this one's counters.
    webhook_receipt.reset(instance_id, record.vendor_slug)

    fresh = get_instance(instance_id) or record
    return DisableInstanceResponse(
        instance_id=fresh.id,
        vendor_slug=fresh.vendor_slug,
        status=fresh.status,
        disabled_at=fresh.disabled_at,
        tenant_mappings_not_carried_over=mappings,
        message=(
            f"{_vendor_display_name(request, fresh.vendor_slug)} disabled — "
            "it has stopped collecting. To connect it again: + Add integration"
            + (
                f". Its {mappings} site mapping(s) belonged to the old "
                "connection, so map your sites again BEFORE attaching the "
                "webhook (alerts from unmapped sites create pending tenants "
                "or are held in quarantine)."
                if mappings else "."
            )
        ),
    )
