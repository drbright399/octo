"""Vendor portal link settings — `/api/v1/integrations/{vendor_slug}/{instance_id}/vendor-links`.

"Open in <vendor>" ALERT links are built from a per-instance portal base URL
plus an alert path template (`apps.octo.instances.vendor_links`). The base is
normally derived from the instance's API URL; the path has a default. An admin
can override either here — non-secret instance config, never a credential.
GET also returns a sample URL so the admin can see what is built BEFORE
analysts rely on it.

DEVICE links have no template: the portal addresses a device by an id no
payload carries, so they are looked up at the vendor when an operator clicks
Open (`apps.octo.instances.device_links`) and must land on the portal base
configured here. Changing the settings drops the resolved addresses.

admin+ gated. PUT validates everything (https only, host under the vendor's
own domain, plain path + known placeholders), is audited (before → after) and
never contacts the vendor.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, Path, Request
from pydantic import BaseModel, ConfigDict, Field

from apps.octo import paths
from apps.octo.api.errors import APIError
from apps.octo.api.role_gates import session_admin_plus
from apps.octo.api.vendor_links import supports_links
from apps.octo.auth import audit, sessions
from apps.octo.db import connect
from apps.octo.instances import device_links, vendor_links
from apps.octo.instances.manager import (
    InstanceRecord,
    get_instance,
    update_instance_config,
)

router = APIRouter(prefix="/integrations", tags=["integration-vendor-links"])

# Shown in sample URLs only — obviously not a real id.
_SAMPLE_IDS = {
    "alert_uid": "ALERT-UID",
    "device_uid": "DEVICE-UID",
    "site_uid": "SITE-UID",
}


class VendorLinkSettingsIn(BaseModel):
    """Blank / null = use the default for that field. An unknown field is
    refused, not ignored: a setting that silently does nothing is a lie."""
    model_config = ConfigDict(extra="forbid")

    portal_base_url: str | None = Field(default=None, max_length=400)
    alert_path_template: str | None = Field(default=None, max_length=400)


class VendorLinkSettingsOut(BaseModel):
    vendor_slug: str
    instance_id: int
    portal_name: str
    allowed_domain: str
    placeholders: list[str]
    # What an admin has overridden (absent = default in use).
    overrides: dict[str, str]
    # What link building uses right now.
    portal_base_url: str | None
    alert_path_template: str
    # The defaults, so the form can show them as placeholders.
    derived_portal_base_url: str | None
    default_alert_path_template: str
    paths_verified: bool
    sample_alert_url: str | None
    # Device pages are looked up at the vendor on click (no template). True
    # when this adapter can do that AND a portal base is known.
    device_links_resolved: bool
    links_enabled: bool
    # Why there are no links, in operator words. Null when links_enabled.
    problem: str | None = None


def _adapter_and_record(
    request: Request, vendor_slug: str, instance_id: int,
) -> tuple[Any, InstanceRecord]:
    record = get_instance(instance_id)
    if record is None or record.vendor_slug != vendor_slug:
        raise APIError(
            "NOT_FOUND", f"no {vendor_slug} adapter instance with id {instance_id}",
        )
    registry = getattr(request.app.state, "adapter_registry", None)
    adapter_cls = registry.get_adapter_class(vendor_slug) if registry else None
    if adapter_cls is None or not supports_links(adapter_cls):
        raise APIError(
            "NOT_FOUND", f"the {vendor_slug} integration does not offer portal links",
        )
    return adapter_cls, record


def _out(adapter_cls: Any, record: InstanceRecord) -> VendorLinkSettingsOut:
    spec = adapter_cls.vendor_link_spec()
    eff = vendor_links.effective_settings(record.instance_config, spec)
    problem = None
    if eff.portal_base_url is None:
        problem = (
            f"No {spec.portal_name} links are shown: the portal address could "
            "not be derived from this integration's API URL (it is not in the "
            "vendor's documented form), and none has been entered here. Enter "
            "the portal base URL to enable links."
        )
    return VendorLinkSettingsOut(
        vendor_slug=record.vendor_slug,
        instance_id=record.id,
        portal_name=spec.portal_name,
        allowed_domain=spec.allowed_domain,
        placeholders=["{" + p + "}" for p in vendor_links.PLACEHOLDERS],
        overrides=eff.overrides,
        portal_base_url=eff.portal_base_url,
        alert_path_template=eff.alert_path_template,
        derived_portal_base_url=eff.derived_portal_base_url,
        default_alert_path_template=spec.default_alert_path,
        paths_verified=spec.paths_verified,
        sample_alert_url=vendor_links.build_url(
            eff.portal_base_url, eff.alert_path_template, _SAMPLE_IDS, spec=spec,
        ),
        device_links_resolved=(
            eff.portal_base_url is not None
            and device_links.supports_device_links(adapter_cls)
        ),
        links_enabled=eff.portal_base_url is not None,
        problem=problem,
    )


@router.get(
    "/{vendor_slug}/{instance_id}/vendor-links",
    response_model=VendorLinkSettingsOut,
)
def get_vendor_link_settings(
    request: Request,
    vendor_slug: str = Path(...),
    instance_id: int = Path(...),
    caller: sessions.SessionInfo = Depends(session_admin_plus),
) -> VendorLinkSettingsOut:
    adapter_cls, record = _adapter_and_record(request, vendor_slug, instance_id)
    return _out(adapter_cls, record)


@router.put(
    "/{vendor_slug}/{instance_id}/vendor-links",
    response_model=VendorLinkSettingsOut,
)
def put_vendor_link_settings(
    body: VendorLinkSettingsIn,
    request: Request,
    vendor_slug: str = Path(...),
    instance_id: int = Path(...),
    caller: sessions.SessionInfo = Depends(session_admin_plus),
) -> VendorLinkSettingsOut:
    adapter_cls, record = _adapter_and_record(request, vendor_slug, instance_id)
    if record.disabled_at is not None:
        raise APIError(
            "CONFLICT",
            f"adapter instance {instance_id} is disabled; its settings can no "
            "longer be changed",
        )
    spec = adapter_cls.vendor_link_spec()
    try:
        cleaned = vendor_links.validate_settings(body.model_dump(), spec)
    except ValueError as exc:
        raise APIError("VALIDATION_FAILED", str(exc))

    before = vendor_links.effective_settings(record.instance_config, spec).overrides
    # Audit FIRST (failure to audit is fatal, so nothing changes unaudited).
    g_audit = connect(paths.global_audit_db_path())
    try:
        audit.append(g_audit, audit.AuditEntry(
            actor=str(caller.operator_id),
            actor_kind="human",
            action="adapter_vendor_links_update",
            target_kind="adapter_instance",
            target_id=str(instance_id),
            client_slug="global",
            before_state={"vendor_slug": vendor_slug, "vendor_links": before},
            after_state={"vendor_slug": vendor_slug, "vendor_links": cleaned},
            reason="vendor portal link settings changed via admin API",
            request_id=str(uuid.uuid4()),
        ))
    finally:
        g_audit.close()

    update_instance_config(
        instance_id, {vendor_links.SETTINGS_KEY: cleaned or None},
    )
    # Resolved device addresses were validated against the OLD portal base.
    device_links.reset(instance_id)
    fresh = get_instance(instance_id)
    return _out(adapter_cls, fresh if fresh is not None else record)
