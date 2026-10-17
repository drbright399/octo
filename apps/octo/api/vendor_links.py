"""Per-request resolver: stored event payload → vendor portal links.

The API-layer half of `apps.octo.instances.vendor_links` (alert links, built
from the payload) and `apps.octo.instances.device_links` (device links,
resolved through the vendor when an operator clicks Open). One resolver is
built per request; it caches what is per-request constant (the caller's role
tier, the instance list per vendor, tenant-map answers).

ROLE RULE: a Viewer (a client's own user) never receives a vendor portal
link — the MSP's RMM portal is not theirs. Analyst and above do. The rule
lives here, in one place, so no endpoint can forget it.

WHICH INSTANCE: an event row records its vendor ('datto'), not the instance
that ingested it. One enabled instance of that vendor → that one. Several →
the one whose tenant map sends the payload's vendor tenant id to the row's
client; if that does not single one out → no link (never guess).

DEVICE LINKS: a row only carries a REFERENCE (`VendorDeviceRefOut`: tenant +
event id) — building it contacts nobody. The reference is offered only when
the lookup could succeed: the payload has a device id, an instance is
determinable, its portal base is known, and the payload's vendor tenant
(Datto: siteUid) maps — in that instance's tenant map — to the row's client.

No credential is read here: links are built from non-secret instance config
and the ids on the payload.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Optional

from fastapi import Request
from pydantic import BaseModel

from apps.octo.api.role_gates import ROLE_TIER, operator_max_tier
from apps.octo.instances import device_links, vendor_links
from apps.octo.instances.manager import InstanceRecord, list_instances

logger = logging.getLogger(__name__)


class VendorLinkOut(BaseModel):
    kind: str            # 'alert'
    label: str           # 'Open in Datto RMM'
    url: str             # https, vendor portal, never carries a token
    vendor: str          # adapter slug — 'datto'


class VendorDeviceRefOut(BaseModel):
    """"Open the device in <vendor>" — a reference, NOT a URL. The console
    posts it to `/dashboard/vendor-device-link` when the operator clicks."""
    vendor: str          # adapter slug — 'datto'
    label: str           # 'Open device in Datto RMM'
    client_slug: str
    event_id: int


@dataclass(frozen=True)
class DeviceTarget:
    """Everything a device lookup needs, established WITHOUT the vendor."""
    instance: InstanceRecord
    device_uid: str
    portal_base: str
    portal_name: str


class NoDeviceLink(Exception):
    """Why no device link can be offered — operator-safe text."""


def supports_links(adapter_cls: Any) -> bool:
    return all(
        callable(getattr(adapter_cls, name, None))
        for name in ("vendor_link_spec", "vendor_link_ids")
    )


class VendorLinkResolver:
    def __init__(self, request: Request, *, operator_id: int) -> None:
        self._registry = getattr(request.app.state, "adapter_registry", None)
        self._allowed = operator_max_tier(operator_id) >= ROLE_TIER["analyst"]
        self._instances: dict[str, list[InstanceRecord]] = {}
        self._mapped: dict[tuple[int, str], Optional[str]] = {}

    @property
    def allowed(self) -> bool:
        return self._allowed and self._registry is not None

    def linkable_sources(self) -> set[str]:
        """Vendor slugs whose adapter can build links (for callers that want
        to fetch payloads only where a link is possible)."""
        if not self.allowed:
            return set()
        return {
            cls.vendor_slug for cls in self._registry.list_adapter_classes()
            if supports_links(cls)
        }

    def links(
        self,
        *,
        source: str,
        client_slug: str,
        payload: Any,
        kinds: tuple[str, ...] = vendor_links.LINK_KINDS,
    ) -> list[VendorLinkOut]:
        if not self.allowed or not isinstance(payload, dict):
            return []
        try:
            adapter_cls = self._registry.get_adapter_class(source)
            if adapter_cls is None or not supports_links(adapter_cls):
                return []
            ids = adapter_cls.vendor_link_ids(payload)
            instance = self._instance_for(adapter_cls, source, client_slug, payload)
            if instance is None:
                return []
            built = vendor_links.build_links(
                instance.instance_config, adapter_cls.vendor_link_spec(), ids, kinds,
            )
        except Exception as exc:  # noqa: BLE001 — a link must never 500 a feed
            logger.warning("[vendor-links] %s: %s", source, type(exc).__name__)
            return []
        return [
            VendorLinkOut(kind=b.kind, label=b.label, url=b.url, vendor=source)
            for b in built
        ]

    # ----- Device links: a reference per row, resolved on click -----

    def device_ref(
        self, *, source: str, client_slug: str, event_id: int, payload: Any,
    ) -> Optional[VendorDeviceRefOut]:
        """The row's "open device" reference, or None. Never contacts the
        vendor."""
        try:
            target = self.device_target(
                source=source, client_slug=client_slug, payload=payload,
            )
        except NoDeviceLink:
            return None
        except Exception as exc:  # noqa: BLE001 — a link must never 500 a feed
            logger.warning("[vendor-links] %s device ref: %s", source, type(exc).__name__)
            return None
        return VendorDeviceRefOut(
            vendor=source, label=f"Open device in {target.portal_name}",
            client_slug=client_slug, event_id=event_id,
        )

    def device_target(
        self, *, source: str, client_slug: str, payload: Any,
    ) -> DeviceTarget:
        """Raises NoDeviceLink (operator-safe reason) unless a device lookup
        for this payload is possible AND the payload's vendor tenant maps to
        `client_slug`."""
        if not self.allowed:
            raise NoDeviceLink("vendor portal links are not available to this role")
        if not isinstance(payload, dict):
            raise NoDeviceLink("this alert has no readable payload")
        adapter_cls = self._registry.get_adapter_class(source)
        if (
            adapter_cls is None or not supports_links(adapter_cls)
            or not device_links.supports_device_links(adapter_cls)
        ):
            raise NoDeviceLink("this alert's source cannot link to a device page")
        spec = adapter_cls.vendor_link_spec()
        ids = adapter_cls.vendor_link_ids(payload)
        device_uid = ids.get("device_uid")
        if not device_uid:
            raise NoDeviceLink("this alert does not carry the vendor's device id")
        instance = self._instance_for(adapter_cls, source, client_slug, payload)
        if instance is None:
            raise NoDeviceLink(
                f"no single enabled {spec.portal_name} integration could be "
                "determined for this alert"
            )
        base = vendor_links.effective_settings(
            instance.instance_config, spec,
        ).portal_base_url
        if base is None:
            raise NoDeviceLink(
                f"the {spec.portal_name} portal address is not known — an "
                "admin can enter it under Settings → Integrations → Portal links"
            )
        if self.mapped_client(instance.id, ids.get("site_uid")) != client_slug:
            raise NoDeviceLink(
                "this alert's vendor site is not mapped to this client, so its "
                "device page is not offered here"
            )
        return DeviceTarget(instance, device_uid, base, spec.portal_name)

    def mapped_client(self, instance_id: int, vendor_tenant_id: Any) -> Optional[str]:
        """adapter_tenant_map: vendor tenant id → client slug (memoised)."""
        if not isinstance(vendor_tenant_id, str) or not vendor_tenant_id:
            return None
        key = (instance_id, vendor_tenant_id)
        if key not in self._mapped:
            from apps.octo.instances import tenant_map

            self._mapped[key] = tenant_map.resolve(instance_id, vendor_tenant_id)
        return self._mapped[key]

    def _instance_for(
        self, adapter_cls: Any, source: str, client_slug: str, payload: dict[str, Any],
    ) -> Optional[InstanceRecord]:
        if source not in self._instances:
            self._instances[source] = [
                r for r in list_instances(include_disabled=False)
                if r.vendor_slug == source
            ]
        candidates = self._instances[source]
        if len(candidates) <= 1:
            return candidates[0] if candidates else None
        vendor_tid = adapter_cls().route_to_tenant(payload)
        if not vendor_tid:
            return None
        matches = [
            r for r in candidates
            if self.mapped_client(r.id, vendor_tid) == client_slug
        ]
        return matches[0] if len(matches) == 1 else None
