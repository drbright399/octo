"""POST /api/v1/dashboard/vendor-device-link — "open this device in the vendor portal".

Why this is an endpoint and not a URL on the row: the vendor portal addresses
a device by a numeric id that no alert payload carries (payloads hold the
device UID). The vendor API answers a device lookup with a ready-made portal
address — so the link is RESOLVED, through the instance's own client, and
only when an operator clicks Open. Never per row, never per poll: the vendor
rate-limits its API.

The caller sends a REFERENCE — `{client_slug, event_id}` — never a device id:
the device uid is read from that stored event's payload, so the endpoint
cannot be pointed at an arbitrary device.

Refusals, in order (nothing below the line contacts the vendor):
  * analyst+ only — a Viewer never gets a vendor portal link;
  * `client_slug` must be in the caller's scope and hold the event (the same
    404 either way — no oracle for other tenants' events);
  * the event's source must support device links, its payload must carry a
    device uid, exactly one enabled instance must be determinable, its portal
    base must be known, and the payload's vendor tenant (Datto: siteUid) must
    map — adapter_tenant_map — to `client_slug`;
  ---------------------------------------------------------------------------
  * the address the vendor returns must pass the adapter's validation and the
    framework's host allowlist (`device_links.checked_url`);
  * the tenant the VENDOR says the device belongs to must map to
    `client_slug` as well (a device can move between sites after the alert);
    a cached answer that does not map is re-asked, not replayed — the cache
    may be hours stale — and the refusal is remembered per client only.

Answers `{url, …}` rather than redirecting: a GET that redirects would be
drivable cross-site (the session cookie is SameSite=Lax, which a top-level GET
navigation carries) and would spend vendor reads for whoever linked to it; and
a failure must leave the operator where they are, with a sentence — not in a
new tab showing JSON. POST lands in the stricter `admin_write` rate class.
The URL is still computed server-side from validated vendor data against a
host allowlist; the console opens it with rel="noopener noreferrer".

The device object's `webRemoteUrl` (starts a remote-control session) never
gets this far: the vendor client drops it at the socket's edge.
"""
from __future__ import annotations

import asyncio
import logging
import sqlite3
import uuid

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from apps.octo import paths
from apps.octo.api.errors import APIError
from apps.octo.api.role_gates import session_at_least
from apps.octo.api.routers.dashboard import (
    _expand_scope_to_concrete_slugs,
    _parsed_payload,
    _resolve_scope_slugs,
)
from apps.octo.api.vendor_links import DeviceTarget, NoDeviceLink, VendorLinkResolver
from apps.octo.auth import sessions
from apps.octo.instances import device_links
from apps.octo.instances.manager import get_instance

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

session_analyst_plus = session_at_least("analyst")

_FAILURE_CODES = {
    "not_found": "NOT_FOUND",
    "forbidden": "VENDOR_ACCESS_FORBIDDEN",
    "auth": "VENDOR_CREDENTIALS_REJECTED",
    "transport": "VENDOR_UNREACHABLE",
    "invalid": "VENDOR_UNREACHABLE",
}
_MAX_MESSAGE_CHARS = 300
_NOT_YOURS = "no such alert in your scope"


class VendorDeviceLinkIn(BaseModel):
    """A reference to a stored event — deliberately NOT a device id."""
    model_config = ConfigDict(extra="forbid")

    client_slug: str = Field(min_length=1, max_length=128)
    event_id: int = Field(ge=1)


class VendorDeviceLinkOut(BaseModel):
    url: str             # https, the vendor portal's device page; no token
    label: str           # 'Open device in Datto RMM'
    vendor: str
    cached: bool         # answered without contacting the vendor


def _stored_event(slug: str, event_id: int) -> tuple[str, dict | None] | None:
    edb = paths.client_dir(slug) / "events.db"
    if not edb.exists():
        return None
    try:
        conn = sqlite3.connect(f"file:{edb}?mode=ro", uri=True)
        try:
            row = conn.execute(
                "SELECT source, payload FROM events WHERE id = ?", (event_id,),
            ).fetchone()
        finally:
            conn.close()
    except sqlite3.OperationalError:
        return None
    if row is None:
        return None
    return (row[0] or "", _parsed_payload(row[1]))


_MAX_FLIGHTS = 4096


def _flight(request: Request, instance_id: int, device_uid: str) -> asyncio.Lock:
    """One lock per (instance, device): a double click is ONE vendor read,
    while one slow lookup never queues every other operator's click on a
    DIFFERENT device behind it (the per-instance read budget bounds the
    total). On app.state because an asyncio.Lock belongs to the loop that
    serves the app; idle locks are dropped when the table fills."""
    locks = getattr(request.app.state, "device_link_flights", None)
    if locks is None:
        locks = request.app.state.device_link_flights = {}
    key = (instance_id, device_uid)
    lock = locks.get(key)
    if lock is None:
        if len(locks) >= _MAX_FLIGHTS:
            for idle in [k for k, held in locks.items() if not held.locked()]:
                del locks[idle]
        lock = locks[key] = asyncio.Lock()
    return lock


@router.post("/vendor-device-link", response_model=VendorDeviceLinkOut)
async def resolve_vendor_device_link(
    body: VendorDeviceLinkIn,
    request: Request,
    response: Response,
    caller: sessions.SessionInfo = Depends(session_analyst_plus),
) -> VendorDeviceLinkOut:
    request_id = str(uuid.uuid4())
    response.headers["Cache-Control"] = "no-store"

    scope = _expand_scope_to_concrete_slugs(_resolve_scope_slugs(caller.operator_id))
    stored = _stored_event(body.client_slug, body.event_id) if body.client_slug in scope else None
    if stored is None:
        raise APIError("NOT_FOUND", _NOT_YOURS, request_id=request_id)
    source, payload = stored

    resolver = VendorLinkResolver(request, operator_id=caller.operator_id)
    try:
        target = resolver.device_target(
            source=source, client_slug=body.client_slug, payload=payload,
        )
    except NoDeviceLink as exc:
        raise APIError("NOT_FOUND", f"No device link: {exc}.", request_id=request_id)

    label = f"Open device in {target.portal_name}"
    instance, device_uid = target.instance, target.device_uid

    def _mapped_here(device: device_links.CachedDevice) -> bool:
        # Second tenant check — on what the VENDOR says about the device now.
        return resolver.mapped_client(instance.id, device.vendor_tenant_id) == body.client_slug

    def _answer(device: device_links.CachedDevice, *, cached: bool) -> VendorDeviceLinkOut:
        return VendorDeviceLinkOut(
            url=device.portal_url, label=label, vendor=source, cached=cached,
        )

    def _refused_for_this_client() -> APIError:
        # Remembered for THIS client only (FAILURE_THROTTLE_SEC): a click-retry
        # loop is not a stream of vendor reads, and a tenant the device DOES
        # belong to is not answered with someone else's refusal.
        message = (
            f"{target.portal_name} says this device belongs to a site that "
            "is not mapped to this client; the link was refused."
        )
        device_links.remember_failure(
            instance.id, instance.cred_ref, device_uid, code="ISOLATION_VIOLATION",
            message=message, for_client=body.client_slug,
        )
        return APIError("ISOLATION_VIOLATION", message, request_id=request_id)

    def _from_memory() -> VendorDeviceLinkOut | None:
        hit = device_links.lookup(instance.id, instance.cred_ref, device_uid)
        # A cached address is re-checked against the portal base in force
        # NOW (an admin may have changed it since).
        if hit is not None and device_links.checked_url(hit.portal_url, target.portal_base) is None:
            device_links.forget(instance.id, device_uid)
            hit = None
        if hit is not None and _mapped_here(hit):
            return _answer(hit, cached=True)
        failed = device_links.recent_failure(
            instance.id, instance.cred_ref, device_uid, for_client=body.client_slug,
        )
        if failed is not None:
            raise APIError(
                failed.code,
                f"{failed.message} (Not asked again: {target.portal_name} "
                f"answered this moments ago — retry in {failed.retry_in_sec}s.)",
                request_id=request_id,
            )
        if hit is not None:
            # The cached site does not map to this client — and the cache can
            # be STALE for hours while a device has moved between sites. Not
            # refused from memory: ask the vendor again (one read, budgeted),
            # and refuse only on what it says now.
            device_links.forget(instance.id, device_uid)
        return None

    remembered = _from_memory()
    if remembered is not None:
        return remembered
    async with _flight(request, instance.id, device_uid):
        remembered = _from_memory()     # whoever held the lock may have it now
        if remembered is not None:
            return remembered
        device = await _ask_vendor(request, target, request_id)
    if not _mapped_here(device):
        raise _refused_for_this_client()
    return _answer(device, cached=False)


async def _ask_vendor(
    request: Request, target: DeviceTarget, request_id: str,
) -> device_links.CachedDevice:
    """The vendor-contacting half (caller holds the instance's flight lock)."""
    instance = target.instance

    def _fail(kind: str, message: str) -> APIError:
        code = _FAILURE_CODES.get(kind, "VENDOR_UNREACHABLE")
        message = " ".join(str(message).split())[:_MAX_MESSAGE_CHARS]
        device_links.remember_failure(
            instance.id, instance.cred_ref, target.device_uid, code=code, message=message,
            whole_instance=(kind == "auth"),
        )
        logger.info("[device-link] instance id=%s outcome=%s", instance.id, kind)
        return APIError(code, message, request_id=request_id)

    manager = getattr(request.app.state, "instance_manager", None)
    adapter = manager.running_adapter(instance.id) if manager is not None else None
    resolve = getattr(adapter, "resolve_device_portal", None)
    if not callable(resolve):
        raise APIError(
            "SERVICE_UNAVAILABLE",
            f"The {target.portal_name} integration is not running, so the "
            "device page could not be looked up.",
            request_id=request_id,
        )
    wait = device_links.take_vendor_read(instance.id, instance.cred_ref)
    if wait:
        raise APIError(
            "RATE_LIMITED",
            f"Too many device lookups at {target.portal_name} in the last "
            f"minute — retry in {wait}s.",
            request_id=request_id,
        )
    try:
        # Blocking network IO — run on a thread.
        found = await asyncio.to_thread(resolve, target.device_uid, target.portal_base)
    except device_links.DeviceLookupError as exc:
        raise _fail(exc.kind, exc.message) from None
    except Exception as exc:  # noqa: BLE001 — an adapter bug, not a vendor answer
        # Class name only: an exception's text can embed what it was given.
        logger.error(
            "[device-link] %s adapter raised %s for instance id=%s",
            instance.vendor_slug, type(exc).__name__, instance.id,
        )
        raise _fail(
            "transport",
            f"Looking the device up at {target.portal_name} failed "
            f"unexpectedly ({type(exc).__name__}).",
        ) from None

    # The framework's own check, after the adapter's: the host allowlist.
    url = device_links.checked_url(getattr(found, "portal_url", None), target.portal_base)
    if url is None:
        raise _fail(
            "invalid",
            f"{target.portal_name} returned a device page address that did "
            "not pass validation; no link was opened.",
        )
    tenant_id = getattr(found, "vendor_tenant_id", None)
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        # Nothing to map: this is a vendor answer that cannot be checked, not
        # a tenant mismatch — and it is not cached (an answer with a site may
        # come next; the failure memory throttles the retry).
        raise _fail(
            "invalid",
            f"{target.portal_name} did not say which site this device belongs "
            "to, so the link was refused.",
        )
    device = device_links.CachedDevice(portal_url=url, vendor_tenant_id=tenant_id.strip())
    # The instance may have been disabled while the vendor was answering: do
    # not leave anything behind for it, and do not hand out its link.
    current = get_instance(instance.id)
    if current is None or current.disabled_at is not None:
        device_links.reset(instance.id)
        raise APIError(
            "CONFLICT",
            f"The {target.portal_name} integration was disabled meanwhile.",
            request_id=request_id,
        )
    device_links.store(instance.id, instance.cred_ref, target.device_uid, device)
    logger.info("[device-link] instance id=%s outcome=ok", instance.id)
    return device
