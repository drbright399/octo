"""Resolve vendor deep-links from canonical event rows.

Each source adapter implements `deep_link(event, link_type)` per the
shared adapter contract. This module is the seam that calls into that
method from the API layer — given a row out of `events.db`, return a
URL pointing into the originating vendor's portal (or None when no
adapter is registered, no env-based base URL is set, or the adapter
declines the link type).

Centralizing this keeps every endpoint that wants to surface a "View
in vendor →" affordance on one code path. Adding a new adapter requires
no edits here.

The helper is intentionally defensive: ANY adapter exception falls
through to `None` so a buggy adapter can't 500 a search response. We
log via the existing audit hook is NOT done here — these are read-only,
non-state-changing lookups; logging every miss would just be noise.
"""
from __future__ import annotations

import json
from typing import Any

from fastapi import Request

from shared_adapter_contract.types import CanonicalEvent


def _registry(request: Request) -> Any:
    """Pull the AdapterRegistry off `app.state` if it was stashed at boot.
    Missing registry (e.g., tests that don't wire integrations) returns
    None — callers treat that as "no vendor link available"."""
    return getattr(request.app.state, "adapter_registry", None)


def _build_canonical_event(
    *,
    source_host: str | None,
    payload: dict,
    payload_sha256: str,
    received_at: str,
    severity: str,
    summary: str,
) -> CanonicalEvent | None:
    """Reconstruct just enough of a CanonicalEvent for `deep_link()`.

    Adapter implementations typically need only `vendor_event_id` and
    sometimes `source_host`. Other fields are populated best-effort —
    if `vendor_event_id` isn't recoverable, return None so the caller
    falls through to no link.
    """
    vendor_event_id = payload.get("vendor_event_id") or payload.get("id") or payload.get("eventId")
    if not isinstance(vendor_event_id, (str, int)):
        return None
    indicator = payload.get("indicator") if isinstance(payload.get("indicator"), str) else None
    indicator_type = payload.get("indicator_type") if isinstance(payload.get("indicator_type"), str) else None
    try:
        return CanonicalEvent(
            vendor_event_id=str(vendor_event_id),
            received_at=received_at,
            severity=severity,  # type: ignore[arg-type]
            indicator=indicator,
            indicator_type=indicator_type,  # type: ignore[arg-type]
            source_host=source_host,
            summary=summary or "",
            payload=payload,
            payload_sha256=payload_sha256,
        )
    except (TypeError, ValueError):
        return None


def resolve_alert_link(
    request: Request,
    *,
    source_slug: str,
    payload: dict,
    payload_sha256: str,
    source_host: str | None,
    received_at: str,
    severity: str,
    summary: str,
) -> tuple[str | None, str | None]:
    """Return `(deep_link_url, vendor_display_name)` for an event row.

    Either side of the tuple may be None:
      - No adapter registered for `source_slug` → (None, None)
      - Adapter has no `vendor_event_id` in payload → (None, display_name)
      - Adapter's deep_link() returns None / raises → (None, display_name)

    The display_name is still useful even without a URL — the UI surfaces
    it as a "vendor: Datto RMM" badge so operators can see provenance
    even when the link isn't available.
    """
    registry = _registry(request)
    if registry is None:
        return None, None
    adapter_cls = registry.get_adapter_class(source_slug)
    if adapter_cls is None:
        return None, None

    vendor_display_name = getattr(adapter_cls, "vendor_display_name", None)

    event = _build_canonical_event(
        source_host=source_host,
        payload=payload,
        payload_sha256=payload_sha256,
        received_at=received_at,
        severity=severity,
        summary=summary,
    )
    if event is None:
        return None, vendor_display_name

    try:
        instance = adapter_cls()
        url = instance.deep_link(event, "alert")
    except Exception:
        # Adapter bugs or env-based misconfig must NOT break the search
        # response. The caller renders without a link.
        return None, vendor_display_name
    if not isinstance(url, str) or not url:
        return None, vendor_display_name
    return url, vendor_display_name


def resolve_from_payload_text(
    request: Request,
    *,
    source_slug: str,
    payload_text: str,
    payload_sha256: str,
    source_host: str | None,
    received_at: str,
    severity: str,
    summary: str,
) -> tuple[str | None, str | None]:
    """Convenience wrapper for callers that hold `payload` as a JSON
    string (e.g., direct row reads). Handles parse failure → (None,
    display_name) so a malformed payload still surfaces vendor identity."""
    try:
        parsed = json.loads(payload_text)
        if not isinstance(parsed, dict):
            parsed = {}
    except (json.JSONDecodeError, TypeError):
        parsed = {}
    return resolve_alert_link(
        request,
        source_slug=source_slug,
        payload=parsed,
        payload_sha256=payload_sha256,
        source_host=source_host,
        received_at=received_at,
        severity=severity,
        summary=summary,
    )
