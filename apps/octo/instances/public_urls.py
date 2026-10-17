"""Vendor-facing URLs — built from the INGEST hostname, never the console's.

A deployment has two public names with very different exposure:

  OCTO_PUBLIC_BASE_URL         the operator CONSOLE origin. In a hardened
                               deployment it sits behind an interactive access
                               gate, so a vendor POSTing to it is silently
                               blocked at the edge.
  OCTO_PUBLIC_INGEST_BASE_URL  the vendor-facing name that serves ONLY
                               /api/v1/webhooks and /api/v1/ingest.

Every URL an operator is told to paste into a vendor portal comes from here.
When the ingest name is not configured there is deliberately NO fallback to
the console origin: a URL that can never receive traffic is worse than none,
because the vendor side accepts it and the failure is invisible. Callers get
None plus :data:`NO_INGEST_HOST_PROBLEM` to show instead.
"""
from __future__ import annotations

import logging
import os
from typing import Optional
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

INGEST_BASE_URL_ENV = "OCTO_PUBLIC_INGEST_BASE_URL"

# How an owner fixes it, in plain words. One sentence set, reused by the
# wizard, the one-time token screen and the instance-card warning.
SET_INGEST_HOST_HOWTO = (
    "To turn them on: set the ingest hostname in this bundle's compose file "
    "(the OCTO_PUBLIC_INGEST_BASE_URL line in docker-compose.yml), make sure "
    "that name reaches the ingest edge, then recreate the octo-core container "
    "— the bundle deploy guide (docs/operations/bundle.md, 'Template "
    "variables') has the exact steps."
)

NO_INGEST_HOST_PROBLEM = (
    "No public ingest hostname is configured for this deployment, so "
    "real-time webhooks cannot work yet. Polling is unaffected. "
    + SET_INGEST_HOST_HOWTO
    + " The console address is NOT a substitute: it sits behind the operator "
    "sign-in gate, so a vendor posting there is blocked."
)


_warned: set[str] = set()


def _warn_once(msg: str, *args: object) -> None:
    """This runs on every integrations-list request; a misrendered compose
    file must produce ONE log line, not one per page load."""
    if msg not in _warned:
        _warned.add(msg)
        logger.warning(msg, *args)


def public_ingest_base_url() -> Optional[str]:
    """The configured ingest origin without a trailing slash, or None.

    Anything that is not an http(s) URL with a hostname counts as unset — the
    compose template renders an unset optional host as the bare 'https://'.
    """
    raw = os.environ.get(INGEST_BASE_URL_ENV, "").strip().rstrip("/")
    if not raw:
        return None
    if "${" in raw:
        # The compose file was rendered without this variable in its envsubst
        # list: a literal placeholder is not a hostname.
        _warn_once(
            "[public-urls] %s still holds an unrendered template variable — "
            "treating it as unset", INGEST_BASE_URL_ENV,
        )
        return None
    parts = urlsplit(raw)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        if raw not in ("https:", "http:"):  # not just the template's empty render
            _warn_once(
                "[public-urls] %s is set but is not an http(s) URL with a "
                "hostname — treating it as unset", INGEST_BASE_URL_ENV,
            )
        return None
    return raw


def webhook_url(vendor_slug: str) -> Optional[str]:
    """The URL a vendor posts `vendor_slug` webhooks to, or None when no
    ingest hostname is configured."""
    base = public_ingest_base_url()
    return f"{base}/api/v1/webhooks/{vendor_slug}" if base else None
