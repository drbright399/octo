"""Datto RMM portal links — the Datto-specific half of
`apps.octo.instances.vendor_links`.

Portal base: Datto names its platforms; the API for a platform is served at
``<platform>-api.centrastage.net`` and its web portal at
``https://<platform>.rmm.datto.com``. The base is DERIVED from the API URL the
operator configured, and only when that URL is exactly of this form — any
other API URL (a proxy, a future naming scheme) yields NO base and therefore no
links, until an admin enters the portal base by hand. Nothing is guessed.

Alert link: ``/alert/<alertUid>`` — confirmed against the live portal; the
template stays a per-instance setting in case the vendor moves it.

Device link: NOT templated. The portal addresses a device by a NUMERIC id
(``/device/<number>[/<hostname>]``, the trailing host name being cosmetic) and
alert payloads carry only the device UID. The API's device object has a
ready-made ``portalUrl``; `device_portal_url()` is the check that value must
pass before anyone is sent to it (see `apps.octo.instances.device_links`).

Site link (the Fleet drawer): ``/site/<number>/<name slug>`` — VERIFIED
2026-10-08 against a live portal address copied from the browser
(``https://<platform>.rmm.datto.com/site/<digits>/<site-name-slug>``). Like a
device, a site is addressed by a NUMERIC id that mappings and alerts do not
carry (they hold the site UID); the account's site list does — see
`site_ids` (learned by the inventory poller, at most daily). `site_portal_url`
rebuilds the address from the portal base, the digits and a slug of the name
(ours, ascii-lowercase-hyphen: the portal builds the same kind) — nothing of
a vendor string survives into it.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any, Optional
from urllib.parse import urlsplit

from apps.octo.adapters.datto.fields import (
    _alert_device_uid,
    _alert_site_uid,
    _alert_uid,
)
from apps.octo.instances.vendor_links import (
    VendorLinkSpec,
    build_url,
    validate_portal_base,
)

_API_HOST_RE = re.compile(r"^([a-z][a-z0-9]{1,30})-api\.centrastage\.net$")

# ASCII digits only (`\d` also matches other scripts' digits).
_DEVICE_PATH_RE = re.compile(r"^/device/([0-9]{1,20})(?:/[^/?#]*)?$")
_MAX_PORTAL_URL_CHARS = 300
# A site's numeric portal id (`re.fullmatch`): ASCII digits, 1–12 of them.
SITE_ID_RE = re.compile(r"[0-9]{1,12}")
_SITE_PATH_RE = re.compile(r"^/site/([0-9]{1,12})(?:/[^/?#]*)?$")
SITE_SLUG_MAX = 60

LINK_SPEC = VendorLinkSpec(
    portal_name="Datto RMM",
    allowed_domain="datto.com",
    default_alert_path="/alert/{alert_uid}",
    paths_verified=True,
)


def derive_portal_base(api_url: Any) -> Optional[str]:
    """``https://<platform>.rmm.datto.com`` for an API URL that is exactly
    ``https://<platform>-api.centrastage.net[/]``; otherwise None."""
    if not isinstance(api_url, str):
        return None
    try:
        parts = urlsplit(api_url.strip())
        if parts.port is not None:
            return None
    except ValueError:
        return None
    if parts.scheme != "https" or "@" in parts.netloc:
        return None
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        return None
    match = _API_HOST_RE.fullmatch((parts.hostname or "").lower())
    if match is None:
        return None
    return f"https://{match.group(1)}.rmm.datto.com"


def device_portal_url(portal_url: Any, portal_base: Any) -> Optional[str]:
    """The address to open for a device, from the vendor's `portalUrl` — or
    None. `portal_url` is VENDOR DATA and is treated as hostile: it must be a
    plain https URL whose host is EXACTLY `portal_base`'s (the base derived
    from the configured API URL, or the one an admin entered), without
    userinfo, port, query or fragment, and whose path is
    ``/device/<digits>[/<one cosmetic segment>]``.

    The result is REBUILT from the base and the digits: nothing else of the
    vendor's string survives into the link."""
    if not isinstance(portal_url, str) or not isinstance(portal_base, str):
        return None
    if not portal_url or len(portal_url) > _MAX_PORTAL_URL_CHARS or "\\" in portal_url:
        return None
    if not portal_url.isprintable() or any(ch.isspace() for ch in portal_url):
        return None
    if "?" in portal_url or "#" in portal_url:
        return None
    try:
        parts, base = urlsplit(portal_url), urlsplit(portal_base)
        if parts.port is not None or base.port is not None:
            return None
    except ValueError:
        return None
    host = (base.hostname or "").lower()
    if base.scheme != "https" or not host or base.netloc.lower() != host:
        return None
    if parts.scheme != "https" or parts.netloc.lower() != host:
        return None         # also refuses userinfo and a port: netloc != host
    match = _DEVICE_PATH_RE.fullmatch(parts.path)
    if match is None:
        return None
    return f"https://{host}/device/{match.group(1)}"


def _site_id_from_portal_url(value: Any) -> Optional[str]:
    """The digits of a site's `portalUrl` — a plain https URL on a host under
    datto.com (no userinfo, port, query or fragment) whose path is
    ``/site/<digits>[/<one cosmetic segment>]`` — or None."""
    if not isinstance(value, str) or not value or len(value) > _MAX_PORTAL_URL_CHARS:
        return None
    if not value.isprintable() or any(ch.isspace() for ch in value) or \
            any(ch in value for ch in "\\?#@"):
        return None
    try:
        parts = urlsplit(value)
        if parts.port is not None:
            return None
    except ValueError:
        return None
    host = (parts.hostname or "").lower()
    domain = LINK_SPEC.allowed_domain
    if parts.scheme != "https" or parts.netloc.lower() != host or \
            not (host == domain or host.endswith("." + domain)):
        return None
    match = _SITE_PATH_RE.fullmatch(parts.path)
    return match.group(1) if match else None


def site_portal_id(site: Any) -> Optional[str]:
    """The NUMERIC id the portal addresses a site by, from ONE entry of the
    account's site list — or None. Read from `id` (an integer, or a string of
    ASCII digits; at most 12) and, when the entry carries one, from the
    digits of its `portalUrl`; both present and different → None (never
    guess between them)."""
    if not isinstance(site, dict):
        return None
    raw = site.get("id")
    if isinstance(raw, int) and not isinstance(raw, bool) and raw >= 0:
        raw = str(raw)
    from_id = raw if isinstance(raw, str) and SITE_ID_RE.fullmatch(raw) else None
    from_url = _site_id_from_portal_url(site.get("portalUrl"))
    if from_id and from_url and int(from_id) != int(from_url):
        return None
    return from_id or from_url


def site_slug(name: Any) -> str:
    """The cosmetic last segment of a site's portal address: the name in
    ascii lower case, every run of anything else one '-' ('Café & Bar' →
    'cafe-bar', 'Straße' → 'strasse'; apostrophes dropped), at most
    SITE_SLUG_MAX characters; '' when nothing is left (the link is then
    ``/site/<id>`` alone)."""
    if not isinstance(name, str):
        return ""
    text = unicodedata.normalize("NFKD", name.casefold())
    text = text.encode("ascii", "ignore").decode("ascii").replace("'", "")
    slug = re.sub(r"[^a-z0-9]+", "-", text).strip("-")
    return slug[:SITE_SLUG_MAX].rstrip("-")


def site_portal_url(portal_base: Any, site_id: Any, name: Any = None) -> Optional[str]:
    """``<portal base>/site/<id>/<slug of name>`` — or None when the id is
    not 1–12 ASCII digits or the base is not a valid Datto portal base. Built
    from the base, the digits and our own slug only."""
    if not isinstance(site_id, str) or not SITE_ID_RE.fullmatch(site_id):
        return None
    try:
        base = validate_portal_base(portal_base, allowed_domain=LINK_SPEC.allowed_domain)
    except ValueError:
        return None
    slug = site_slug(name)
    return build_url(base, f"/site/{site_id}" + (f"/{slug}" if slug else ""), {})


def link_ids(payload: Any) -> dict[str, str]:
    """Placeholder → Datto's own id, from either inbound shape. A blank or
    unsubstituted ('[alert_uid]') value is simply absent."""
    env = payload if isinstance(payload, dict) else {}
    found = {
        "alert_uid": _alert_uid(env),
        "device_uid": _alert_device_uid(env),
        "site_uid": _alert_site_uid(env),
    }
    return {k: v for k, v in found.items() if v}
