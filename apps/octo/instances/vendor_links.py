"""Vendor portal ALERT links ("Open in <vendor>") — the vendor-neutral half.

(Device links are not built here: a portal may address a device by an id no
payload carries, so they are resolved through the vendor on demand — see
`apps.octo.instances.device_links`. Both share the portal base below.)

An earlier version of this product built such links and "sometimes the link
just went to the vendor's home dashboard". The rules here exist so that cannot
happen silently from OUR side:

  * a link is built SERVER-side, from the vendor's own ids on the stored
    payload plus a per-instance portal base URL — never from a hostname, never
    from a guess. Anything missing or odd → NO link (an absent link is honest;
    a wrong one is not);
  * the portal base and the alert path template are non-secret instance
    settings. They are validated when an admin saves them AND again every time
    a link is built (the stored value is never trusted);
  * a template may only contain a plain path and the known {placeholders}; ids
    are percent-encoded whole, so an id can never add a path segment, a query,
    a fragment or userinfo. The ONE exception is declared by the adapter
    (`VendorLinkSpec.keep_unencoded`): a few harmless characters an id of ONE
    placeholder keeps as they are — and only when the whole id matches the
    vendor's strict shape for it. UniFi's console host id is
    ``<hex>:<digits>``; its portal answers "Access denied" for ``%3A``. An id
    that carries such a character but does not match the shape yields NO link
    (encoded, it would be a link we know is wrong). '/', '?', '#', '@', '%',
    '.', whitespace and backslash can never be kept; an id that is '.' or
    '..' never fills a placeholder;
  * a link never carries a credential or token: nothing in this module has
    access to one.

An adapter opts in by offering, on its CLASS:

    vendor_link_spec() -> VendorLinkSpec
    vendor_link_ids(payload) -> dict[str, str]       # placeholder → vendor id
    derive_portal_base(config) -> str | None         # from its own API URL

Settings live in ``adapter_instances.instance_config_json``:

    "derived_portal_base_url": "https://…"   written by the framework at start
    "vendor_links": {"portal_base_url": …, "alert_path_template": …}
                                             written by an admin
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping, Optional
from urllib.parse import quote, urlsplit

PLACEHOLDERS: tuple[str, ...] = ("alert_uid", "device_uid", "site_uid")
LINK_KINDS: tuple[str, ...] = ("alert",)
# Which placeholder a template of each kind MUST contain — a template without
# it is exactly the link that "just goes to the home dashboard".
_REQUIRED_PLACEHOLDER = {"alert": "alert_uid"}

DERIVED_BASE_KEY = "derived_portal_base_url"
SETTINGS_KEY = "vendor_links"
SETTING_FIELDS = ("portal_base_url", "alert_path_template")

MAX_URL_CHARS = 200
MAX_TEMPLATE_CHARS = 200
MAX_ID_CHARS = 128

_HOST_RE = re.compile(
    r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)
_PLAIN_PATH_RE = re.compile(r"^/[A-Za-z0-9._~/-]*$")
_PLACEHOLDER_RE = re.compile(r"\{([^{}]*)\}")
# What an id may ever keep unencoded: ':' and the RFC 3986 sub-delims that are
# plain data inside a path segment. NOT '/', '?', '#', '@', '%', '.', quotes,
# brackets, whitespace or '\\' — whatever an adapter declares.
KEEPABLE_ID_CHARS = frozenset(":!$&*+,;=")


@dataclass(frozen=True)
class KeptIdChars:
    """Characters the ids of ONE placeholder keep unencoded — only an id whose
    WHOLE value matches `shape` (`re.fullmatch`)."""

    placeholder: str
    chars: str
    shape: re.Pattern[str]

    def __post_init__(self) -> None:
        if self.placeholder not in PLACEHOLDERS:
            raise ValueError(f"unknown placeholder {self.placeholder!r}")
        if not self.chars or not set(self.chars) <= KEEPABLE_ID_CHARS:
            raise ValueError("an id may only keep these characters unencoded: "
                             + "".join(sorted(KEEPABLE_ID_CHARS)))
        if not isinstance(self.shape, re.Pattern):
            raise ValueError("shape must be a compiled pattern")


@dataclass(frozen=True)
class VendorLinkSpec:
    """What an adapter declares about its portal."""

    portal_name: str
    """'Datto RMM' — the link reads 'Open in Datto RMM'."""

    allowed_domain: str
    """Registrable domain every portal base must sit under ('datto.com')."""

    default_alert_path: str

    paths_verified: bool = False
    """False = the default alert path was never checked against the live
    portal; the settings panel says so."""

    keep_unencoded: tuple[KeptIdChars, ...] = ()
    """Per placeholder, the characters an id of the vendor's own shape keeps
    as they are (see the module note). Empty: every id is encoded whole."""


@dataclass(frozen=True)
class VendorLink:
    kind: str
    label: str
    url: str


@dataclass(frozen=True)
class EffectiveLinkSettings:
    portal_base_url: Optional[str]
    alert_path_template: str
    derived_portal_base_url: Optional[str]
    overrides: dict[str, str]


# ---------------------------------------------------------------------------
# Validation — used on save AND on every build
# ---------------------------------------------------------------------------

def _printable(value: str) -> bool:
    return value.isprintable() and not any(ch.isspace() for ch in value)


def validate_portal_base(value: Any, *, allowed_domain: str) -> str:
    """Normalised ``https://host`` or ValueError (operator-readable)."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("portal base URL is blank")
    url = value.strip()
    if len(url) > MAX_URL_CHARS or not _printable(url) or "\\" in url:
        raise ValueError(
            "portal base URL must be a plain https:// address without spaces"
        )
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        raise ValueError("portal base URL is not a valid URL") from None
    if parts.scheme != "https":
        raise ValueError("portal base URL must start with https://")
    if "@" in parts.netloc or parts.username or parts.password:
        raise ValueError("portal base URL must not contain a user name or password")
    if port is not None:
        raise ValueError("portal base URL must not name a port")
    if parts.query or parts.fragment or "?" in url or "#" in url:
        raise ValueError("portal base URL must not contain '?' or '#'")
    if parts.path not in ("", "/"):
        raise ValueError(
            "portal base URL is the site only (https://host) — put the path in "
            "the path templates"
        )
    host = (parts.hostname or "").lower()
    if not _HOST_RE.fullmatch(host):
        raise ValueError("portal base URL needs a plain DNS host name")
    domain = allowed_domain.lower()
    if host != domain and not host.endswith("." + domain):
        raise ValueError(f"portal base URL must be a host under {domain}")
    return f"https://{host}"


def validate_path_template(value: Any, *, kind: str) -> str:
    """The template unchanged, or ValueError (operator-readable)."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{kind} path template is blank")
    template = value.strip()
    if len(template) > MAX_TEMPLATE_CHARS:
        raise ValueError(f"{kind} path template is longer than {MAX_TEMPLATE_CHARS} characters")
    names = _PLACEHOLDER_RE.findall(template)
    unknown = sorted({n for n in names if n not in PLACEHOLDERS})
    if unknown:
        raise ValueError(
            f"{kind} path template: unknown placeholder {{{unknown[0][:32]}}} — "
            "allowed: " + ", ".join("{" + p + "}" for p in PLACEHOLDERS)
        )
    plain = _PLACEHOLDER_RE.sub("x", template)
    if not plain.startswith("/") or plain.startswith("//"):
        raise ValueError(f"{kind} path template must start with a single '/'")
    if not _PLAIN_PATH_RE.fullmatch(plain):
        raise ValueError(
            f"{kind} path template may only contain letters, digits, '/', '-', "
            "'.', '_', '~' and the placeholders (no '?', '#', '@', '%', spaces)"
        )
    if any(seg in (".", "..") for seg in plain.split("/")):
        raise ValueError(f"{kind} path template must not contain '.' or '..' segments")
    required = _REQUIRED_PLACEHOLDER[kind]
    if required not in names:
        raise ValueError(
            f"{kind} path template must contain {{{required}}} — without it "
            "every link would open the same page"
        )
    return template


def validate_settings(raw: Any, spec: VendorLinkSpec) -> dict[str, str]:
    """Operator overrides, validated. Blank / null field = "use the default"
    (dropped). Unknown fields are refused. Raises ValueError."""
    if not isinstance(raw, Mapping):
        raise ValueError("vendor link settings must be an object")
    unknown = sorted(str(k)[:32] for k in raw if k not in SETTING_FIELDS)
    if unknown:
        raise ValueError(f"unknown vendor link setting {unknown[0]!r}")
    out: dict[str, str] = {}
    for field in SETTING_FIELDS:
        value = raw.get(field)
        if value is None or (isinstance(value, str) and not value.strip()):
            continue
        if field == "portal_base_url":
            out[field] = validate_portal_base(value, allowed_domain=spec.allowed_domain)
        else:
            out[field] = validate_path_template(value, kind="alert")
    return out


def effective_settings(
    instance_config: Mapping[str, Any], spec: VendorLinkSpec,
) -> EffectiveLinkSettings:
    """What link building will use. Stored values are re-validated; a stored
    value that no longer validates is IGNORED (→ default, or no base)."""
    stored = instance_config.get(SETTINGS_KEY)
    stored = stored if isinstance(stored, Mapping) else {}
    overrides: dict[str, str] = {}
    for field in SETTING_FIELDS:
        try:
            overrides.update(validate_settings({field: stored.get(field)}, spec))
        except ValueError:
            continue
    try:
        derived: Optional[str] = validate_portal_base(
            instance_config.get(DERIVED_BASE_KEY), allowed_domain=spec.allowed_domain,
        )
    except ValueError:
        derived = None
    return EffectiveLinkSettings(
        portal_base_url=overrides.get("portal_base_url") or derived,
        alert_path_template=overrides.get("alert_path_template", spec.default_alert_path),
        derived_portal_base_url=derived,
        overrides=overrides,
    )


# ---------------------------------------------------------------------------
# Building
# ---------------------------------------------------------------------------

def _usable_id(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    if not value or len(value) > MAX_ID_CHARS or value != value.strip():
        return None
    return value if _printable(value) else None


def encode_id(vendor_id: str, keep: Optional[KeptIdChars] = None) -> Optional[str]:
    """One id as it goes into a path: percent-encoded whole — or, when `keep`
    names a character the id carries, with those characters kept, provided
    the WHOLE id matches `keep.shape`; None when it does not (and for '.' /
    '..', which a browser would resolve as a path step)."""
    if vendor_id in (".", ".."):
        return None
    if keep is None or not any(ch in keep.chars for ch in vendor_id):
        return quote(vendor_id, safe="")
    if not keep.shape.fullmatch(vendor_id):
        return None
    return quote(vendor_id, safe=keep.chars)


def build_url(
    base: Optional[str], template: str, ids: Mapping[str, Any],
    *, spec: Optional[VendorLinkSpec] = None,
) -> Optional[str]:
    """``base`` + ``template`` with every placeholder filled by a
    percent-encoded id (`encode_id`, with `spec`'s kept characters) — or None
    when anything is missing or the result is not exactly an https URL on
    ``base``'s host with no query / fragment and no '.' / '..' segment."""
    if not base:
        return None
    keep = {k.placeholder: k for k in (spec.keep_unencoded if spec is not None else ())}
    filled = template
    for name in _PLACEHOLDER_RE.findall(template):
        vendor_id = _usable_id(ids.get(name))
        if name not in PLACEHOLDERS or vendor_id is None:
            return None
        encoded = encode_id(vendor_id, keep.get(name))
        if encoded is None:
            return None
        filled = filled.replace("{" + name + "}", encoded)
    if any(seg in (".", "..") for seg in filled.split("/")):
        return None
    url = base.rstrip("/") + filled
    try:
        parts = urlsplit(url)
        expected = urlsplit(base)
        if parts.port is not None:
            return None
    except ValueError:
        return None
    if (
        parts.scheme != "https"
        or parts.hostname != expected.hostname
        or parts.username or parts.password or "@" in parts.netloc
        or parts.query or parts.fragment
        or parts.path != filled
    ):
        return None
    return url


def build_links(
    instance_config: Mapping[str, Any],
    spec: VendorLinkSpec,
    ids: Mapping[str, Any],
    kinds: tuple[str, ...] = LINK_KINDS,
) -> list[VendorLink]:
    settings = effective_settings(instance_config, spec)
    out: list[VendorLink] = []
    for kind in kinds:
        if kind not in LINK_KINDS:
            continue
        url = build_url(settings.portal_base_url, settings.alert_path_template, ids,
                        spec=spec)
        if url:
            out.append(VendorLink(kind=kind, label=f"Open in {spec.portal_name}", url=url))
    return out
