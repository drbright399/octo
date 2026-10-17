"""Normalisation — ONE place for every identifier entity resolution compares
(design 2.5). Feeders, the resolver and the API all go through here, so the
same value always compares equal.

  IP        canonical `ipaddress` form, IPv4-mapped IPv6 unwrapped; a class:
            public | rfc1918 | cgnat | link_local | loopback | doc | ula
  MAC       lower-case colon form; kind: global | random (locally
            administered bit) | virtual (hypervisor / container / VPN OUIs)
            — only GLOBAL MACs are tenant-wide keys
  hostname  first DNS label, trailing dot and DHCP suffix stripped,
            upper-cased; inner whitespace kept (NextDNS device names have
            spaces: "Alice's Laptop" stays one name)
  name key  a comparison key for names: case, accents and punctuation
            ignored (never a decision — names only ever suggest)
  time      canonical UTC milliseconds ('YYYY-MM-DDTHH:MM:SS.mmmZ'), the
            format every stored timestamp uses (they compare as strings)
"""
from __future__ import annotations

import ipaddress
import re
import unicodedata
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from apps.octo.ingest.timestamps import format_utc_ms, normalize_timestamp

_MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
# Hypervisor, container and VPN-adapter OUIs (design 2.5): never a key.
VIRTUAL_OUIS = ("00:15:5d", "00:50:56", "00:0c:29", "00:05:69", "08:00:27", "02:42",
                "00:1c:42", "00:16:3e", "0a:00:27", "00:ff:")

_RFC1918 = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12",
                                                   "192.168.0.0/16"))
_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_DOC = tuple(ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24",
                                               "203.0.113.0/24", "2001:db8::/32"))


def ip(value: Any) -> Optional[str]:
    """Canonical IP text, or None."""
    if not isinstance(value, str):
        return None
    text = value.strip().split("%")[0]
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return str(addr)


def ip_class(value: Optional[str]) -> str:
    """public | rfc1918 | cgnat | link_local | loopback | ula | doc | invalid.
    Documentation ranges are told apart explicitly: tests use them as
    stand-ins for PUBLIC addresses (an egress), so `doc` counts as public
    for every rule (`is_public`)."""
    if not value:
        return "invalid"
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return "invalid"
    if addr.is_loopback:
        return "loopback"
    if addr.version == 4:
        if any(addr in n for n in _RFC1918):
            return "rfc1918"
        if addr in _CGNAT:
            return "cgnat"
        if addr.is_link_local:
            return "link_local"
        if any(addr in n for n in _DOC):
            return "doc"
        return "public"
    if addr.is_link_local:
        return "link_local"
    if addr in ipaddress.ip_network("fc00::/7"):
        return "ula"
    if any(addr.version == n.version and addr in n for n in _DOC):
        return "doc"
    return "public"


def is_public(value: Optional[str]) -> bool:
    return ip_class(value) in ("public", "doc")


def is_lan(value: Optional[str]) -> bool:
    return ip_class(value) in ("rfc1918", "link_local", "ula", "cgnat")


def mac(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    text = value.strip().lower().replace("-", ":")
    if re.fullmatch(r"[0-9a-f]{12}", text):
        text = ":".join(text[i:i + 2] for i in range(0, 12, 2))
    return text if _MAC_RE.fullmatch(text) else None


def mac_kind(value: Optional[str]) -> str:
    """global | random | virtual | none."""
    if not value:
        return "none"
    if any(value.startswith(o) for o in VIRTUAL_OUIS):
        return "virtual"
    try:
        first = int(value[:2], 16)
    except ValueError:
        return "none"
    return "random" if first & 0x02 else "global"


def hostname(value: Any) -> Optional[str]:
    """First DNS label, trailing dot / DHCP suffix stripped, upper-cased."""
    if not isinstance(value, str):
        return None
    text = " ".join("".join(c if c.isprintable() else " " for c in value).split())
    text = text.rstrip(".")
    if not text:
        return None
    if " " not in text and "." in text:
        text = text.split(".", 1)[0]
    return text.upper()[:128] or None


def name_key(value: Any) -> Optional[str]:
    """A comparison key for a device / site name: case, accents and
    punctuation ignored. Two names with the same key are only ever a
    SUGGESTION."""
    if not isinstance(value, str):
        return None
    text = unicodedata.normalize("NFKD", value)
    text = "".join(c for c in text if not unicodedata.combining(c))
    text = re.sub(r"[^0-9a-z]+", " ", text.lower()).strip()
    return text[:128] or None


# ---------------------------------------------------------------------------
# Time
# ---------------------------------------------------------------------------

def ts(value: Any) -> Optional[str]:
    """Any vendor timestamp → canonical UTC ms text, or None."""
    if isinstance(value, datetime):
        return format_utc_ms(value)
    text = normalize_timestamp(value, allow_epoch=True, naive_is_utc=True)
    return text or None


def dt(value: Any) -> Optional[datetime]:
    text = ts(value)
    if not text:
        return None
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


def iso(value: datetime) -> str:
    return format_utc_ms(value)


def shift(value: str, seconds: float) -> str:
    base = dt(value)
    assert base is not None, value
    return format_utc_ms(base + timedelta(seconds=seconds))


def seconds_between(a: str, b: str) -> float:
    da, db = dt(a), dt(b)
    assert da is not None and db is not None, (a, b)
    return (db - da).total_seconds()


def midpoint(a: str, b: str) -> str:
    da, db = dt(a), dt(b)
    assert da is not None and db is not None, (a, b)
    return format_utc_ms(da + (db - da) / 2)


def day_start(value: str) -> str:
    return value[:10] + "T00:00:00.000Z"


def hour_start(value: str) -> str:
    return value[:13] + ":00:00.000Z"
