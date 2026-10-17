"""Mask an indicator (IOC) value for display outside the step-up gate.

IOC values are tenant data: the full value is only ever read through the
step-up-gated `/search/indicators`. Surfaces that sit OUTSIDE that gate (the
dashboard's threat-intel pulse) show a masked form that says what KIND of
thing was sighted without saying which one (owner decision 2026-09-28):

    ip       203.0.113.5            → 203.0.x.x
    ipv6     2001:db8::1            → 2001:db8:x:x:x:x:x:x
    cidr     198.51.100.0/24        → 198.51.x.x/24
    domain   example.test           → ex*****.test
    url      https://a.example/p?q  → https://a*****.example/…
    email    alice@example.test     → a***@ex*****.test
    hashes   <md5|sha1|sha256>      → first 8 characters + …
    cve      CVE-2026-0001          → CVE-2026-…
    other    anything               → *****

Masking happens server-side — the raw value never leaves the API on these
surfaces. Stars are a fixed run (never one per hidden character) so a mask
does not leak the value's length, and anything that does not parse as its
declared type falls back to the opaque mask rather than being echoed. An
IPv6 zone id ("fe80::1%eth0") names a local interface, not the host, and is
dropped. `mask_indicator` never raises: one odd stored value must not fail
the whole pulse.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

MASK = "*****"
_ELLIPSIS = "…"
_HASH_TYPES = frozenset({"md5", "sha1", "sha256"})
_HASH_PREFIX = 8
_MAX_TLD = 10
_HEX = re.compile(r"^[0-9a-fA-F]+$")
_CVE = re.compile(r"^CVE-(\d{4})-\d+$", re.IGNORECASE)


def mask_indicator(value: str | None, type_: str | None) -> str:
    """The display-safe form of one indicator value. Never returns `value`."""
    v = (value or "").strip()
    if not v:
        return MASK
    t = (type_ or "").strip().lower()
    try:
        masked = _mask_by_type(v, t)
    except Exception:  # noqa: BLE001 — an unforeseen parse never fails the caller
        return MASK
    # Belt and braces: a mask that could still contain the raw value (a very
    # short value, an odd parse) is replaced by the opaque one.
    if v in masked or v.lower() in masked.lower():
        return MASK
    return masked


def _mask_by_type(v: str, t: str) -> str:
    if t in ("ip", "ipv6"):
        return _mask_ip(v)
    if t == "cidr":
        return _mask_cidr(v)
    if t == "domain":
        return _mask_host(v)
    if t == "url":
        return _mask_url(v)
    if t == "email":
        return _mask_email(v)
    if t in _HASH_TYPES:
        return _mask_hash(v)
    if t == "cve":
        return _mask_cve(v)
    return MASK


def _mask_ip(v: str) -> str:
    try:
        ip = ipaddress.ip_address(v)
    except ValueError:
        return MASK
    if isinstance(ip, ipaddress.IPv4Address):
        a, b, _c, _d = str(ip).split(".")
        return f"{a}.{b}.x.x"
    # Rebuilt from its integer: drops a zone id ("2001:db8::1%eth0"), on
    # which `exploded` raises (Python 3.12).
    head = ipaddress.IPv6Address(int(ip)).exploded.split(":")[:2]
    return ":".join(h.lstrip("0") or "0" for h in head) + ":x" * 6


def _mask_cidr(v: str) -> str:
    addr, sep, prefix = v.partition("/")
    masked = _mask_ip(addr.strip())
    if masked == MASK:
        return MASK
    prefix = prefix.strip()
    return f"{masked}/{prefix}" if sep and prefix.isdigit() else masked


def _mask_host(v: str) -> str:
    host = v.strip().rstrip(".").lower()
    if not host or any(c.isspace() for c in host):
        return MASK
    labels = host.split(".")
    first = labels[0]
    # Keep at most two leading characters, and fewer for short labels so a
    # short name is not given away almost whole.
    keep = first[: min(2, len(first) // 3)]
    tld = labels[-1] if len(labels) > 1 else ""
    # The top-level label is kept only when it looks like one: an internal
    # or odd name's last label can be as telling as its first.
    if tld.isalpha() and len(tld) <= _MAX_TLD:
        return f"{keep}{MASK}.{tld}"
    return f"{keep}{MASK}"


def _mask_url(v: str) -> str:
    try:
        parts = urlsplit(v if "://" in v else f"//{v}")
        host = parts.hostname or ""
    except ValueError:
        return MASK
    if not host:
        return MASK
    try:
        # An IP-literal host is masked as an IP, not as a name.
        ipaddress.ip_address(host)
        masked_host = _mask_ip(host)
    except ValueError:
        masked_host = _mask_host(host)
    scheme = parts.scheme.lower()
    prefix = f"{scheme}://" if scheme.isalpha() else ""
    # Path, query, port and userinfo are never shown.
    return f"{prefix}{masked_host}/{_ELLIPSIS}"


def _mask_email(v: str) -> str:
    local, at, domain = v.rpartition("@")
    if not at or not local or not domain:
        return MASK
    keep = local[0] if len(local) >= 4 else ""
    return f"{keep}***@{_mask_host(domain)}"


def _mask_hash(v: str) -> str:
    if len(v) <= _HASH_PREFIX or not _HEX.match(v):
        return MASK
    return f"{v[:_HASH_PREFIX].lower()}{_ELLIPSIS}"


def _mask_cve(v: str) -> str:
    m = _CVE.match(v)
    if not m:
        return MASK
    return f"CVE-{m.group(1)}-{_ELLIPSIS}"
