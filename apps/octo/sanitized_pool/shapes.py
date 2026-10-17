"""M1 + M7 + M8 — Pattern-shape allowlist for the sanitized pool.

Every candidate pattern that the extractor wants to write into the
pool passes through `validate_pattern()`. Validates per-kind shape +
applies M8 URL canonicalization + rejects YARA (M7) per the safety
envelope. Anything that doesn't match an allowlisted shape is rejected
with a structured reason code that's safe to log.

The allowlist:

  - file_hash    md5 | sha1 | sha256, lowercase hex of the right length
  - ip           IPv4 or IPv6 string parsed by stdlib `ipaddress`,
                 rejecting RFC1918 / loopback / link-local / multicast
                 / reserved ranges that don't belong in an IOC pool
  - domain       DNS-style domain, ASCII or punycode-normalized IDN,
                 length-bounded, at least one dot
  - url          Canonicalized scheme + host + path, query/fragment
                 stripped, default-port removed (M8)
  - yara         ALWAYS REJECTED in v1 (M7 — DoS via compiler bombs;
                 must be super_admin curate-only when this lands)

Pure module — no external dependencies beyond stdlib + apps.octo.*. The
return type is a tagged union so callers know whether to write to
`patterns` (accept) or `sanitization_rejects` (reject) without having
to interpret a free-text status string.

This is the substrate the extractor depends on. The extractor itself
does NOT yet exist; this module is what gates it.
"""
from __future__ import annotations

import ipaddress
import re
import urllib.parse
from dataclasses import dataclass
from typing import Literal, Optional, Union


# ---------------------------------------------------------------------------
# Output types
# ---------------------------------------------------------------------------

# Tagged union — callers `match` on .kind to discriminate.

@dataclass(frozen=True)
class Accepted:
    """The candidate passed the allowlist. `canonical_value` is what
    should be stored in `patterns.ioc_value` (URL-canonicalized,
    IP-normalized, hex-lowercased, etc.). `kind` matches the
    `patterns.ioc_type` column.
    """
    kind: Literal["file_hash", "ip", "domain", "url"]
    canonical_value: str
    # Sub-kind detail for kinds that have variants:
    #   file_hash → "md5" / "sha1" / "sha256"
    #   ip        → "ipv4" / "ipv6"
    #   domain    → None
    #   url       → None
    subkind: Optional[str] = None


@dataclass(frozen=True)
class Rejected:
    """The candidate did not pass. `reason_code` is a stable string
    safe for logging + aggregation in `sanitization_rejects`.
    `raw_excerpt` should be the first ~200 chars of the input for
    forensic record (super_admin-only access per M3).
    """
    reason_code: str
    raw_excerpt: str


ValidationResult = Union[Accepted, Rejected]


# ---------------------------------------------------------------------------
# Reason codes (stable strings; downstream dashboards aggregate on these)
# ---------------------------------------------------------------------------

REASON_UNKNOWN_KIND = "unknown_kind"
REASON_EMPTY = "empty_input"
REASON_TOO_LONG = "input_too_long"
REASON_HASH_BAD_LENGTH = "hash_bad_length"
REASON_HASH_NOT_HEX = "hash_not_hex"
REASON_IP_INVALID = "ip_invalid"
REASON_IP_RESERVED = "ip_reserved_range"
REASON_DOMAIN_INVALID = "domain_invalid"
REASON_DOMAIN_NO_TLD = "domain_no_tld"
REASON_URL_INVALID = "url_invalid"
REASON_URL_NO_HOST = "url_no_host"
REASON_URL_SCHEME = "url_unsupported_scheme"
REASON_URL_INVALID_CHARS = "url_invalid_chars"
REASON_YARA_DEFERRED = "kind_yara_deferred_curated_only"


# Maximum length of any raw input we'll accept. Bounds DoS via giant
# input + bounds storage. Real IOCs comfortably fit in 4 KB; we'll
# bound at 8 KB to leave headroom.
MAX_INPUT_LEN = 8192

# Maximum length of the forensic excerpt we keep in
# `sanitization_rejects.raw_excerpt`. Long enough to identify the
# attack shape; short enough that the rejects log stays browseable.
EXCERPT_LEN = 200


def _excerpt(s: str) -> str:
    if len(s) <= EXCERPT_LEN:
        return s
    return s[:EXCERPT_LEN] + "…"


# ---------------------------------------------------------------------------
# Per-kind validators
# ---------------------------------------------------------------------------

# Hash hex-length per algorithm. NOT case-sensitive; lowercased before storage.
_HASH_LENGTHS = {
    "md5":    32,
    "sha1":   40,
    "sha256": 64,
}
_HEX_RE = re.compile(r"^[0-9a-f]+$")


def _validate_file_hash(value: str, sub: Optional[str]) -> ValidationResult:
    """File-hash IOC. `sub` is the algorithm (md5/sha1/sha256)."""
    if sub not in _HASH_LENGTHS:
        return Rejected(REASON_UNKNOWN_KIND, _excerpt(str(sub)))
    v = value.strip().lower()
    expected = _HASH_LENGTHS[sub]
    if len(v) != expected:
        return Rejected(REASON_HASH_BAD_LENGTH, _excerpt(value))
    if not _HEX_RE.fullmatch(v):
        return Rejected(REASON_HASH_NOT_HEX, _excerpt(value))
    return Accepted(kind="file_hash", canonical_value=v, subkind=sub)


def _validate_ip(value: str) -> ValidationResult:
    """IP IOC. Accepts IPv4 + IPv6. Rejects private / loopback /
    link-local / multicast / reserved — those don't belong in a global
    IOC pool (they're per-network locality, not attribution signals)."""
    v = value.strip()
    try:
        addr = ipaddress.ip_address(v)
    except ValueError:
        return Rejected(REASON_IP_INVALID, _excerpt(value))
    # Reject "doesn't belong in IOC pool" ranges.
    if (addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_multicast or addr.is_reserved or addr.is_unspecified):
        return Rejected(REASON_IP_RESERVED, _excerpt(value))
    sub = "ipv6" if addr.version == 6 else "ipv4"
    return Accepted(kind="ip", canonical_value=str(addr), subkind=sub)


# DNS domain label: 1-63 chars, alphanumerics + hyphens, no leading/trailing
# hyphen. Full domain bounded to 253 chars. Punycode (xn--) allowed.
_DOMAIN_LABEL_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$",
)
_DOMAIN_MAX = 253


def _validate_domain(value: str) -> ValidationResult:
    """Domain IOC. ASCII or punycode (IDN). Length-bounded."""
    v = value.strip().lower().rstrip(".")  # strip trailing dot
    if not v:
        return Rejected(REASON_EMPTY, _excerpt(value))
    if len(v) > _DOMAIN_MAX:
        return Rejected(REASON_TOO_LONG, _excerpt(value))
    labels = v.split(".")
    if len(labels) < 2:
        return Rejected(REASON_DOMAIN_NO_TLD, _excerpt(value))
    for label in labels:
        if not _DOMAIN_LABEL_RE.fullmatch(label):
            return Rejected(REASON_DOMAIN_INVALID, _excerpt(value))
    return Accepted(kind="domain", canonical_value=v, subkind=None)


# URL parsing.

_URL_ALLOWED_SCHEMES = ("http", "https")
_URL_DEFAULT_PORTS = {"http": 80, "https": 443}

# RFC 3986 unreserved + reserved + percent + a few we tolerate. Anything
# with a control char or chr < 0x20 is rejected (M8 / M1 — defense
# against URL-encoded prompt-injection escape sequences).
_URL_ILLEGAL_RE = re.compile(r"[\x00-\x1f\x7f]")


def _validate_url(value: str) -> ValidationResult:
    """URL IOC. Canonicalized per M8: lowercase scheme + host, default
    port stripped, query string + fragment stripped, control chars
    rejected. Only http(s) schemes accepted in v0.
    """
    v = value.strip()
    if not v:
        return Rejected(REASON_EMPTY, _excerpt(value))
    if _URL_ILLEGAL_RE.search(v):
        return Rejected(REASON_URL_INVALID_CHARS, _excerpt(value))
    try:
        parsed = urllib.parse.urlsplit(v)
    except ValueError:
        return Rejected(REASON_URL_INVALID, _excerpt(value))

    scheme = parsed.scheme.lower()
    if scheme not in _URL_ALLOWED_SCHEMES:
        return Rejected(REASON_URL_SCHEME, _excerpt(value))
    if not parsed.hostname:
        return Rejected(REASON_URL_NO_HOST, _excerpt(value))

    # Validate hostname as a domain — bounces back any garbage that
    # urlsplit happily accepts (e.g. "http://!!!/").
    host_check = _validate_domain(parsed.hostname)
    if isinstance(host_check, Rejected):
        return Rejected(REASON_URL_INVALID, _excerpt(value))

    host = parsed.hostname.lower()
    port = parsed.port
    # Strip default port for the canonical form.
    if port is not None and _URL_DEFAULT_PORTS.get(scheme) == port:
        port = None

    # Build the canonical netloc.
    if port is None:
        netloc = host
    else:
        netloc = f"{host}:{port}"

    # Path — keep as-is (case matters for some servers); drop empty.
    path = parsed.path or ""
    if not path.startswith("/"):
        path = "/" + path if path else ""

    canonical = urllib.parse.urlunsplit((scheme, netloc, path, "", ""))
    return Accepted(kind="url", canonical_value=canonical, subkind=None)


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------

# What `kind` values does the extractor pass in? These are the
# allowlisted kinds. Everything else → Rejected(REASON_UNKNOWN_KIND).
# YARA is in the dict but always rejects (M7).
SUPPORTED_KINDS = ("file_hash", "ip", "domain", "url")
REJECTED_KINDS = ("yara",)


def validate_pattern(
    kind: str,
    value: str,
    *,
    subkind: Optional[str] = None,
) -> ValidationResult:
    """Validate a candidate IOC pattern against the M1 allowlist.

    Parameters:
        kind     — the pattern kind ("file_hash", "ip", "domain",
                   "url"). YARA is rejected (M7).
        value    — the raw IOC string.
        subkind  — pattern-kind-specific detail. For "file_hash" this
                   is the algorithm ("md5", "sha1", "sha256").
                   Ignored for other kinds.

    Returns Accepted(...) with `canonical_value` to store, or
    Rejected(reason_code=..., raw_excerpt=...) safe to log.

    Length-bounds the input at MAX_INPUT_LEN before any per-kind
    validation runs — prevents DoS via huge inputs.
    """
    if not isinstance(kind, str):
        return Rejected(REASON_UNKNOWN_KIND, "")
    if not isinstance(value, str):
        return Rejected(REASON_EMPTY, "")

    k = kind.lower().strip()
    # YARA kind-check FIRST — before the length / empty / per-kind
    # validators. A YARA submission must always reject with the YARA-
    # specific reason code regardless of size; we never want a giant
    # YARA bomb to fall through to a generic "too long" classification
    # because that would mask the real attack class in the rejects log.
    if k == "yara":
        return Rejected(REASON_YARA_DEFERRED, _excerpt(value))

    if len(value) > MAX_INPUT_LEN:
        return Rejected(REASON_TOO_LONG, _excerpt(value))
    if not value or not value.strip():
        return Rejected(REASON_EMPTY, _excerpt(value))
    if k == "file_hash":
        return _validate_file_hash(value, subkind)
    if k == "ip":
        return _validate_ip(value)
    if k == "domain":
        return _validate_domain(value)
    if k == "url":
        return _validate_url(value)
    return Rejected(REASON_UNKNOWN_KIND, _excerpt(kind))
