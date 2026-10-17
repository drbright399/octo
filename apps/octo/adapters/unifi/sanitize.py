"""The UniFi ADAPTER BOUNDARY: nothing secret ever gets past it.

UniFi answers carry material that must never be stored, logged or shown:
every `x_*` field (the controller's convention for secrets: x_passphrase,
x_wireguard_private_key, x_ipsec_pre_shared_key, x_radius_secret …), the
`utm_token`, and in the legacy `rest/networkconf` answer VPN / RADIUS / Wi-Fi
keys under other names too (verified live 2026-10-01; the UniFi dump rule of
2026-09-28 — a site's WireGuard key leaked through an unstripped dump once).

`strip` is applied to EVERY vendor answer by the client before anything else
reads it (the boundary), recursively, and again by the poller on what it hands
on. It drops, at any depth:

  * a key starting with `x_` (any case);
  * a key whose name contains pass, psk, secret, token, key, credential,
    private, cert or auth_ (any case) — over-broad on purpose: a dropped
    harmless field costs nothing, a kept secret is an incident;
  * a string value that carries a PEM block or looks like a bare private key.

Fields the adapter needs are never caught (hostId, siteId, ipAddress,
macAddress, connectedAt, externalIp, ispInfo, timestamp, parameters …): the
test `test_needed_fields_survive` pins that list. The one needed name the
broad rule WOULD catch — the fleet's paging cursor `nextToken` — is an
explicit, exact exception (`SAFE_FIELDS`).

Bounded: depth, list length and string length are capped so a hostile or
broken answer cannot make the walk expensive.
"""
from __future__ import annotations

import re
from typing import Any

MAX_DEPTH = 12
MAX_LIST = 5_000
MAX_STRING = 4_096

_SECRET_KEY_RE = re.compile(
    r"(pass|psk|secret|token|key|credential|private|cert|auth_)", re.IGNORECASE,
)
_PEM_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*-----")
# A long base64 run with base64-only characters ('+', '/' or '=' padding) —
# the shape of a WireGuard / raw key. Hex ids (hostIds, event ids) have none
# of those, so they always pass.
_RAW_KEY_RE = re.compile(r"^(?=.*[+/=])[A-Za-z0-9+/]{40,}={0,2}$")


# Exact field names the broad rule would catch that are NOT secrets and that
# the adapter needs: the fleet endpoints' opaque paging cursor.
SAFE_FIELDS = frozenset({"nextToken"})


def secret_key(name: Any) -> bool:
    """True when a field NAME must never cross the boundary."""
    if not isinstance(name, str):
        return True
    if name in SAFE_FIELDS:
        return False
    low = name.strip().lower()
    return low.startswith("x_") or bool(_SECRET_KEY_RE.search(low))


def secret_value(value: Any) -> bool:
    """True when a string VALUE looks like key material whatever its field."""
    if not isinstance(value, str):
        return False
    return bool(_PEM_RE.search(value)) or bool(_RAW_KEY_RE.fullmatch(value.strip()))


def strip(value: Any, _depth: int = 0) -> Any:
    """A copy of `value` with every secret-looking field and value removed
    (see the module docstring). Non-JSON types become None."""
    if _depth > MAX_DEPTH:
        return None
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            if secret_key(k):
                continue
            if secret_value(v):
                continue
            out[str(k)] = strip(v, _depth + 1)
        return out
    if isinstance(value, list):
        return [strip(v, _depth + 1) for v in value[:MAX_LIST] if not secret_value(v)]
    if isinstance(value, str):
        return value[:MAX_STRING]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return None


def find_secret_keys(value: Any, _path: str = "", _depth: int = 0) -> list[str]:
    """Every path in `value` whose key or value `strip` would remove — what a
    test (or a store scan) asserts is EMPTY."""
    if _depth > MAX_DEPTH:
        return []
    hits: list[str] = []
    if isinstance(value, dict):
        for k, v in value.items():
            here = f"{_path}.{k}" if _path else str(k)
            if secret_key(k) or secret_value(v):
                hits.append(here)
                continue
            hits.extend(find_secret_keys(v, here, _depth + 1))
    elif isinstance(value, list):
        for i, v in enumerate(value[:MAX_LIST]):
            if secret_value(v):
                hits.append(f"{_path}[{i}]")
            else:
                hits.extend(find_secret_keys(v, f"{_path}[{i}]", _depth + 1))
    return hits
