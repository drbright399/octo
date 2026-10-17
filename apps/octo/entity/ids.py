"""Opaque ids: '<prefix>_' + a ULID (48-bit time + 80 random bits, Crockford
base32) — sortable by creation, never reused."""
from __future__ import annotations

import secrets
import time

_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def ulid(now_ms: int | None = None) -> str:
    t = int(time.time() * 1000) if now_ms is None else int(now_ms)
    value = (t << 80) | secrets.randbits(80)
    out = []
    for _ in range(26):
        out.append(_ALPHABET[value & 31])
        value >>= 5
    return "".join(reversed(out))


def new(prefix: str) -> str:
    return f"{prefix}_{ulid()}"
