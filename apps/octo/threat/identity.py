"""Canonical asset identity — how the threat code compares a device or a
network path WITHOUT trusting its spelling (the lockdown carve-out, an
incident's asset tags).

  host   the short host name, case-blind: `DISPATCH-01`, `dispatch-01`,
         `dispatch-01.example.local` and `CORP\\dispatch-01` are one host;
  net    an address or a network (a single address is a /32 or /128):
         `192.0.2.167` lies on a tagged `192.0.2.0/24`, `192.0.0.0/16`
         overlaps it.

A reference with neither in it — a vendor device id (a Datto deviceUid), free
text — has NO canonical identity (`None`): nothing in slice 1 resolves an id
into a host name, so a caller that must be safe treats it as "cannot be
checked", never as "not a match". An `ip:` prefix (R6's device reference) is
an address.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Optional, Union

Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

_HOST_RE = re.compile(r"^[a-z0-9_][a-z0-9_-]{0,62}$")
# A vendor device id (Datto deviceUid and the like): no host name in it.
_UID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


@dataclass(frozen=True)
class Identity:
    """('host', short name) or ('net', network)."""
    kind: str
    host: str = ""
    net: Optional[Network] = None


def canonical(ref: Any) -> Optional[Identity]:
    """`ref` → its canonical identity, or None (not comparable)."""
    text = str(ref or "").strip().lower().rstrip(".")
    if text.startswith("ip:"):
        text = text[3:].strip()
    if not text:
        return None
    try:
        return Identity("net", net=ipaddress.ip_network(text, strict=False))
    except ValueError:
        pass
    if "\\" in text:                                  # DOMAIN\host
        text = text.rsplit("\\", 1)[-1]
    if _UID_RE.match(text):
        return None
    short = text.split(".", 1)[0]
    return Identity("host", host=short) if _HOST_RE.match(short) else None


def network(ref: Any) -> Optional[Network]:
    """`ref` as an address / network, or None."""
    ident = canonical(ref)
    return ident.net if ident is not None and ident.kind == "net" else None


def same_host(a: Any, b: Any) -> bool:
    ia, ib = canonical(a), canonical(b)
    if ia is None or ib is None:
        return str(a or "").strip().lower() == str(b or "").strip().lower() != ""
    if ia.kind == ib.kind == "host":
        return ia.host == ib.host
    if ia.kind == ib.kind == "net":
        assert ia.net is not None and ib.net is not None
        return ia.net.version == ib.net.version and ia.net.overlaps(ib.net)
    return False
