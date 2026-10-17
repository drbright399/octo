"""Where a site is pinned — the manual SITE override (042), the manual
per-tenant fallback (041) and the UniFi console's own report.

PRECEDENCE (read time, `resolve`):
  1. the SITE's own override (admin+ sets it from the Fleet drawer, audited)
     — the way to correct a console that reports the wrong place, and to pin
     each site of a multi-site client on its own;
  2. the UniFi console's location (`/v1/hosts` reportedState.location —
     already read by the UniFi adapter): a single-site console, or a console
     with several sites that are ALL this tenant's;
  3. the TENANT override (041; admin+ from Settings → Tenants) — the
     fallback for a site with neither, and the pin of a tenant without UniFi;
  4. NO PIN (the site is listed, not mapped).
Athena does NO IP geolocation, and coordinates never leave the box (the map
tiles are self-hosted). An address lookup (`geocode.py`) only happens when an
operator presses Find; what is saved is the coordinate pair, LOCKED — never
re-looked-up, never moved by a console's report.

History: v0.14.1 (2026-10-02) briefly let the TENANT override beat the
console, because a console states away from its client could not be
corrected at all; the per-site override (042) is now that correction, so the
tenant override is a fallback again and cannot collapse a multi-site
client's sites onto one point.

A CONSOLE WITH SEVERAL SITES (a hosted / self-hosted controller, a console
with remote sites) reports where the CONSOLE is, not each site — the same
rule the poller applies to the console's WAN. Its location is used only when
every site on that console is this tenant's (one client's own console); a
console shared with another tenant (or an unmapped site) pins nobody there.

PROVENANCE (043). A site override records who set it (`set_by`) and how
(`origin`): 'manual' (the editor) or 'autotask' (an Autotask address an
operator CONFIRMED from a proposal — `apps.octo.proposals`). Precedence does
not look at it: a confirmed proposal is a hand-set pin like any other.

A coordinate pair of (0, 0), a NaN or an out-of-range value is "no
location" (the null island many systems report when unset).
"""
from __future__ import annotations

import math
import sqlite3
from dataclasses import dataclass
from typing import Any, Mapping, Optional

from apps.octo import paths
from apps.octo.db import connect, transaction

MAX_LABEL = 120
ORIGINS = ("manual", "autotask")


@dataclass(frozen=True)
class Location:
    lat: float
    lng: float
    label: str
    source: str              # 'site' (the site's override) | 'unifi' | 'manual' (tenant)
    origin: str = "manual"
    """A hand-set pin's provenance (043): 'manual' (typed / pasted / looked
    up in the editor) or 'autotask' (an Autotask address an operator
    confirmed from a proposal). Not part of `as_dict` — the API shows it as
    the site's `provenance`, to operators only."""
    set_by: Optional[int] = None
    set_at: Optional[str] = None

    def as_dict(self) -> dict[str, Any]:
        return {"lat": self.lat, "lng": self.lng, "label": self.label, "source": self.source}


class LocationError(ValueError):
    """Operator-safe text."""


def _coord(value: Any, bound: float) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    v = float(value)
    if math.isnan(v) or math.isinf(v) or abs(v) > bound:
        return None
    return v


def valid_pair(lat: Any, lng: Any) -> Optional[tuple[float, float]]:
    la, ln = _coord(lat, 90.0), _coord(lng, 180.0)
    if la is None or ln is None or (la == 0.0 and ln == 0.0):
        return None
    return la, ln


def clean_label(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    flat = " ".join("".join(c if c.isprintable() else " " for c in value).split())
    return flat[:MAX_LABEL]


def from_unifi(location: Optional[Mapping[str, Any]], fallback_label: str = "") -> \
        Optional[Location]:
    """The console's reported location (`{lat, long, radius, text}`), or None."""
    if not isinstance(location, Mapping):
        return None
    pair = valid_pair(location.get("lat"), location.get("long", location.get("lng")))
    if pair is None:
        return None
    label = clean_label(location.get("text")) or clean_label(fallback_label)
    return Location(round(pair[0], 6), round(pair[1], 6), label, "unifi")


def from_manual(manual: Optional[Mapping[str, Any]], fallback_label: str = "", *,
                source: str = "manual") -> Optional[Location]:
    """A hand-set location (a tenant override: source 'manual'; a site
    override: source 'site'), or None."""
    if not isinstance(manual, Mapping):
        return None
    pair = valid_pair(manual.get("lat"), manual.get("lng"))
    if pair is None:
        return None
    origin, set_by, set_at = manual.get("origin"), manual.get("set_by"), manual.get("set_at")
    return Location(round(pair[0], 6), round(pair[1], 6),
                    clean_label(manual.get("label")) or clean_label(fallback_label), source,
                    origin=origin if origin in ORIGINS else "manual",
                    set_by=set_by if isinstance(set_by, int) and not isinstance(set_by, bool)
                    else None,
                    set_at=set_at if isinstance(set_at, str) else None)


def resolve(unifi: Optional[Mapping[str, Any]], tenant: Optional[Mapping[str, Any]], *,
            site: Optional[Mapping[str, Any]] = None, fallback_label: str = "",
            console_sites: int = 1, console_shared: bool = False) -> Optional[Location]:
    """The site's override > the console's location (a single-site console,
    or a multi-site console that is this tenant's alone) > the tenant
    override > None (listed, not pinned)."""
    own = from_manual(site, fallback_label, source="site")
    if own is not None:
        return own
    console = from_unifi(unifi, fallback_label)
    if console is not None and not (console_sites > 1 and console_shared):
        return console
    return from_manual(tenant, fallback_label)


# ---------------------------------------------------------------------------
# The TENANT fallback (registry tenant_locations, 041)
# ---------------------------------------------------------------------------

def all_overrides(reg: Optional[sqlite3.Connection] = None) -> dict[str, dict[str, Any]]:
    """slug → {lat, lng, label, set_by, set_at}; {} before 041 / unreadable."""
    own = reg is None
    try:
        conn = reg if reg is not None else connect(paths.registry_db_path(), read_only=True)
    except (sqlite3.Error, FileNotFoundError):
        return {}
    try:
        rows = conn.execute(
            "SELECT slug, lat, lng, label, set_by, set_at FROM tenant_locations").fetchall()
    except sqlite3.Error:
        return {}
    finally:
        if own:
            conn.close()
    return {r[0]: {"lat": r[1], "lng": r[2], "label": r[3], "set_by": r[4], "set_at": r[5]}
            for r in rows}


def get(slug: str) -> Optional[dict[str, Any]]:
    return all_overrides().get(slug)


def validated(lat: Any, lng: Any, label: Any) -> tuple[float, float, str]:
    pair = valid_pair(lat, lng)
    if pair is None:
        raise LocationError("latitude must be within ±90 and longitude within ±180, "
                            "and (0, 0) is not a location")
    text = clean_label(label)
    if not text:
        raise LocationError("a label is required (e.g. \"Main office\")")
    return round(pair[0], 6), round(pair[1], 6), text


def set_override(slug: str, lat: float, lng: float, label: str, *, actor: int) -> None:
    """Write (or replace) the tenant's override. The caller validated and
    audited (BEFORE this write)."""
    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            reg.execute(
                "INSERT INTO tenant_locations (slug, lat, lng, label, set_by, set_at) "
                "VALUES (?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now')) "
                "ON CONFLICT (slug) DO UPDATE SET lat = excluded.lat, lng = excluded.lng, "
                "label = excluded.label, set_by = excluded.set_by, set_at = excluded.set_at",
                (slug, float(lat), float(lng), label, int(actor)))
    finally:
        reg.close()


def clear_override(slug: str) -> bool:
    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            cur = reg.execute("DELETE FROM tenant_locations WHERE slug = ?", (slug,))
            return cur.rowcount > 0
    finally:
        reg.close()


# ---------------------------------------------------------------------------
# The SITE override (registry site_locations, 042)
# ---------------------------------------------------------------------------

def all_site_overrides(reg: Optional[sqlite3.Connection] = None) -> dict[str, dict[str, Any]]:
    """site key → {tenant_slug, lat, lng, label, set_by, set_at, origin,
    proposal_id}; {} before 042 / unreadable. Before 043 (no provenance
    columns) every pin reads 'manual'."""
    own = reg is None
    try:
        conn = reg if reg is not None else connect(paths.registry_db_path(), read_only=True)
    except (sqlite3.Error, FileNotFoundError):
        return {}
    try:
        try:
            rows = conn.execute("SELECT site_key, tenant_slug, lat, lng, label, set_by, set_at, "
                                "origin, proposal_id FROM site_locations").fetchall()
        except sqlite3.OperationalError:
            rows = [(*r, "manual", None) for r in conn.execute(
                "SELECT site_key, tenant_slug, lat, lng, label, set_by, set_at "
                "FROM site_locations").fetchall()]
    except sqlite3.Error:
        return {}
    finally:
        if own:
            conn.close()
    return {r[0]: {"tenant_slug": r[1], "lat": r[2], "lng": r[3], "label": r[4],
                   "set_by": r[5], "set_at": r[6], "origin": r[7], "proposal_id": r[8]}
            for r in rows}


def site_override_for(overrides: Mapping[str, Mapping[str, Any]], key: str,
                      slug: str) -> Optional[Mapping[str, Any]]:
    """The site's override if it was set for THIS tenant — a site re-mapped
    to another tenant does not carry the old tenant's pin."""
    row = overrides.get(key)
    return row if row is not None and row.get("tenant_slug") == slug else None


def get_site(key: str, slug: str) -> Optional[dict[str, Any]]:
    row = site_override_for(all_site_overrides(), key, slug)
    return dict(row) if row is not None else None


def write_site_override(conn: sqlite3.Connection, key: str, slug: str, lat: float,
                        lng: float, label: str, *, actor: int, origin: str = "manual",
                        proposal_id: Optional[int] = None) -> None:
    """The upsert itself, on the caller's connection and inside ITS
    transaction (a confirmed proposal writes the pin and its decision
    together). The provenance is the LAST writer's: a hand edit of a pin
    confirmed from Autotask is 'manual' again."""
    if origin not in ORIGINS:
        raise LocationError(f"unknown origin {origin!r}")
    conn.execute(
        "INSERT INTO site_locations (site_key, tenant_slug, lat, lng, label, set_by, set_at, "
        "origin, proposal_id) "
        "VALUES (?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?, ?) "
        "ON CONFLICT (site_key) DO UPDATE SET tenant_slug = excluded.tenant_slug, "
        "lat = excluded.lat, lng = excluded.lng, label = excluded.label, "
        "set_by = excluded.set_by, set_at = excluded.set_at, origin = excluded.origin, "
        "proposal_id = excluded.proposal_id",
        (key, slug, float(lat), float(lng), label, int(actor), origin, proposal_id))


def set_site_override(key: str, slug: str, lat: float, lng: float, label: str, *,
                      actor: int) -> None:
    """Write (or replace) the site's override by hand (origin 'manual'). The
    caller validated and audited (BEFORE this write)."""
    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            write_site_override(reg, key, slug, lat, lng, label, actor=actor)
    finally:
        reg.close()


def clear_site_override(key: str) -> bool:
    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            cur = reg.execute("DELETE FROM site_locations WHERE site_key = ?", (key,))
            return cur.rowcount > 0
    finally:
        reg.close()
