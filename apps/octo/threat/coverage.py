"""P8 — honest coverage: per tenant, per rule, are the rule's mandatory
inputs CONFIGURED and FRESH? A gap reads "not covered: <rule> (<why>)" in
the drawer and the rule list — never Green-by-default.

  B6, R8   a person — always covered.
  R6       a buoy registered for the tenant that runs OpenCanary, with a
           fresh heartbeat, AND the canary scanner allowlist (N15) set up
           for the tenant (its precondition).
  R2-W     a Wazuh integration delivering into the tenant, whose last
           contact succeeded recently.
  FR2      intake health — always measured.
  B7       a NextDNS profile mapped to the tenant, the instance reached
           within the hour (v0.17.1).
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from apps.octo import paths
from apps.octo.db import connect
from apps.octo.threat import registry, rules
from apps.octo.threat.store import parse

BUOY_FRESH = timedelta(minutes=15)
WAZUH_FRESH = timedelta(minutes=30)
NEXTDNS_FRESH = timedelta(minutes=60)


@dataclass
class Coverage:
    rule_id: str
    covered: bool
    missing: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {"rule_id": self.rule_id, "covered": self.covered, "missing": list(self.missing)}


def _buoy(slug: str) -> Optional[dict[str, Any]]:
    try:
        reg = connect(paths.registry_db_path(), read_only=True)
        try:
            row = reg.execute("SELECT last_heartbeat_at, services_json FROM buoys WHERE slug = ?",
                              (slug,)).fetchone()
        finally:
            reg.close()
    except sqlite3.Error:
        return None
    return dict(row) if row else None


def _wazuh_ok(slug: str, now: datetime) -> tuple[bool, bool]:
    """(delivering into the tenant, fresh)."""
    from apps.octo.instances import tenant_map, vendor_contact
    from apps.octo.instances.manager import list_instances

    try:
        recs = [r for r in list_instances() if r.vendor_slug == "wazuh" and r.disabled_at is None]
    except sqlite3.Error:
        return False, False
    mapped = fresh = False
    for rec in recs:
        try:
            slugs = tenant_map.instance_tenant_slugs(rec)
        except sqlite3.Error:
            slugs = set()
        if slug not in slugs:
            continue
        mapped = True
        ok = parse(vendor_contact.snapshot(rec.id).get("last_ok_at"))
        fresh = fresh or (ok is not None and now - ok <= WAZUH_FRESH)
    return mapped, fresh


def tenant_coverage(slug: str, now: Optional[datetime] = None) -> dict[str, Coverage]:
    now = now or datetime.now(timezone.utc)
    out: dict[str, Coverage] = {}
    for r in rules.RULES.values():
        if r.kind == rules.HUMAN or r.id == "FR2":
            out[r.id] = Coverage(r.id, True)
    missing: list[str] = []
    buoy = _buoy(slug)
    if buoy is None:
        missing.append("no buoy at this client")
    else:
        try:
            services = json.loads(buoy.get("services_json") or "{}")
        except (TypeError, ValueError):
            services = {}
        if not isinstance(services, dict) or "opencanary" not in services:
            missing.append("the buoy does not run OpenCanary")
        hb = parse(buoy.get("last_heartbeat_at"))
        if hb is None or now - hb > BUOY_FRESH:
            missing.append("the buoy's heartbeat is stale")
    allow = registry.canary_allowlist(slug)
    if allow is None:
        missing.append("the canary scanner allowlist could not be read")
    elif not allow:
        missing.append("the canary scanner allowlist is not set up (N15 precondition)")
    out["R6"] = Coverage("R6", not missing, missing)
    mapped, fresh = _wazuh_ok(slug, now)
    w_missing = [] if mapped and fresh else \
        ["no Wazuh integration delivers into this client"] if not mapped else \
        ["Wazuh has not been reached recently"]
    out["R2-W"] = Coverage("R2-W", not w_missing, w_missing)
    mapped, fresh = _nextdns_ok(slug, now)
    n_missing = [] if mapped and fresh else \
        ["no NextDNS profile is mapped to this client"] if not mapped else \
        ["NextDNS has not been reached recently"]
    out["B7"] = Coverage("B7", not n_missing, n_missing)
    return {rid: out[rid] for rid in rules.RULES if rid in out}


def _nextdns_ok(slug: str, now: datetime) -> tuple[bool, bool]:
    """B7's input: (a NextDNS profile is mapped to the tenant, the instance
    was reached recently)."""
    from apps.octo.instances import tenant_map, vendor_contact
    from apps.octo.instances.manager import list_instances

    try:
        recs = [r for r in list_instances() if r.vendor_slug == "nextdns"
                and r.disabled_at is None]
    except sqlite3.Error:
        return False, False
    mapped = fresh = False
    for rec in recs:
        try:
            slugs = {m.octo_client_slug for m in tenant_map.get_mappings(rec.id)}
        except sqlite3.Error:
            slugs = set()
        if slug not in slugs:
            continue
        mapped = True
        ok = parse(vendor_contact.snapshot(rec.id).get("last_ok_at"))
        fresh = fresh or (ok is not None and now - ok <= NEXTDNS_FRESH)
    return mapped, fresh


def not_covered(slug: str, now: Optional[datetime] = None) -> list[str]:
    """"not covered: R6 (no buoy at this client)" lines."""
    return [f"not covered: {c.rule_id} ({'; '.join(c.missing)})"
            for c in tenant_coverage(slug, now).values() if not c.covered]
