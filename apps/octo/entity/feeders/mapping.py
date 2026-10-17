"""Which adapter instance maps a vendor scope to THIS tenant — read from the
registry's tenant map on every feed call (fail closed). A feed call for a
scope that is not mapped to the tenant it names writes NOTHING (invariant
I10: an unmapped or ignored site writes nothing; there is no default tenant).
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Optional

from apps.octo import paths
from apps.octo.db import connect


@dataclass(frozen=True)
class Mapped:
    instance_id: int
    match_source: str
    label: Optional[str]


def mapped(vendor: str, scope_id: str, slug: str) -> Optional[Mapped]:
    """The (instance, match source) that maps `scope_id` of `vendor` to
    `slug`, an ACTIVE tenant; None otherwise."""
    try:
        reg = connect(paths.registry_db_path(), read_only=True)
    except (sqlite3.Error, FileNotFoundError):
        return None
    try:
        row = reg.execute(
            "SELECT m.adapter_instance_id, m.match_source, m.vendor_tenant_label "
            "FROM adapter_tenant_map m JOIN adapter_instances i ON i.id = m.adapter_instance_id "
            "JOIN clients c ON c.slug = m.octo_client_slug "
            "WHERE i.vendor_slug = ? AND m.vendor_tenant_id = ? AND m.octo_client_slug = ? "
            "AND c.status = 'active' AND i.disabled_at IS NULL ORDER BY m.adapter_instance_id "
            "LIMIT 1", (vendor, scope_id, slug)).fetchone()
    except sqlite3.Error:
        return None
    finally:
        reg.close()
    if row is None:
        return None
    return Mapped(int(row[0]), str(row[1] or "manual"), row[2])


def mapped_scopes(vendor: str, slug: str) -> Optional[list[tuple[int, str, str, Optional[str]]]]:
    """Every (instance, scope, match source, label) of `vendor` mapped to
    `slug`. [] = really nothing mapped; None = the registry could not be read
    (missing, locked, corrupt) — callers then change NOTHING: a read fault is
    never "everything was unmapped"."""
    try:
        reg = connect(paths.registry_db_path(), read_only=True)
    except (sqlite3.Error, FileNotFoundError, OSError):
        return None
    try:
        rows = reg.execute(
            "SELECT m.adapter_instance_id, m.vendor_tenant_id, m.match_source, "
            "m.vendor_tenant_label FROM adapter_tenant_map m "
            "JOIN adapter_instances i ON i.id = m.adapter_instance_id "
            "WHERE i.vendor_slug = ? AND m.octo_client_slug = ? AND i.disabled_at IS NULL "
            "ORDER BY m.adapter_instance_id, m.vendor_tenant_id", (vendor, slug)).fetchall()
    except sqlite3.Error:
        return None
    finally:
        reg.close()
    return [(int(r[0]), str(r[1]), str(r[2] or "manual"), r[3]) for r in rows]
