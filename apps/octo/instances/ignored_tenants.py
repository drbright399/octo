"""Vendor tenants an admin chose to IGNORE (migration 037).

A NextDNS account lists every profile it can see — client sites, but also
personal and test profiles. None of them is polled until it is mapped; an
ignored one additionally stops being listed as "needs mapping" on the
integration card and in the mapping panel. Ignoring is a statement about
attention, never about data: an ignored profile is exactly as unpolled as an
unmapped one, and mapping it later is always possible (the save route
removes the ignore mark in the same write).

Generic by design (adapter instance + the vendor's tenant id, like the
tenant map), fail-soft on read: a registry without the table (pre-037)
reads as "nothing ignored".
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Iterable, Optional

from apps.octo import paths
from apps.octo.db import connect, transaction


@dataclass(frozen=True)
class IgnoredTenant:
    vendor_tenant_id: str
    vendor_tenant_label: Optional[str]
    ignored_at: str
    ignored_by_operator_id: Optional[int]


def get_ignored(instance_id: int) -> list[IgnoredTenant]:
    reg = connect(paths.registry_db_path(), read_only=True)
    reg.row_factory = sqlite3.Row
    try:
        rows = reg.execute(
            "SELECT vendor_tenant_id, vendor_tenant_label, ignored_at, ignored_by_operator_id "
            "FROM adapter_ignored_vendor_tenants WHERE adapter_instance_id = ? "
            "ORDER BY vendor_tenant_id",
            (int(instance_id),),
        ).fetchall()
    except sqlite3.OperationalError:
        return []
    finally:
        reg.close()
    return [
        IgnoredTenant(r["vendor_tenant_id"], r["vendor_tenant_label"], r["ignored_at"],
                      r["ignored_by_operator_id"])
        for r in rows
    ]


def ignored_ids(instance_id: int) -> set[str]:
    return {t.vendor_tenant_id for t in get_ignored(instance_id)}


def set_ignored(
    instance_id: int,
    entries: Iterable[tuple[str, Optional[str]]],
    *,
    operator_id: Optional[int] = None,
    conn: Optional[sqlite3.Connection] = None,
) -> int:
    """Replace the instance's ignore list with `entries` ((id, label) pairs).
    Rows that stay keep their original time and author. All-or-nothing.
    With `conn`, runs on the caller's open transaction instead."""
    wanted = {tid: label for tid, label in entries}

    def _apply(c: sqlite3.Connection) -> None:
        existing = {
            r[0] for r in c.execute(
                "SELECT vendor_tenant_id FROM adapter_ignored_vendor_tenants "
                "WHERE adapter_instance_id = ?", (int(instance_id),),
            ).fetchall()
        }
        for gone in existing - set(wanted):
            c.execute(
                "DELETE FROM adapter_ignored_vendor_tenants WHERE adapter_instance_id = ? "
                "AND vendor_tenant_id = ?", (int(instance_id), gone),
            )
        for tid, label in wanted.items():
            if tid in existing:
                c.execute(
                    "UPDATE adapter_ignored_vendor_tenants SET vendor_tenant_label = ? "
                    "WHERE adapter_instance_id = ? AND vendor_tenant_id = ?",
                    (label, int(instance_id), tid),
                )
            else:
                c.execute(
                    "INSERT INTO adapter_ignored_vendor_tenants (adapter_instance_id, "
                    " vendor_tenant_id, vendor_tenant_label, ignored_by_operator_id) "
                    "VALUES (?, ?, ?, ?)",
                    (int(instance_id), tid, label, operator_id),
                )

    if conn is not None:
        _apply(conn)
        return len(wanted)
    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            _apply(reg)
    finally:
        reg.close()
    return len(wanted)
