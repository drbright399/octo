"""Generic per-instance tenant map — vendor tenant id → OCTO client slug.

The cross-source client-identity store (migration 030). Each adapter's
``route_to_tenant()`` returns a VENDOR tenant id (Datto siteUid, Wazuh agent
group, RocketCyber customerId, …); this module resolves it to the canonical
OCTO client slug for that adapter instance, so events from every source land
under one client. Operator-declared today; the master-directory auto-matcher
(Autotask Companies / IT Glue Organizations) will pre-fill it later.

``MappingIngestSink`` wraps the real sink so pollers route through the map with
no per-poller change: the poller still calls ``ingest(vendor_id, source, event)``
and the wrapper swaps ``vendor_id`` for the mapped slug before persisting.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from dataclasses import dataclass
from typing import Any, Optional

from apps.octo import paths
from apps.octo.db import connect, transaction
from apps.octo.ingest import IngestSink
from apps.octo.instances import freshness

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class TenantMapping:
    vendor_tenant_id: str
    octo_client_slug: str
    vendor_tenant_label: Optional[str] = None
    match_source: str = "manual"


def get_mappings(adapter_instance_id: int) -> list[TenantMapping]:
    reg = connect(paths.registry_db_path())
    reg.row_factory = sqlite3.Row
    try:
        rows = reg.execute(
            "SELECT vendor_tenant_id, octo_client_slug, vendor_tenant_label, "
            "match_source FROM adapter_tenant_map "
            "WHERE adapter_instance_id = ? ORDER BY vendor_tenant_id",
            (adapter_instance_id,),
        ).fetchall()
    finally:
        reg.close()
    return [
        TenantMapping(
            vendor_tenant_id=r["vendor_tenant_id"],
            octo_client_slug=r["octo_client_slug"],
            vendor_tenant_label=r["vendor_tenant_label"],
            match_source=r["match_source"],
        )
        for r in rows
    ]


def resolve(adapter_instance_id: int | None, vendor_tenant_id: str | None) -> str | None:
    """Resolve one vendor tenant id → OCTO client slug, or None if unmapped.

    Returns None (treated as "no mapping, pass the id through") when there's no
    instance id, no vendor id, or the table isn't present yet (migration 030 not
    applied) — so this never breaks ingest if mappings simply aren't configured.
    """
    if adapter_instance_id is None or not vendor_tenant_id:
        return None
    reg = connect(paths.registry_db_path())
    try:
        row = reg.execute(
            "SELECT octo_client_slug FROM adapter_tenant_map "
            "WHERE adapter_instance_id = ? AND vendor_tenant_id = ?",
            (adapter_instance_id, vendor_tenant_id),
        ).fetchone()
    except sqlite3.OperationalError:
        return None
    finally:
        reg.close()
    return row[0] if row else None


def set_mappings(
    adapter_instance_id: int,
    mappings: list[TenantMapping],
    *,
    operator_id: int | None = None,
) -> int:
    """Bulk-replace all mappings for an instance. Returns the row count written.

    All-or-nothing: connections are autocommit, so without the explicit
    transaction a failure on the Nth INSERT left the old mappings deleted and
    a partial new set committed — sites silently unmapped, their alerts
    dropped. BEGIN IMMEDIATE also serializes two admins saving at once."""
    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            reg.execute(
                "DELETE FROM adapter_tenant_map WHERE adapter_instance_id = ?",
                (adapter_instance_id,),
            )
            for m in mappings:
                reg.execute(
                    "INSERT INTO adapter_tenant_map "
                    "(adapter_instance_id, vendor_tenant_id, octo_client_slug, "
                    " vendor_tenant_label, match_source, updated_by_operator_id) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        adapter_instance_id,
                        m.vendor_tenant_id,
                        m.octo_client_slug,
                        m.vendor_tenant_label,
                        m.match_source,
                        operator_id,
                    ),
                )
    finally:
        reg.close()
    return len(mappings)


def instance_tenant_slugs(record: Any) -> set[str]:
    """Every client slug an adapter instance can deliver into: its tenant
    map, its default tenant, the tenants it auto-created, and the older
    per-adapter maps (UniFi's `site_to_tenant` config, Autotask's company
    map). Scopes an MSP-wide instance row to a caller who may only read
    some tenants. Tables a registry lacks are skipped, never an error."""
    slugs: set[str] = set()
    if getattr(record, "default_tenant_slug", None):
        slugs.add(record.default_tenant_slug)
    config = getattr(record, "instance_config", None) or {}
    site_map = config.get("site_to_tenant") if isinstance(config, dict) else None
    if isinstance(site_map, str):
        try:
            site_map = json.loads(site_map)
        except ValueError:
            site_map = None
    if isinstance(site_map, dict):
        slugs.update(v for v in site_map.values() if isinstance(v, str) and v)
    queries = (
        "SELECT octo_client_slug FROM adapter_tenant_map WHERE adapter_instance_id = ?",
        "SELECT slug FROM clients WHERE created_by_instance_id = ?",
        "SELECT tenant_slug FROM autotask_tenant_company_map WHERE adapter_instance_id = ?",
    )
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        for sql in queries:
            try:
                slugs.update(r[0] for r in reg.execute(sql, (record.id,)).fetchall() if r[0])
            except sqlite3.OperationalError:
                continue
    finally:
        reg.close()
    return slugs


class MappingIngestSink:
    """Wraps an ``IngestSink``, resolving a vendor tenant id → OCTO client slug
    via this instance's tenant map before delegating.

    Unmapped ids pass through unchanged, so an already-resolved slug (e.g. the
    instance default the poller falls back to) still ingests correctly; an
    unmapped vendor id passes through and the underlying sink raises
    FileNotFoundError. Pollers that know their instance id no longer rely on
    that: they resolve through ``instances.tenant_autocreate.deliver`` (map →
    same-name suggestion (held) → auto-create → quarantine) and hand the
    resolved slug to ``inner`` directly.
    """

    def __init__(self, inner: IngestSink, adapter_instance_id: int | None) -> None:
        self._inner = inner
        self._instance_id = adapter_instance_id

    @property
    def inner(self) -> IngestSink:
        """The wrapped sink, for callers that already resolved the slug."""
        return self._inner

    def ingest(self, tenant_slug: str, source: str, event: Any) -> Any:
        slug = tenant_slug
        if self._instance_id is not None:
            mapped = resolve(self._instance_id, tenant_slug)
            if mapped:
                slug = mapped
        # Hand back the inner sink's outcome so pollers can tell a stored
        # event from an idempotent replay.
        outcome = self._inner.ingest(slug, source, event)
        if not getattr(outcome, "duplicate", False):
            # Receive-clock freshness for the source-health view (debounced
            # registry write; never raises). A replay is not news.
            freshness.record_event(instance_id=self._instance_id, slug=slug)
        return outcome
