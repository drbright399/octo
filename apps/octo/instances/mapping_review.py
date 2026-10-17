"""Tenant mappings made by a NAME — listed for a human to re-review.

The same-name fix (Phase 0 of the UniFi / entity-resolution build,
2026-10-01). Two businesses can share a name; a name is a SUGGESTION for a
human, never evidence. Until this release two paths mapped a vendor site to a
client by name alone, and their rows still route traffic:

  * the ingest path's auto-link (`tenant_autocreate`, match_source 'auto') —
    closed: the same name is now held in quarantine with a "map to <client>"
    suggestion;
  * the NextDNS panel's bulk "Use N suggestions" ('auto-name') — closed: a
    suggestion is confirmed row by row and saved as the operator's decision
    ('manual'); the mapping routes refuse a NEW non-manual row.

This module finds the rows that are left (`unconfirmed`), tells every admin+
operator once, in-app (`notify`: one `mapping_review` operator notice each,
migration 038), and gives the Integrations card its line (`card_warnings`).
A row stops being listed when an operator confirms it in the mapping panel
(saved 'manual') or re-maps it. `is_confirmed` is what later consumers (entity
resolution's site links) read: anything but 'manual' is unconfirmed.

Not listed: the mapping an instance wrote for a tenant it AUTO-CREATED from
that very site (origin 'auto', created by the same instance) — that tenant IS
the site, and it is pending review under Settings → Tenants already; rows of a
disabled instance (no traffic); rows frozen to a tenant that left (they route
to quarantine, never to a client).

Once per mapping: the mappings already noticed are remembered in
`bundle_config` ('mapping_review_noticed'), so a restart never repeats a
notice and a newly found unconfirmed mapping raises a new one. Fail-soft:
`notify` never raises (a startup hook calls it).
"""
from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
from dataclasses import dataclass
from typing import Any, Iterable, Optional

from apps.octo import paths
from apps.octo.db import connect, transaction
from apps.octo.ingest.timestamps import utcnow_iso

logger = logging.getLogger(__name__)

NOTICE_KIND = "mapping_review"
NOTICED_KEY = "mapping_review_noticed"
# Bounds: the remembered keys, and the rows one notice body lists.
MAX_REMEMBERED = 10_000
MAX_LISTED = 12
_SOURCE_WORDS = {
    "auto": "linked automatically by name",
    "auto-name": "accepted from a name suggestion in bulk",
    "auto-domain": "matched by domain",
    "directory": "matched from a directory",
}


@dataclass(frozen=True)
class UnconfirmedMapping:
    instance_id: int
    vendor_slug: str
    instance_name: str
    vendor_tenant_id: str
    vendor_tenant_label: Optional[str]
    client_slug: str
    client_name: str
    match_source: str

    @property
    def key(self) -> str:
        return "|".join((str(self.instance_id), self.vendor_tenant_id, self.client_slug,
                         self.match_source))


def is_confirmed(match_source: Optional[str]) -> bool:
    """A mapping a PERSON made or confirmed. Everything else (a name match,
    a bulk-accepted suggestion, a future directory matcher) is unconfirmed:
    it may route traffic, but nothing may treat it as evidence."""
    return match_source == "manual"


def unconfirmed(
    conn: Optional[sqlite3.Connection] = None, *, instance_id: Optional[int] = None,
) -> list[UnconfirmedMapping]:
    """Every mapping still to re-review (see the module docstring), oldest
    instance first. [] on a registry without the tables."""
    own = conn is None
    reg = conn or connect(paths.registry_db_path(), read_only=True)
    try:
        where = ("m.match_source <> 'manual' AND i.disabled_at IS NULL "
                 "AND c.status = 'active' "
                 "AND NOT (c.origin = 'auto' AND c.created_by_instance_id = m.adapter_instance_id)")
        args: list[Any] = []
        if instance_id is not None:
            where += " AND m.adapter_instance_id = ?"
            args.append(int(instance_id))
        try:
            rows = reg.execute(
                "SELECT m.adapter_instance_id, i.vendor_slug, i.display_name, "
                " m.vendor_tenant_id, m.vendor_tenant_label, m.octo_client_slug, "
                " c.display_name, m.match_source "
                "FROM adapter_tenant_map m "
                "JOIN adapter_instances i ON i.id = m.adapter_instance_id "
                "JOIN clients c ON c.slug = m.octo_client_slug "
                f"WHERE {where} ORDER BY m.adapter_instance_id, m.vendor_tenant_id",
                args,
            ).fetchall()
        except sqlite3.OperationalError:
            return []
    finally:
        if own:
            reg.close()
    return [
        UnconfirmedMapping(int(r[0]), str(r[1]), str(r[2] or r[1]), str(r[3]),
                           r[4], str(r[5]), str(r[6] or r[5]), str(r[7]))
        for r in rows
    ]


def _line(m: UnconfirmedMapping) -> str:
    site = f"'{m.vendor_tenant_label}' ({m.vendor_tenant_id})" if m.vendor_tenant_label \
        else f"'{m.vendor_tenant_id}'"
    how = _SOURCE_WORDS.get(m.match_source, m.match_source)
    return f"{m.instance_name} #{m.instance_id}: {site} → {m.client_name} ({how})"


def notice_text(found: list[UnconfirmedMapping], total: int) -> tuple[str, str]:
    """(title, body) of one notice — plain text, bounded (≤ 2000 chars)."""
    n = len(found)
    title = (f"{n} tenant mapping{'s' if n != 1 else ''} made from a name match — "
             "please re-review")
    lines = [_line(m) for m in found[:MAX_LISTED]]
    more = n - len(lines)
    body = (
        "These vendor sites were mapped to a client by NAME alone, by an earlier "
        "version of Athena (or by accepting name suggestions in bulk) — not by a person. "
        "Two different businesses can share a name. Their traffic still "
        "routes there. Open each integration's Tenant mapping and confirm the row, or "
        "re-map it; until then Athena treats it as unconfirmed. "
        + "; ".join(lines)
        + (f"; and {more} more." if more > 0 else ".")
    )
    if total > n:
        body += f" ({total - n} mapping(s) listed in an earlier notice are still unconfirmed.)"
    if len(body) > 2000:
        body = body[:1999].rstrip() + "…"
    return title, body


def _noticed(conn: sqlite3.Connection) -> set[str]:
    try:
        row = conn.execute("SELECT value_json FROM bundle_config WHERE key = ?",
                           (NOTICED_KEY,)).fetchone()
    except sqlite3.OperationalError:
        return set()
    if row is None:
        return set()
    try:
        value = json.loads(row[0])
    except ValueError:
        return set()
    return {v for v in value if isinstance(v, str)} if isinstance(value, list) else set()


def _remember(conn: sqlite3.Connection, keys: Iterable[str]) -> None:
    value = sorted(set(keys))[-MAX_REMEMBERED:]
    conn.execute(
        "INSERT INTO bundle_config (key, value_json, description, updated_at) "
        "VALUES (?, ?, ?, ?) ON CONFLICT (key) DO UPDATE SET "
        "value_json = excluded.value_json, updated_at = excluded.updated_at",
        (NOTICED_KEY, json.dumps(value, separators=(",", ":")),
         "Tenant mappings made from a name match that admins were already told about "
         "(mapping_review notices).", utcnow_iso()),
    )


def notify() -> list[int]:
    """Raise one `mapping_review` notice per admin+ for the unconfirmed
    mappings no notice has listed yet. Returns the notice ids created ([]
    when there is nothing new). Never raises."""
    from apps.octo.auth import operator_notices

    try:
        reg = connect(paths.registry_db_path())
        try:
            with transaction(reg):
                current = unconfirmed(reg)
                noticed = _noticed(reg)
                new = [m for m in current if m.key not in noticed]
                if not new or not operator_notices.all_admins(reg):
                    # Nothing new — or nobody to tell yet (nothing is marked
                    # as told: the first admin hears of it at the next start).
                    return []
                title, body = notice_text(new, len(current))
                digest = hashlib.sha256(
                    "\n".join(sorted(m.key for m in new)).encode("utf-8")).hexdigest()[:24]
                ids = operator_notices.notify_admins_system(
                    reg, kind=NOTICE_KIND, title=title, body=body,
                    request_id=f"mapping-review:{digest}",
                )
                _remember(reg, noticed | {m.key for m in current})
        finally:
            reg.close()
    except Exception as exc:  # noqa: BLE001 — a reminder never stops the platform
        logger.warning("[mapping-review] notices not raised (%s)", type(exc).__name__)
        return []
    if ids:
        logger.info("[mapping-review] %d unconfirmed name-matched mapping(s) listed for "
                    "re-review (%d notice(s))", len(new), len(ids))
    return ids


def card_warnings(instance_id: Optional[int], vendor_display_name: str) -> list[str]:
    """The Integrations card's line; [] when every mapping is confirmed."""
    if instance_id is None:
        return []
    try:
        found = unconfirmed(instance_id=instance_id)
    except sqlite3.Error:
        return []
    if not found:
        return []
    n = len(found)
    return [
        f"{n} {vendor_display_name} tenant mapping{'s were' if n != 1 else ' was'} made from "
        "a name match, not by a person — two businesses can share a name. Open Tenant "
        "mapping and confirm each row (or re-map it); until then it is unconfirmed."
    ]
