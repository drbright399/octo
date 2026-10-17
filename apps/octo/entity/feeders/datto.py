"""The Datto inventory consumer — a mapped Datto site's device list becomes
THIS tenant's `inv_device` rows (`apps.octo.adapters.datto.feed`).

  * whole list: every device upserted (hostname, type, online, lastSeen, LAN
    IP, external IP, OS, domain — never a UDF: the adapter never reads one);
    a device that goes online gets `online_since` = this poll (sampled: the
    check only trusts a window Datto vouched for from its start); one that
    went offline clears it; a device missing from the whole list gets
    `missing_since`; the site's `datto.devices` watermark moves;
  * partial list (a failed or truncated read): the attempt only — nothing is
    marked missing or offline, the watermark stays (G7's rule for UniFi).

WHO (v0.17.2, Rick's decision D): the device list is kept for EVERY tenant
the site is mapped to (registry) — the Fleet's endpoint counts and the
alerts' device names read it — whatever the tenant's entity switch.
Identity LINKING stays gated exactly as before: only for a tenant switched
shadow / on are the NextDNS ↔ Datto device links re-evaluated after a list
(`linkrules.device_links`); the resolver and the checks read the rows only
for those tenants (the entity worker's own switch gate).

AUDITS (v0.17.3, Rick's decision A): `audit_due` names the devices of the
tenant's list (mapped sites, NOT missing) whose audit was never read or is
older than the poller's cut-off; `on_audit` keeps what the audit said —
serial, manufacturer, model and `audit_at` — on the device's EXISTING row
(an audit never creates a device; nothing else of the audit ever gets here).
A "no serial" answer is kept too (NULL + `audit_at`): the device is not asked
again until its audit is old.
"""
from __future__ import annotations

from typing import Any, Optional

from apps.octo.entity import intervals as iv
from apps.octo.entity import linkrules
from apps.octo.entity import normalize as nz
from apps.octo.entity import switch
from apps.octo.entity.db import TenantDB
from apps.octo.entity.feeders.mapping import mapped

VENDOR = "datto"


class DattoInventoryFeeder:
    def wants(self, slug: str) -> bool:
        """Every mapped tenant's list is kept (D); linking is gated below."""
        return True

    def audit_due(self, slug: str, instance_id: Any, site_uids: list[str], before: str,
                  limit: int, skip_types: tuple[str, ...] | list[str] = (),
                  ) -> list[tuple[str, str, Optional[str]]]:
        """(device uid, site uid, audit_at) of up to `limit` devices of THIS
        tenant's list — `instance_id`'s, on `site_uids` that are mapped to the
        tenant, not missing, whose device type (lower-case) is not in
        `skip_types` — whose audit was never read or was read before
        `before`: never audited first, then the oldest."""
        if not isinstance(instance_id, int) or limit <= 0:
            return []
        skip = sorted({str(t).lower() for t in skip_types}) or [""]
        sites = sorted({s for s in site_uids if isinstance(s, str)
                        and (m := mapped(VENDOR, s, slug)) is not None
                        and m.instance_id == instance_id})
        if not sites:
            return []
        with TenantDB.for_tenant(slug).connect() as conn:
            rows = conn.execute(
                f"SELECT device_uid, site_uid, audit_at FROM inv_device WHERE "
                f"adapter_instance_id = ? AND missing_since IS NULL AND site_uid IN "
                f"({','.join('?' * len(sites))}) AND (audit_at IS NULL OR audit_at < ?) "
                f"AND lower(COALESCE(device_type, '-')) NOT IN ({','.join('?' * len(skip))}) "
                f"ORDER BY audit_at IS NOT NULL, audit_at, device_uid LIMIT ?",
                (instance_id, *sites, before, *skip, int(limit))).fetchall()
        return [(str(r["device_uid"]), str(r["site_uid"]), r["audit_at"]) for r in rows]

    def on_audit(self, slug: str, snapshot: dict[str, Any]) -> bool:
        """Keep one device's audit (serial / manufacturer / model, cleaned by
        the adapter) on its existing row. True when a row took it."""
        site_uid, uid = snapshot.get("site_uid"), snapshot.get("device_uid")
        inst = snapshot.get("instance_id")
        if not isinstance(site_uid, str) or not isinstance(uid, str):
            return False
        m = mapped(VENDOR, site_uid, slug)
        if m is None or (isinstance(inst, int) and m.instance_id != inst):
            return False
        audited = nz.ts(snapshot.get("audited_at"))
        if not audited:
            return False

        def text(name: str, limit: int) -> Optional[str]:
            value = snapshot.get(name)
            return value[:limit] if isinstance(value, str) and value else None

        with TenantDB.for_tenant(slug).write() as conn:
            return conn.execute(
                "UPDATE inv_device SET serial = ?, manufacturer = ?, model = ?, audit_at = ? "
                "WHERE adapter_instance_id = ? AND device_uid = ?",
                (text("serial", 64), text("manufacturer", 80), text("model", 80), audited,
                 m.instance_id, uid[:128])).rowcount == 1

    def on_inventory(self, slug: str, site_uid: str, snapshot: dict[str, Any]) -> Optional[int]:
        m = mapped(VENDOR, site_uid, slug)
        inst = snapshot.get("instance_id")
        if m is None or (isinstance(inst, int) and m.instance_id != inst):
            return None
        polled = nz.ts(snapshot.get("polled_at"))
        if not polled:
            return None
        tdb = TenantDB.for_tenant(slug)
        with tdb.write() as conn:
            if not snapshot.get("complete"):
                iv.watermark_failed(conn, "datto.devices", site_uid, polled,
                                    "device list not read whole")
                return 0
            seen: set[str] = set()
            for d in snapshot.get("devices") or []:
                if not isinstance(d, dict) or not isinstance(d.get("uid"), str):
                    continue
                uid = d["uid"][:128]
                seen.add(uid)
                online = d.get("online")
                online_i = 1 if online is True else 0 if online is False else None
                hostname = nz.hostname(d.get("hostname"))
                prior = conn.execute("SELECT online, online_since FROM inv_device WHERE "
                                     "adapter_instance_id = ? AND device_uid = ?",
                                     (m.instance_id, uid)).fetchone()
                if online_i == 1:
                    since = prior["online_since"] if prior is not None and prior["online"] == 1 \
                        and prior["online_since"] else polled
                else:
                    since = None
                conn.execute(
                    "INSERT INTO inv_device (adapter_instance_id, device_uid, site_uid, hostname, "
                    " hostname_key, device_type, online, online_since, last_seen, int_ip, os, "
                    " domain, first_seen_at, updated_at, missing_since, ext_ip) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?) "
                    "ON CONFLICT (adapter_instance_id, device_uid) DO UPDATE SET "
                    " site_uid = excluded.site_uid, hostname = excluded.hostname, "
                    " hostname_key = excluded.hostname_key, device_type = excluded.device_type, "
                    " online = excluded.online, online_since = excluded.online_since, "
                    " last_seen = excluded.last_seen, int_ip = excluded.int_ip, os = excluded.os, "
                    " domain = excluded.domain, updated_at = excluded.updated_at, "
                    " missing_since = NULL, ext_ip = excluded.ext_ip",
                    (m.instance_id, uid, site_uid, hostname,
                     nz.name_key(hostname) if hostname else None,
                     str(d.get("device_type"))[:40] if d.get("device_type") else None,
                     online_i, since, nz.ts(d.get("last_seen")), nz.ip(d.get("int_ip")),
                     str(d.get("os"))[:120] if d.get("os") else None,
                     str(d.get("domain"))[:120] if d.get("domain") else None, polled, polled,
                     nz.ip(d.get("ext_ip"))))
            for r in conn.execute("SELECT device_uid FROM inv_device WHERE adapter_instance_id = ? "
                                  "AND site_uid = ? AND missing_since IS NULL",
                                  (m.instance_id, site_uid)).fetchall():
                if r["device_uid"] not in seen:
                    conn.execute("UPDATE inv_device SET missing_since = ?, online = NULL, "
                                 "online_since = NULL WHERE adapter_instance_id = ? AND "
                                 "device_uid = ?", (polled, m.instance_id, r["device_uid"]))
            iv.watermark_ok(conn, "datto.devices", site_uid, polled)
            if switch.enabled(slug):
                # Identity linking: only for a tenant in shadow / on.
                linkrules.device_links(conn, polled)
            return len(seen)
