"""The NextDNS feed consumer — device presence per hour and per-IP volume per
day become THIS tenant's lookups (`apps.octo.adapters.nextdns.feed`), and the
device-silence check runs on every presence hour.

Each call carries ONE tenant slug and ONE profile id; the profile must be
mapped to that tenant (registry) and the tenant's switch shadow / on — else
nothing is read or written (and the poller makes no call for it: `wants`).

Per-IP volume: only addresses that are an egress of THIS tenant on that day
are stored (with their counts); every other public address — a laptop at
home, a hotel — is only counted (design 2.4: never written into entities.db).

The SEED: when a profile's feed starts, the 14 UTC days before today are read
once each (analytics/devices per day): every device the app reported in that
fortnight gets its row and per-day counts — so a PC whose NextDNS app was
ALREADY dead when the client was switched on is known, linked to its Datto
device and watched (the 09-19..09-29 failure: the app dead on all 4 PCs).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from apps.octo.entity import checks, linkrules
from apps.octo.entity import intervals as iv
from apps.octo.entity import normalize as nz
from apps.octo.entity import switch
from apps.octo.entity.db import TenantDB
from apps.octo.entity.feeders.mapping import mapped

VENDOR = "nextdns"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class NextDNSDeviceFeeder:
    def __init__(self, *, now: Callable[[], datetime] = _utcnow,
                 silent_hours: int = checks.SILENT_HOURS) -> None:
        self._now = now
        self.silent_hours = silent_hours

    def wants(self, slug: str) -> bool:
        return switch.enabled(slug)

    def _target(self, slug: str, profile_id: str) -> Optional[TenantDB]:
        if not switch.enabled(slug) or mapped(VENDOR, profile_id, slug) is None:
            return None
        return TenantDB.for_tenant(slug)

    def hours_needed(self, slug: str, profile_id: str, hours: list[str]) -> list[str]:
        tdb = self._target(slug, profile_id)
        if tdb is None:
            return []
        keys = {h: nz.hour_start(nz.ts(h) or "") for h in hours if nz.ts(h)}
        with tdb.read() as conn:
            if conn is None:
                return list(keys)
            have = {r[0] for r in conn.execute(
                f"SELECT hour FROM ndns_presence_hour WHERE profile_id = ? AND hour IN "
                f"({','.join('?' * len(keys))})", (profile_id, *keys.values())).fetchall()} \
                if keys else set()
        return [h for h, k in keys.items() if k not in have]

    def on_device_hour(self, slug: str, profile_id: str, data: dict[str, Any]) -> None:
        tdb = self._target(slug, profile_id)
        hour = nz.ts(data.get("hour"))
        if tdb is None or not hour:
            return
        hour = nz.hour_start(hour)
        read_at = nz.ts(data.get("read_at")) or nz.iso(self._now())
        devices = [d for d in (data.get("devices") or []) if isinstance(d, dict)]
        with tdb.write() as conn:
            for d in devices:
                did = str(d.get("id") or "")[:64]
                if not did:
                    continue
                name = str(d.get("name"))[:120] if d.get("name") else None
                queries = d.get("queries") if isinstance(d.get("queries"), int) else 0
                local_ip = nz.ip(d.get("local_ip")) if d.get("local_ip") else None
                conn.execute(
                    "INSERT INTO ndns_device (profile_id, device_id, name, name_key, model, client, "
                    " local_ip, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT (profile_id, device_id) DO UPDATE SET "
                    " name = COALESCE(excluded.name, name), "
                    " name_key = COALESCE(excluded.name_key, name_key), "
                    " model = COALESCE(excluded.model, model), "
                    " client = COALESCE(excluded.client, client), "
                    " local_ip = COALESCE(excluded.local_ip, local_ip), "
                    " last_seen = MAX(last_seen, excluded.last_seen)",
                    (profile_id, did, name, nz.name_key(nz.hostname(name)) if name else None,
                     str(d.get("model"))[:80] if d.get("model") else None,
                     str(d.get("client"))[:32] if d.get("client") else None, local_ip,
                     hour, hour))
                conn.execute(
                    "INSERT INTO ndns_device_hour (profile_id, device_id, hour, queries) "
                    "VALUES (?, ?, ?, ?) ON CONFLICT (profile_id, device_id, hour) DO UPDATE SET "
                    " queries = excluded.queries", (profile_id, did, hour, max(0, queries)))
            total = data.get("total") if isinstance(data.get("total"), int) else None
            conn.execute(
                "INSERT INTO ndns_presence_hour (profile_id, hour, complete, method, devices, "
                " total_queries, read_at) VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (profile_id, hour) DO UPDATE SET complete = excluded.complete, "
                " method = excluded.method, devices = excluded.devices, "
                " total_queries = excluded.total_queries, read_at = excluded.read_at",
                (profile_id, hour, 1 if data.get("complete") else 0,
                 "logs" if data.get("method") == "logs" else "analytics", len(devices), total,
                 read_at))
            linkrules.device_links(conn, read_at)
            checks.evaluate(conn, slug, mode=switch.mode(slug), now=read_at,
                            silent_hours=self.silent_hours)

    def seed_days_needed(self, slug: str, profile_id: str, days: list[str]) -> list[str]:
        """Which of `days` (YYYY-MM-DD) of the 14-day seed are not read yet."""
        tdb = self._target(slug, profile_id)
        if tdb is None:
            return []
        wanted = [d for d in days if isinstance(d, str) and len(d) == 10]
        with tdb.read() as conn:
            if conn is None:
                return wanted
            have = {r[0] for r in conn.execute(
                f"SELECT day FROM ndns_seed_day WHERE profile_id = ? AND day IN "
                f"({','.join('?' * len(wanted))})", (profile_id, *wanted)).fetchall()} \
                if wanted else set()
        return [d for d in wanted if d not in have]

    def on_device_day(self, slug: str, profile_id: str, data: dict[str, Any]) -> None:
        """One seed day: {day, devices[{id, name, model, local_ip, queries}],
        read_at}."""
        tdb = self._target(slug, profile_id)
        day = str(data.get("day") or "")[:10]
        if tdb is None or len(day) != 10 or not nz.ts(day + "T00:00:00Z"):
            return
        start = day + "T00:00:00.000Z"
        read_at = nz.ts(data.get("read_at")) or nz.iso(self._now())
        devices = [d for d in (data.get("devices") or []) if isinstance(d, dict)]
        with tdb.write() as conn:
            for d in devices:
                did = str(d.get("id") or "")[:64]
                queries = d.get("queries") if isinstance(d.get("queries"), int) else 0
                if not did or queries <= 0:
                    continue
                name = str(d.get("name"))[:120] if d.get("name") else None
                local_ip = nz.ip(d.get("local_ip")) if d.get("local_ip") else None
                conn.execute(
                    "INSERT INTO ndns_device (profile_id, device_id, name, name_key, model, client, "
                    " local_ip, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?) "
                    "ON CONFLICT (profile_id, device_id) DO UPDATE SET "
                    " name = COALESCE(name, excluded.name), "
                    " name_key = COALESCE(name_key, excluded.name_key), "
                    " model = COALESCE(model, excluded.model), "
                    " local_ip = COALESCE(local_ip, excluded.local_ip), "
                    " first_seen = MIN(first_seen, excluded.first_seen), "
                    " last_seen = MAX(last_seen, excluded.last_seen)",
                    (profile_id, did, name, nz.name_key(nz.hostname(name)) if name else None,
                     str(d.get("model"))[:80] if d.get("model") else None, local_ip,
                     start, start))
                conn.execute(
                    "INSERT INTO ndns_device_day (profile_id, device_id, day, queries) "
                    "VALUES (?, ?, ?, ?) ON CONFLICT (profile_id, device_id, day) DO UPDATE SET "
                    " queries = excluded.queries", (profile_id, did, day, queries))
            conn.execute(
                "INSERT INTO ndns_seed_day (profile_id, day, devices, read_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT (profile_id, day) DO UPDATE SET devices = excluded.devices, "
                " read_at = excluded.read_at", (profile_id, day, len(devices), read_at))
            linkrules.device_links(conn, read_at)
            checks.evaluate(conn, slug, mode=switch.mode(slug), now=read_at,
                            silent_hours=self.silent_hours)

    def day_needed(self, slug: str, profile_id: str, day: str) -> bool:
        tdb = self._target(slug, profile_id)
        if tdb is None:
            return False
        with tdb.read() as conn:
            if conn is None:
                return True
            return conn.execute("SELECT 1 FROM ndns_ip_day WHERE profile_id = ? AND day = ?",
                                (profile_id, day)).fetchone() is None

    def on_ip_day(self, slug: str, profile_id: str, data: dict[str, Any]) -> None:
        tdb = self._target(slug, profile_id)
        day = str(data.get("day") or "")[:10]
        if tdb is None or len(day) != 10:
            return
        read_at = nz.ts(data.get("read_at")) or nz.iso(self._now())
        with tdb.write() as conn:
            rows = conn.execute(
                "SELECT DISTINCT addr, prefix_len FROM lk_site_egress WHERE valid_from <= ? AND "
                "(valid_to IS NULL OR valid_to >= ?)",
                (day + "T23:59:59.999Z", day + "T00:00:00.000Z")).fetchall()
            egress = {r["addr"] for r in rows if int(r["prefix_len"]) in (32, 128)}
            # IPv6 delegated prefixes: a device's own IPv6 address inside one
            # is counted under the PREFIX (never stored one by one).
            prefixes = [r for r in rows if int(r["prefix_len"]) not in (32, 128)]
            counts: dict[str, int] = {}
            total = 0
            for item in data.get("ips") or []:
                if not isinstance(item, (list, tuple)) or len(item) != 2:
                    continue
                ip, q = nz.ip(str(item[0])), item[1]
                if not isinstance(q, int) or q < 0:
                    continue
                total += q
                if not ip:
                    continue
                if ip in egress:
                    key: Optional[str] = ip       # this tenant's own egress only
                else:
                    key = next((iv.egress_key(r) for r in prefixes
                                if iv.egress_contains(r, ip)), None)
                if key is not None:
                    counts[key] = counts.get(key, 0) + q
            kept: list[list[Any]] = [[k, v] for k, v in counts.items()]
            conn.execute(
                "INSERT INTO ndns_ip_day (profile_id, day, egress_queries, total_queries, "
                " egress_ips, read_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (profile_id, day) "
                "DO UPDATE SET egress_queries = excluded.egress_queries, "
                " total_queries = excluded.total_queries, egress_ips = excluded.egress_ips, "
                " read_at = excluded.read_at",
                (profile_id, day, sum(q for _ip, q in kept), total,
                 json.dumps(sorted(kept)), read_at))

    def pending_signals(self, slug: str) -> list[dict[str, Any]]:
        if switch.mode(slug) != "on":
            return []
        tdb = TenantDB.for_tenant(slug)
        with tdb.read() as conn:
            if conn is None:
                return []
            return checks.pending(conn)

    def signal_stored(self, slug: str, key: str, event_id: int) -> None:
        tdb = TenantDB.for_tenant(slug)
        with tdb.write() as conn:
            checks.stored(conn, key, event_id)
