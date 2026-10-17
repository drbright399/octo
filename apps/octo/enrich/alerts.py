"""Per-alert enrichment for the drawer's list (operators only) — LOCAL reads
and the enrichment CACHE only: nothing here contacts anything. A remote
address without a cached answer is queued for the background worker and
shown as `pending` (the raw text shows meanwhile).

  UniFi IPS  direction, action, signature, remote / local addresses, the
             remote's owner + PTR (+ forward-confirmed) + labels (scanner /
             vendor), the LOCAL device's name (the tenant's Datto device
             list by LAN address, else the name UniFi gave the client), and
             "N× in 24 h" for (remote, local, signature) from the coalescing
             ledger's per-remote split (`approximate` when part of it is not
             known — buckets written before 046).
  Datto RMM  `datto_summary.summarize` + "N repeats since <date>": the
             DISTINCT Datto alerts of the same device + monitor signature in
             Athena's own events of the last 30 days — keyed by the Datto
             DEVICE UID, never the host name — and WHICH device it is: its
             uid, Datto site, LAN / WAN address (the tenant's Datto device
             list) and, when other devices of the tenant carry the same host
             name, how many and at how many sites (two PCs named "Shared-PC"
             at two sites are two machines: a count by name would merge them).
             v0.17.3 (Rick's decision A): the device's manufacturer, model and
             SERIAL NUMBER from its Datto audit, and the serials of the OTHER
             devices with the same name when known ("this one SN X; the
             other: SN Y"). Operators only — this module feeds the analyst
             drawer alone; no client surface (the Fleet's layers, the sites
             list, an export) reads a serial. A tenant file not yet at 047
             (lazy migration) reads as "no serial", never an error.

TODO(v0.17.3) — "is the remote already in the site's firewall groups /
policies?" (C.1, optional; not cheap enough for this slice): the UniFi
connector client has no firewall read today. Design: one new read-only
connector call per site per day (`/proxy/network/integration/v1/sites/
{id}/firewall/...` — the path is NOT verified live yet), allowlisted fields
only (group name + member addresses / networks; every `x_` field stripped by
`sanitize.strip` as for every other UniFi read), kept in the tenant's
telemetry.db; the enrichment then answers `in_firewall_group: <name>` by a
membership test — never a vendor call on a page load.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Optional

from apps.octo import paths
from apps.octo.enrich import cache, datto_summary, labels, netintel, worker
from apps.octo.ingest.timestamps import format_utc_ms
from apps.octo.verdicts import keys

REPEAT_WINDOW = timedelta(hours=24)
DATTO_LOOKBACK = timedelta(days=30)
DATTO_SCAN = 5_000
# A Datto alert's device facts when its device is not in the list.
_NO_IDENTITY: dict[str, Any] = {"lan_ip": None, "wan_ip": None, "serial": None,
                                "manufacturer": None, "model": None}


def _m(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _clean(value: Any, limit: int = 120) -> Optional[str]:
    return netintel.clean(value, limit) or None


# ---------------------------------------------------------------------------
# The local device's name
# ---------------------------------------------------------------------------

def datto_names_by_ip(slug: str, ips: list[str], *,
                      exclude_sites: frozenset[str] = frozenset()) -> dict[str, str]:
    """LAN address → host name from the tenant's Datto device list — ONLY
    when exactly one device (not missing, not in `exclude_sites`) holds the
    address: two offices on the same factory-default /24, or a device that kept
    an address DHCP gave to another, make it ambiguous — then no Datto name
    (the caller falls back to the name UniFi gave the client), never a
    guess. Never a UDF: the list holds none. {} when unreadable."""
    from apps.octo.entity.db import EntityPathError, TenantDB

    wanted = sorted({i for i in ips if i})
    if not wanted:
        return {}
    try:
        with TenantDB.for_tenant(slug).read() as conn:
            if conn is None:
                return {}
            rows = conn.execute(
                f"SELECT int_ip, hostname, adapter_instance_id AS inst, device_uid, site_uid "
                f"FROM inv_device WHERE missing_since IS NULL AND hostname IS NOT NULL AND "
                f"int_ip IN ({','.join('?' * len(wanted))})", wanted).fetchall()
    except (sqlite3.Error, EntityPathError, ValueError):
        return {}
    held: dict[str, dict[tuple[Any, str], str]] = {}
    for r in rows:
        if str(r["site_uid"] or "") in exclude_sites:
            continue
        held.setdefault(str(r["int_ip"]), {})[(r["inst"], str(r["device_uid"]))] = \
            str(r["hostname"])
    return {ip: next(iter(devices.values())) for ip, devices in held.items()
            if len(devices) == 1}


class _OtherSites:
    """UniFi scope → the Datto sites linked to ANOTHER UniFi site of the
    tenant (their devices are not this site's: the Fleet's own rule) — only
    when the tenant's entity switch is ON (the links are used only then).
    Nothing excluded otherwise / when unreadable (then uniqueness across the
    tenant's whole device list decides)."""

    def __init__(self, slug: str) -> None:
        from apps.octo.fleet import sources

        self._mine: dict[str, set[str]] = {}
        self._every: frozenset[str] = frozenset()
        try:
            tenant = sources.tenants().get(slug)
        except sqlite3.Error:
            return
        if tenant is None or tenant.entity_mode != "on":
            return
        links = sources.entity_links(slug)
        self._mine = {scope: set(refs.get("datto", set())) for scope, refs in links.items()}
        self._every = frozenset(d for refs in self._mine.values() for d in refs)

    def of(self, scope: str) -> frozenset[str]:
        return frozenset(self._every - self._mine.get(scope, set()))


# ---------------------------------------------------------------------------
# Remote addresses
# ---------------------------------------------------------------------------

def remote_info(ips: list[str], *, queue: bool = True) -> dict[str, dict[str, Any]]:
    """ip → {ptr, ptr_confirmed, org, net_name, cidr, country, labels,
    pending, failed} from the cache; a miss is queued (when enrichment is
    on) and reads `pending`."""
    wanted = sorted({i for i in ips if netintel.enrichable(i)})
    held = cache.many(cache.IP, wanted)
    missing = [i for i in wanted if i not in held]
    if missing and queue:
        worker.enqueue(missing)
    out: dict[str, dict[str, Any]] = {}
    on = worker.enabled() and worker.current() is not None
    for ip in wanted:
        info = held.get(ip)
        if info is None:
            out[ip] = {"pending": on, "failed": False, "labels": labels.labels(ip, None)}
            continue
        if info.get("failed"):
            out[ip] = {"pending": False, "failed": True, "labels": labels.labels(ip, None)}
            continue
        out[ip] = {"ptr": _clean(info.get("ptr"), 253),
                   "ptr_confirmed": bool(info.get("ptr_confirmed")),
                   "org": _clean(info.get("org")), "net_name": _clean(info.get("net_name")),
                   "cidr": _clean(info.get("cidr"), 90), "country": _clean(info.get("country"), 8),
                   "pending": False, "failed": False, "labels": labels.labels(ip, info),
                   "as_of": info.get("fetched_at")}
    return out


# ---------------------------------------------------------------------------
# UniFi IPS
# ---------------------------------------------------------------------------

def _subject_parts(subject: str) -> tuple[str, str]:
    parts = (subject or "").split("|")
    return (parts[0] if parts else "?"), (parts[1] if len(parts) > 1 else "")


def unifi_ips(slug: str, rows: list[dict[str, Any]], buckets: dict[int, Any], *,
              now: datetime) -> dict[int, dict[str, Any]]:
    """{event id: enrichment} for the UniFi IPS alerts among `rows`."""
    from apps.octo.adapters.unifi import store as ustore

    ips_rows = [(r, keys.payload_of(r)) for r in rows
                if r.get("source") == "unifi" and keys.payload_of(r).get("kind") == "ips_threat"]
    if not ips_rows:
        return {}
    remotes = [str(_m(p.get("ips")).get("remote_ip") or "") for _r, p in ips_rows]
    info = remote_info([r for r in remotes if r])
    # The local device's Datto name, per UniFi site (a Datto site linked to
    # another of the tenant's sites never names a device here).
    other = _OtherSites(slug)
    by_scope: dict[str, list[str]] = {}
    for _r, p in ips_rows:
        local_ip = str(_m(p.get("ips")).get("local_ip") or "")
        if local_ip:
            by_scope.setdefault(str(p.get("scope") or ""), []).append(local_ip)
    names = {scope: datto_names_by_ip(slug, ips, exclude_sites=other.of(scope))
             for scope, ips in by_scope.items()}
    since_hour = (now - REPEAT_WINDOW).strftime("%Y-%m-%dT%H:00:00Z")
    window: dict[str, list[Any]] = {}
    out: dict[int, dict[str, Any]] = {}
    for row, p in ips_rows:
        ips = _m(p.get("ips"))
        scope = str(p.get("scope") or "")
        if scope not in window:
            window[scope] = ustore.window_buckets(slug, "ips_threat", since_hour, scope=scope)
        subject = str(_m(p.get("signal")).get("subject") or "")
        client, sig = _subject_parts(subject)
        remote = _clean(ips.get("remote_ip"), 45)
        local = _clean(ips.get("local_ip"), 45)
        count, approximate = 0, False
        if remote and subject:
            for b in window[scope]:
                b_client, b_sig = _subject_parts(b.subject)
                if b_client != client or b_sig != sig:
                    continue
                if b.remotes is None:
                    approximate = True
                    continue
                known = sum(v for k, v in b.remotes.items() if k not in ("~", "?"))
                if known < b.hits or b.remotes.get("~") or b.remotes.get("?"):
                    approximate = True
                count += int(b.remotes.get(remote) or 0)
        client_info = _m(ips.get("client"))
        local_name, source = None, None
        site_names = names.get(scope, {})
        if local and site_names.get(local):
            local_name, source = _clean(site_names[local]), "datto"
        elif client_info.get("name") or client_info.get("hostname"):
            local_name = _clean(client_info.get("name") or client_info.get("hostname"))
            source = "unifi"
        b = buckets.get(int(row["id"]))
        out[int(row["id"])] = {
            "kind": "unifi_ips",
            "direction": ips.get("direction") if ips.get("direction") in ("inbound", "outbound")
            else None,
            "action": "detected" if ips.get("action") == "detected" else "blocked",
            "signature": _clean(ips.get("signature"), 160),
            "remote_ip": remote, "local_ip": local,
            "local_name": local_name, "local_name_source": source,
            "remote": info.get(remote or "") if remote else None,
            "repeats_24h": count if remote else None,
            "repeats_approximate": approximate,
            "hits": b.hits if b is not None else None,
            "last_seen": b.last_seen if b is not None else None,
        }
    return out


# ---------------------------------------------------------------------------
# Datto RMM
# ---------------------------------------------------------------------------

def _datto_history(slug: str, now: datetime) -> tuple[dict[tuple[str, str],
                                                            tuple[set[str], str]], set[str]]:
    """((device key, signature key) → ({alert uids}, earliest received_at),
    {alert uids a RESOLUTION row was stored for}) over the tenant's Datto
    events of the last 30 days (bounded)."""
    from apps.octo.adapters.datto.fields import _alert_is_resolved

    path = paths.client_dir(slug) / "events.db"
    if not path.exists():
        return {}, set()
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5.0)
    except sqlite3.Error:
        return {}, set()
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT id, received_at, payload FROM events WHERE source = 'datto' "
            "AND received_at >= ? ORDER BY received_at DESC, id DESC LIMIT ?",
            (format_utc_ms(now - DATTO_LOOKBACK), DATTO_SCAN)).fetchall()
    except sqlite3.Error:
        return {}, set()
    finally:
        conn.close()
    out: dict[tuple[str, str], tuple[set[str], str]] = {}
    resolved: set[str] = set()
    for r in rows:
        p = keys.payload_of(dict(r))
        k = keys.alert_key({"source": "datto"}, p)
        uid = str(p.get("alertUid") or f"event:{r['id']}")
        if p.get("alertUid") and _alert_is_resolved(p):
            resolved.add(uid)
        uids, first = out.get((k.device_key, k.signature_key), (set(), str(r["received_at"])))
        uids.add(uid)
        out[(k.device_key, k.signature_key)] = (uids, min(first, str(r["received_at"])))
    return out, resolved


# How many OTHER devices' serials a shared-hostname warning names.
SHARED_SERIALS_MAX = 5


@dataclass(frozen=True)
class SharedName:
    """Devices of the tenant that carry ONE host name (more than one)."""
    devices: int
    sites: int
    serials: dict[str, Optional[str]] = field(default_factory=dict)
    """device uid → its serial (None = not known) — every device of the name."""


def _columns(conn: sqlite3.Connection) -> set[str]:
    """inv_device's columns — a tenant file migrates lazily: 046's `ext_ip`
    and 047's `serial` / `manufacturer` / `model` may not be there yet."""
    try:
        return {str(r[1]) for r in conn.execute("PRAGMA table_info(inv_device)")}
    except sqlite3.Error:
        return set()


def datto_identity(slug: str, uids: list[str], names: list[str]) -> tuple[
        dict[str, dict[str, Any]], dict[str, SharedName]]:
    """({device uid: {lan_ip, wan_ip, serial, manufacturer, model}} for the
    devices of the tenant's Datto device list among `uids`, {host-name key:
    SharedName} for the names among `names` that MORE THAN ONE device of the
    tenant carries} — devices Datto no longer lists left out. Never a UDF:
    the list holds none. A column the tenant's file does not have yet (046 /
    047 not applied) reads as None. ({}, {}) when unreadable."""
    from apps.octo.entity import normalize as nz
    from apps.octo.entity.db import EntityPathError, TenantDB

    want_uids = sorted({u for u in uids if u})
    want_keys = sorted({k for k in (nz.name_key(nz.hostname(n)) if nz.hostname(n) else None
                                    for n in names) if k})
    if not want_uids and not want_keys:
        return {}, {}
    ids: dict[str, dict[str, Any]] = {}
    shared: dict[str, SharedName] = {}
    try:
        with TenantDB.for_tenant(slug).read() as conn:
            if conn is None:
                return {}, {}
            cols = _columns(conn)

            def col(name: str) -> str:
                return name if name in cols else f"NULL AS {name}"

            if want_uids:
                for r in conn.execute(
                        f"SELECT device_uid, int_ip, {col('ext_ip')}, {col('serial')}, "
                        f"{col('manufacturer')}, {col('model')} FROM inv_device WHERE "
                        f"missing_since IS NULL AND device_uid IN "
                        f"({','.join('?' * len(want_uids))})", want_uids).fetchall():
                    ids[str(r["device_uid"])] = {
                        "lan_ip": _clean(r["int_ip"], 45), "wan_ip": _clean(r["ext_ip"], 45),
                        "serial": _clean(r["serial"], 64),
                        "manufacturer": _clean(r["manufacturer"], 80),
                        "model": _clean(r["model"], 80)}
            if want_keys:
                held: dict[str, dict[str, Any]] = {}
                for r in conn.execute(
                        f"SELECT hostname_key AS k, device_uid, site_uid, {col('serial')} "
                        f"FROM inv_device WHERE missing_since IS NULL AND hostname_key IN "
                        f"({','.join('?' * len(want_keys))}) ORDER BY device_uid",
                        want_keys).fetchall():
                    h = held.setdefault(str(r["k"]), {"sites": set(), "serials": {}})
                    h["sites"].add(str(r["site_uid"]))
                    h["serials"][str(r["device_uid"])] = _clean(r["serial"], 64)
                for k, h in held.items():
                    if len(h["serials"]) > 1:
                        shared[k] = SharedName(len(h["serials"]), len(h["sites"]),
                                               h["serials"])
    except (sqlite3.Error, EntityPathError, ValueError):
        return {}, {}
    return ids, shared


def datto(slug: str, rows: list[dict[str, Any]], *, now: datetime) -> dict[int, dict[str, Any]]:
    """{event id: enrichment} for the Datto alerts among `rows`. A raise
    whose RESOLUTION was stored since (the same alert uid — Datto stores it
    as a new row) reads resolved."""
    from apps.octo.adapters.datto.fields import _alert_device_uid, _alert_site_name
    from apps.octo.entity import normalize as nz

    mine = [r for r in rows if r.get("source") == "datto"]
    if not mine:
        return {}
    history, resolved = _datto_history(slug, now)
    payloads = {int(r["id"]): keys.payload_of(r) for r in mine}
    summaries = {i: datto_summary.summarize(p) for i, p in payloads.items()}
    ids, shared = datto_identity(
        slug, [_clean(_alert_device_uid(p), 128) or "" for p in payloads.values()],
        [s.get("host") or "" for s in summaries.values()])
    out: dict[int, dict[str, Any]] = {}
    for r in mine:
        p = payloads[int(r["id"])]
        s = summaries[int(r["id"])]
        if p.get("alertUid") and str(p.get("alertUid")) in resolved:
            s = dict(s, resolved=True)
        k = keys.alert_key(r, p)
        uids, first = history.get((k.device_key, k.signature_key), (set(), None))
        seen = len(uids)
        uid = _clean(_alert_device_uid(p), 128)
        host = nz.hostname(s.get("host")) if s.get("host") else None
        same = shared.get(nz.name_key(host)) if host else None
        # The OTHER devices of the name, by their serial where known.
        others = sorted({sn for d, sn in (same.serials.items() if same else ())
                         if d != uid and sn})[:SHARED_SERIALS_MAX]
        out[int(r["id"])] = {"kind": "datto", **s,
                             "repeats": max(0, seen - 1), "since": first if seen > 1 else None,
                             "device_uid": uid, "site": _clean(_alert_site_name(p), 128),
                             **_NO_IDENTITY, **(ids.get(uid or "") or {}),
                             "shared_hostname": same.devices if same else 0,
                             "shared_sites": same.sites if same else 0,
                             "shared_serials": others}
    return out
