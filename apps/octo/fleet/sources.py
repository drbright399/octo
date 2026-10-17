"""Readers for the Fleet — over what the pollers ALREADY store. Nothing here
contacts a vendor: a page load costs local reads only.

  UniFi       the running poller's last fleet poll (`fleet_health`: the
              report + statistics of every site), its per-site system-log
              progress (`site_states`), the tenant map; the IPS coalescing
              ledger (telemetry.db `unifi_signal_buckets`, 24 h)
  NextDNS     the running poller's per-profile protection state
              (`profile_states`) and the hourly roll-ups (telemetry.db
              `nextdns_hourly`: threat blocks = signal_high + signal_medium,
              split HIGH / MEDIUM — N8 — with the known-benign probes taken
              out of their level, from the coalescing ledger; v0.17.1: CSAM
              taken out of every count, the top reasons, and the PER-DEVICE
              view from the ledger's hour buckets — distinct HIGH clock hours
              and device-originated reasons per device — plus the 7-day count
              for "Threats stopped this week")
  RocketCyber the stored incident versions (events.db, the summary index —
              the latest version per incident id, status 'open'), freshness
              from the instance's last successful contact
  Datto       the inventory feed's rows (entities.db `inv_device` — every
              Datto-mapped tenant since v0.17.2, whatever its entity switch)
  entity      site links (entities.db `site_vendor_ref`, auto / confirmed,
              open) — used only for tenants whose switch is ON
  buoys       the heartbeat table (registry `buoys`), the same rollup as the
              buoy fleet view
  incidents   the tenant's Red / Black records (events.db `incidents`, 044) —
              open, and closed in the last 30 days; an unreadable store keeps
              the LAST KNOWN set (an incident is a floor: never read as gone)

Every reader is fail-soft: a store that cannot be read answers "nothing"
(the layer is then unknown or absent), never an exception to the API.
"""
from __future__ import annotations

import json
import logging
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from apps.octo import paths
from apps.octo.db import connect
from apps.octo.ingest.timestamps import format_utc_ms, normalize_timestamp

logger = logging.getLogger(__name__)

FRESH_POLLS = 2
FRESH_SLACK = timedelta(seconds=120)
DEFAULT_RC_INTERVAL_SEC = 300.0
DEFAULT_NEXTDNS_INTERVAL_SEC = 300.0
DEFAULT_NEXTDNS_PENDING_SEC = 6 * 3600.0
DATTO_INVENTORY_INTERVAL_SEC = 1800.0
RC_SCAN_LIMIT = 20_000
RC_LOOKBACK = timedelta(days=90)


def dt(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    ts = normalize_timestamp(value, naive_is_utc=True)
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def fresh(at: Any, interval_sec: float, now: datetime) -> bool:
    """At most two polls of its feed old (+ slack). Never-read is not fresh."""
    when = dt(at) if not isinstance(at, datetime) else at
    if when is None:
        return False
    return now - when <= timedelta(seconds=float(interval_sec) * FRESH_POLLS) + FRESH_SLACK


def _ro(path) -> Optional[sqlite3.Connection]:
    if not path.exists():
        return None
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5.0)
    except sqlite3.Error:
        return None
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Tenant:
    slug: str
    name: str
    kind: str
    entity_mode: str


def tenants() -> dict[str, Tenant]:
    """ACTIVE tenants: slug → Tenant."""
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        cols = {r[1] for r in reg.execute("PRAGMA table_info(clients)")}
        mode = "entity_resolution" if "entity_resolution" in cols else "'off'"
        rows = reg.execute(
            f"SELECT slug, display_name, kind, {mode} AS mode FROM clients "
            f"WHERE status = 'active' ORDER BY slug").fetchall()
    finally:
        reg.close()
    return {r["slug"]: Tenant(r["slug"], r["display_name"] or r["slug"], r["kind"] or "",
                              r["mode"] or "off") for r in rows}


def placeholder_named(slugs: list[str]) -> set[str]:
    """Tenants whose display name is still the auto-create placeholder
    ("<vendor> site <id>", it names a vendor) — a client user is shown "Your
    organization" instead (source health's rule)."""
    from apps.octo.instances.tenant_autocreate import placeholder_parts

    try:
        reg = connect(paths.registry_db_path(), read_only=True)
    except sqlite3.Error:
        return set(slugs)
    try:
        return {slug for slug, parts in placeholder_parts(reg, slugs).items() if "name" in parts}
    except sqlite3.Error:
        return set(slugs)
    finally:
        reg.close()


def mappings(instance_id: int) -> dict[str, tuple[str, Optional[str]]]:
    """vendor tenant id → (tenant slug, the label it was saved with)."""
    from apps.octo.instances import tenant_map

    try:
        return {m.vendor_tenant_id: (m.octo_client_slug, m.vendor_tenant_label)
                for m in tenant_map.get_mappings(instance_id)}
    except sqlite3.Error:
        return {}


def datto_site_ids(instance_id: int) -> dict[str, dict[str, str]]:
    """Datto site uid → {id, name?}: the numeric portal ids the inventory
    poller learned (`adapters.datto.site_ids`) — a registry read, never a
    vendor call. {} when none / unreadable (→ the portal-home link)."""
    from apps.octo.adapters.datto import site_ids

    try:
        return site_ids.known(instance_id)
    except Exception as exc:  # noqa: BLE001 — a page never fails for a link
        logger.warning("[fleet] Datto site ids of instance %s not read (%s)", instance_id,
                       type(exc).__name__)
        return {}


def tenant_site_keys(slug: str) -> set[str]:
    """Every Fleet site key that is this tenant's: its tenant-level entry and
    each UniFi site mapped to it (enabled instances) — what an incident's
    `site_key` may name. A mapping that cannot be read adds nothing (the
    caller refuses an unknown key; never guesses one in)."""
    from apps.octo.adapters.unifi.poller import split_scope
    from apps.octo.fleet.build import site_key

    keys = {site_key("tenant", slug)}
    for record in instances("unifi"):
        if record.disabled_at is not None:
            continue
        keys |= {site_key("unifi", scope) for scope, (owner, _label) in
                 mappings(record.id).items() if owner == slug and split_scope(scope)}
    return keys


def instances(vendor: str) -> list[Any]:
    from apps.octo.instances.manager import list_instances

    try:
        return [r for r in list_instances() if r.vendor_slug == vendor]
    except sqlite3.Error:
        return []


def running_poller(manager: Any, instance_id: int) -> Any:
    if manager is None:
        return None
    try:
        adapter = manager.running_adapter(instance_id)
    except Exception:  # noqa: BLE001
        return None
    return getattr(adapter, "poller", None) if adapter is not None else None


def buoy_health(now: Optional[datetime] = None) -> dict[str, tuple[str, str]]:
    """slug → (health, last heartbeat) — the buoy fleet view's rollup, aged
    against the build's `now` (one clock for every layer of a model)."""
    from apps.octo.api.routers.dashboard import _derive_fleet_row_health, \
        _normalize_services_read

    try:
        reg = connect(paths.registry_db_path(), read_only=True)
    except sqlite3.Error:
        return {}
    try:
        rows = reg.execute("SELECT slug, last_heartbeat_at, interval_sec, services_json "
                           "FROM buoys").fetchall()
    except sqlite3.Error:
        return {}
    finally:
        reg.close()
    now = now or datetime.now().astimezone()
    out: dict[str, tuple[str, str]] = {}
    for r in rows:
        last = dt(r["last_heartbeat_at"])
        stale = int((now - last).total_seconds()) if last else 10 ** 9
        try:
            services = _normalize_services_read(json.loads(r["services_json"] or "{}"))
        except (ValueError, TypeError):
            services = {}
        out[r["slug"]] = (_derive_fleet_row_health(services, max(0, stale),
                                                   r["interval_sec"] or 60),
                          r["last_heartbeat_at"])
    return out


# ---------------------------------------------------------------------------
# UniFi
# ---------------------------------------------------------------------------

@dataclass
class UnifiSite:
    instance_id: int
    scope: str
    host_id: str
    site_id: str
    internal_ref: Optional[str]
    slug: str
    name: str
    console_name: str
    location: dict[str, Any]
    health: Optional[dict[str, Any]]
    fleet_at: Optional[str]
    fleet_fresh: bool
    last_syslog_at: Optional[str]
    syslog_fresh: bool
    problem: Optional[str] = None
    client_name: Optional[str] = None
    """The site's own name as a CLIENT user may read it: the name UniFi
    reports when it is the site's own (not its console's — UniFi's default
    site takes the console's name, often a model / vendor name), never the
    mapping label (it carries the console and its address). None: the API
    shows a neutral name."""
    console_sites: int = 1
    """Sites of the last fleet poll on this site's console (mapped or not)."""
    console_shared: bool = False
    """The console also carries a site of ANOTHER tenant or an unmapped one."""


@dataclass
class UnifiFleet:
    sites: list[UnifiSite] = field(default_factory=list)
    unmapped: int = 0
    outages: list[dict[str, Any]] = field(default_factory=list)


def unifi_fleet(manager: Any, active: dict[str, Tenant], now: datetime) -> UnifiFleet:
    """Every UniFi site MAPPED to an active tenant, from the running poller's
    last fleet poll — a mapped site the poller has not seen (just started,
    instance not running) is listed with no health (unknown)."""
    from apps.octo.adapters.unifi.poller import split_scope
    from apps.octo.instances import ignored_tenants

    out = UnifiFleet()
    for record in instances("unifi"):
        if record.disabled_at is not None:
            continue
        mapped = {scope: v for scope, v in mappings(record.id).items() if split_scope(scope)}
        poller = running_poller(manager, record.id)
        health: dict[str, Any] = {}
        states: dict[str, Any] = {}
        if poller is not None and hasattr(poller, "fleet_health"):
            try:
                health = poller.fleet_health() or {}
                states = poller.site_states() or {}
                out.outages.extend(
                    dict(i, instance_id=record.id) for i in (poller.isp_outages() or []))
            except Exception:  # noqa: BLE001 — a page never fails for a snapshot
                health, states = {}, {}
        fleet_sites = health.get("sites") if isinstance(health.get("sites"), dict) else {}
        at = health.get("at")
        is_fresh = fresh(at, float(health.get("interval_sec") or 300.0), now)
        syslog_every = float(health.get("syslog_interval_sec") or 300.0)
        try:
            ignored = ignored_tenants.ignored_ids(record.id)
        except sqlite3.Error:
            ignored = set()
        out.unmapped += sum(1 for scope in fleet_sites
                            if scope not in mapped and scope not in ignored)
        # Who else is on each console: its sites in the last fleet poll and
        # their owners (an unmapped site is an owner of its own).
        per_host: dict[str, int] = {}
        owners: dict[str, set[str]] = {}
        for scope_k in fleet_sites:
            host = str(scope_k).split("/")[0]
            per_host[host] = per_host.get(host, 0) + 1
            owner = mapped.get(scope_k, (None, None))[0]
            owners.setdefault(host, set()).add(f"t:{owner}" if owner else f"s:{scope_k}")
        for scope, (slug, label) in sorted(mapped.items()):
            if slug not in active:
                continue
            host_id, site_id = split_scope(scope)  # type: ignore[misc]
            site = fleet_sites.get(scope) if isinstance(fleet_sites.get(scope), dict) else None
            st = states.get(scope) or {}
            last_syslog = st.get("last_syslog_at")
            console = str((site or {}).get("console_name") or "")
            reported = str((site or {}).get("name") or "")
            out.sites.append(UnifiSite(
                instance_id=record.id, scope=scope, host_id=host_id, site_id=site_id,
                internal_ref=(site or {}).get("internal_ref"), slug=slug,
                name=str(reported or label or site_id),
                console_name=console,
                location=dict((site or {}).get("location") or {}),
                health=site, fleet_at=at if site else None,
                fleet_fresh=bool(site) and is_fresh,
                last_syslog_at=last_syslog,
                syslog_fresh=fresh(last_syslog, syslog_every, now),
                problem=st.get("problem"),
                client_name=reported if site and not console_named(reported, console)
                else None,
                console_sites=per_host.get(host_id, 1),
                console_shared=len(owners.get(host_id, set()) - {f"t:{slug}"}) > 0,
            ))
    return out


def console_named(name: str, console: str) -> bool:
    """Is `name` UniFi's stand-in for a default site — its CONSOLE's name
    ("<console>" or "<console> — Default", `poller.site_name`)? Empty is."""
    n, c = name.strip().lower(), console.strip().lower()
    if not n:
        return True
    return bool(c) and (n == c or n.startswith(f"{c} — "))


def ips_counts(slug: str, since: datetime, *, verdicts: Any = None,
               hidden: Optional[dict[str, int]] = None,
               raw: Optional[dict[str, tuple[int, int, int]]] = None,
               ) -> dict[str, tuple[int, int, int]]:
    """scope → (detected-not-blocked, blocked, blocked INBOUND) IPS hits since
    `since`, from the coalescing ledger (every hit counted, not only the
    first alert). The direction is the subject's next-to-last part when the
    catalogue knew it (N7); a subject without one counts as not inbound.

    `verdicts` (`verdicts.state.TenantVerdicts`): a bucket whose alert is
    ACKNOWLEDGED (and not re-surfaced) or EXPECTED is not counted — its hits
    go to `hidden[scope]` instead (v0.17.2, A / B: it stops contributing to
    the site's Yellow; the hits stay stored). `raw` gets every hit, judged
    or not: the counts SHOWN are the facts — only the Yellow is the
    humans' to change."""
    from apps.octo.ingest import telemetry

    hour = since.strftime("%Y-%m-%dT%H:00:00Z")
    if verdicts is not None and not verdicts.empty:
        return _ips_counts_with_verdicts(slug, hour, verdicts, hidden, raw)
    conn = _ro(telemetry.db_path_for(slug))
    if conn is None:
        return {}
    try:
        rows = conn.execute(
            "SELECT scope, subject, SUM(hits) AS n FROM unifi_signal_buckets "
            "WHERE kind = 'ips_threat' AND hour >= ? GROUP BY scope, subject", (hour,),
        ).fetchall()
    except sqlite3.Error:
        return {}
    finally:
        conn.close()
    out = _ips_tally((str(r["scope"]), str(r["subject"] or ""), int(r["n"] or 0))
                     for r in rows)
    if raw is not None:
        raw.update(out)
    return out


def _ips_counts_with_verdicts(slug: str, hour: str, verdicts: Any,
                              hidden: Optional[dict[str, int]],
                              raw: Optional[dict[str, tuple[int, int, int]]],
                              ) -> dict[str, tuple[int, int, int]]:
    from apps.octo.adapters.unifi import store as ustore
    from apps.octo.verdicts import occurrences

    buckets = ustore.window_buckets(slug, "ips_threat", hour)
    linked = occurrences.linked_events(slug, [b.event_id for b in buckets if b.event_id])
    kept, every = [], []
    for b in buckets:
        every.append((b.scope, b.subject, b.hits))
        st = verdicts.state(occurrences.unifi_occurrence(b, linked=b.event_id in linked))
        if st.hidden:
            if hidden is not None:
                hidden[b.scope] = hidden.get(b.scope, 0) + b.hits
            continue
        kept.append((b.scope, b.subject, b.hits))
    if raw is not None:
        raw.update(_ips_tally(every))
    return _ips_tally(kept)


def _ips_tally(rows: Any) -> dict[str, tuple[int, int, int]]:
    out: dict[str, list[int]] = {}
    for scope, subject, n in rows:
        parts = str(subject or "").split("|")
        action = parts[-1]
        direction = parts[-2] if len(parts) >= 4 else None
        trio = out.setdefault(scope, [0, 0, 0])
        n = int(n or 0)
        if action == "detected":
            trio[0] += n
        else:
            trio[1] += n
            if direction == "inbound":
                trio[2] += n
    return {k: (v[0], v[1], v[2]) for k, v in out.items()}


# ---------------------------------------------------------------------------
# NextDNS
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Profile:
    instance_id: int
    profile_id: str
    name: str
    slug: str
    state: str
    missing: bool
    fresh: bool
    since: Optional[str] = None
    """When the profile entered its current state (the poller's `since`)."""


def profile_fresh(st: dict[str, Any], *, security_sec: float, pending_sec: float,
                  now: datetime) -> bool:
    """Is the poller's word on this profile current? Judged by what the
    poller actually re-reads for its STATE: an ACTIVE / LAPSED profile by
    its security check (`last_check_at`, every security round); a PENDING /
    NEW or a MISSING one by its status / probe read (`health_at`, every
    `pending_check_sec` — it never gets a security check)."""
    if not st:
        return False
    if st.get("missing") or str(st.get("state") or "") not in ("active", "lapsed"):
        return fresh(st.get("health_at"), pending_sec, now)
    return fresh(st.get("last_check_at"), security_sec, now)


def nextdns_profiles(manager: Any, active: dict[str, Tenant], now: datetime) -> \
        dict[str, list[Profile]]:
    """slug → its mapped profiles with the poller's protection state. A mapped
    profile the poller has no state for (not running, not read yet) is
    listed as not fresh (unknown)."""
    out: dict[str, list[Profile]] = {}
    for record in instances("nextdns"):
        if record.disabled_at is not None:
            continue
        poller = running_poller(manager, record.id)
        states: dict[str, Any] = {}
        security = DEFAULT_NEXTDNS_INTERVAL_SEC
        pending = DEFAULT_NEXTDNS_PENDING_SEC
        if poller is not None and hasattr(poller, "profile_states"):
            try:
                states = poller.profile_states() or {}
                snap = (poller.snapshot() if hasattr(poller, "snapshot") else {}) or {}
                security = float(snap.get("security_round_sec") or snap.get("interval_sec")
                                 or security)
                pending = float(snap.get("pending_check_sec") or pending)
            except Exception:  # noqa: BLE001
                states = {}
        for pid, (slug, label) in sorted(mappings(record.id).items()):
            if slug not in active:
                continue
            st = states.get(pid) or {}
            out.setdefault(slug, []).append(Profile(
                instance_id=record.id, profile_id=pid,
                name=str(st.get("name") or label or pid), slug=slug,
                state=str(st.get("state") or "pending"), missing=bool(st.get("missing")),
                fresh=profile_fresh(st, security_sec=security, pending_sec=pending, now=now),
                since=st.get("since") if isinstance(st.get("since"), str) else None,
            ))
    return out


@dataclass(frozen=True)
class DnsDevice:
    """One device's DNS signal buckets in the window (the coalescing
    ledger): the distinct CLOCK HOURS it had a HIGH-risk block in (CSAM and
    known-benign never count) and its blocks in the device-originated
    reasons (dga, tunneling, exfiltration, payload delivery: software makes
    those lookups)."""
    key: str                 # NextDNS device id, else the client IP ('' = neither)
    name: str                # the device's name as its alert carried it, else the key
    profile_id: str
    high_hours: int
    originated: tuple[tuple[str, int], ...] = ()
    network: bool = False
    """The key is an IP ADDRESS: NextDNS named no device, and the client IP
    of gateway / linked-IP traffic is the site's public address — every
    device behind it shares the key. It is never "one device" for the
    beaconing rule (three people's blocks in three hours are not a beacon);
    only a device-originated block flags it ("a device behind <ip>")."""


@dataclass(frozen=True)
class DnsCounts:
    total: int          # threats: high + medium (known-benign, filter-bypass and CSAM out)
                        # — every such block, whatever a human decided about it
    high: int           # HIGH, known-benign probes taken out (N8)
    medium: int         # MEDIUM, known-benign and filter-bypass taken out
    benign: int         # blocks a known-benign rule matched
    bypass: int = 0
    """Filter-bypass blocks (VPN / proxy / Tor / Private Relay — NextDNS's
    Parental Control "bypass methods"): policy, not a security-category
    threat — never in a threat count (operators read them apart)."""
    reasons: tuple[tuple[str, int], ...] = ()
    """HIGH / MEDIUM threat reasons with their counts in the window (the
    roll-ups, known-benign hits taken out), most first — never a CSAM or a
    filter-bypass reason (v0.17.1)."""
    devices: tuple[DnsDevice, ...] = ()
    """Devices that may look wrong: ≥ 2 HIGH clock hours, or any block in a
    device-originated reason (the threshold is the caller's knob)."""
    originated_unattributed: tuple[tuple[str, int], ...] = ()
    """Device-originated reasons the roll-ups counted inside the window (a
    known-benign rule's hits taken out) but no ledger bucket names a device
    for (a log page not read) — still Yellow, at the profile."""


# A device with fewer distinct HIGH hours than this is never a candidate
# (the knob's floor: `registry.KNOBS['dns_beacon_hours'].low`).
BEACON_HOURS_FLOOR = 2
DEVICE_SCAN_ROWS = 20_000


def _is_ip(value: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def dns_threats(slug: str, profile_ids: list[str], since: datetime, *,
                devices: bool = True, verdicts: Any = None,
                hidden: Optional[dict[str, int]] = None) -> dict[str, DnsCounts]:
    """profile → threat blocks since `since`, from the hourly roll-ups (HIGH
    + MEDIUM signal reasons) — split by level (N8). A block a known-benign
    rule matched (the Samsung connectivity probe) is counted by the
    coalescing ledger under its `kb:<rule>` root (a DAY bucket: the rule files
    it at LOW): only the kb buckets WHOLLY inside the window are taken out of
    the level NextDNS gave them (a bucket that began before the window holds
    hits from before it — taking those out could hide a real block in it).
    And neither the HIGH nor the MEDIUM count is ever only a difference: the
    ledger's own non-kb buckets of that level in the window are counted too,
    and the larger of the two wins — a real block is never subtracted away
    (the roll-up of the current hour may lag the ledger). Louder, never
    quieter.

    v0.17.1 (Rick, 2026-10-06): CSAM blocks are taken out of every count
    (rule B7 handles them — they are never a fleet colour or a "top reason");
    so are filter-bypass blocks (NextDNS files them under Parental Control,
    not Security: counted apart, `bypass`); `reasons` = the window's HIGH /
    MEDIUM threat reasons by count, known-benign hits taken out; `devices`
    (when asked) = the ledger's per-device view: distinct HIGH clock hours
    and the device-originated reasons — the source of "the device looks
    wrong" — from the buckets with a hit INSIDE the window (`last_seen`; an
    hour that began before `since` counts only for its later hits).

    `verdicts` (v0.17.2): the COUNTS stay every block (a fact, shown to a
    client user too); a bucket whose alert a human ACKNOWLEDGED (not
    re-surfaced) or EXPECTED leaves only the DEVICE view — the Yellow
    ("possible infection") — and its hits go to `hidden[profile]` (the
    operators' "N acknowledged"). A new hour's bucket is a new alert: it
    counts again."""
    from apps.octo.adapters.nextdns.classification import (
        BYPASS_REASON,
        HIGH,
        MEDIUM,
        classify_reason,
        is_csam,
    )
    from apps.octo.ingest import telemetry

    if not profile_ids:
        return {}
    conn = _ro(telemetry.db_path_for(slug))
    if conn is None:
        return {}
    marks = ",".join("?" * len(profile_ids))
    hour = since.strftime("%Y-%m-%dT%H:00:00Z")
    # The first clock hour wholly inside the window: the roll-up of the hour
    # `since` falls in holds lookups from before it.
    inside = since.replace(minute=0, second=0, microsecond=0)
    if inside < since:
        inside += timedelta(hours=1)
    inside_hour = inside.strftime("%Y-%m-%dT%H:00:00Z")
    day0 = since.replace(hour=0, minute=0, second=0, microsecond=0)
    try:
        per_hour = conn.execute(
            f"SELECT profile_id, hour, signal_high, signal_medium, signal_reasons "
            f"FROM nextdns_hourly WHERE hour >= ? AND profile_id IN ({marks})",
            (hour, *profile_ids)).fetchall()
        sums: dict[str, list[int]] = {}
        by_reason: dict[str, dict[str, int]] = {}
        by_reason_inside: dict[str, dict[str, int]] = {}
        for r in per_hour:
            slot = sums.setdefault(r["profile_id"], [0, 0])
            slot[0] += int(r["signal_high"] or 0)
            slot[1] += int(r["signal_medium"] or 0)
            try:
                found = json.loads(r["signal_reasons"] or "{}")
            except ValueError:
                found = {}
            if isinstance(found, dict):
                mine = by_reason.setdefault(r["profile_id"], {})
                inner = by_reason_inside.setdefault(r["profile_id"], {}) \
                    if str(r["hour"]) >= inside_hour else None
                for rid, n in found.items():
                    if isinstance(n, int) and not isinstance(n, bool) and n > 0:
                        mine[str(rid)] = mine.get(str(rid), 0) + n
                        if inner is not None:
                            inner[str(rid)] = inner.get(str(rid), 0) + n
        rows = [{"profile_id": pid, "h": h, "m": m} for pid, (h, m) in sums.items()]
        # A bucket's `hour` is its START: hour buckets from the window's
        # first hour; DAY buckets only from the first whole UTC day inside
        # the window (one that began before `since` holds hits from before
        # it).
        day_cut = (day0 if day0 == since else day0 + timedelta(days=1)) \
            .strftime("%Y-%m-%dT%H:00:00Z")
        try:
            ledger = conn.execute(
                f"SELECT profile_id, reason_id, (root LIKE 'kb:%') AS kb, SUM(hits) AS n "
                f"FROM nextdns_signal_buckets WHERE profile_id IN ({marks}) AND "
                f"((span = 'day' AND hour >= ?) OR (span <> 'day' AND hour >= ?)) "
                f"GROUP BY profile_id, reason_id, kb",
                (*profile_ids, day_cut, hour)).fetchall()
        except sqlite3.Error:
            ledger = []
        # Known-benign hits PER REASON over every kb day bucket that touches
        # the window — taken out of the shown reasons and of the
        # device-originated check (a rule an operator wrote for a vendor
        # domain NextDNS calls DGA quiets it; the roll-up alone cannot tell).
        try:
            kb_rows = conn.execute(
                f"SELECT profile_id, reason_id, SUM(hits) AS n FROM nextdns_signal_buckets "
                f"WHERE profile_id IN ({marks}) AND root LIKE 'kb:%' AND hour >= ? "
                f"GROUP BY profile_id, reason_id",
                (*profile_ids, day0.strftime("%Y-%m-%dT%H:00:00Z"))).fetchall()
        except sqlite3.Error:
            kb_rows = []
        buckets: list[sqlite3.Row] = []
        if devices:
            try:
                buckets = conn.execute(
                    f"SELECT bucket_key, profile_id, device, reason_id, root, span, hour, "
                    f"hits, event_id, first_seen, last_seen FROM nextdns_signal_buckets WHERE profile_id IN ({marks}) AND "
                    f"span = 'hour' AND hour >= ? AND last_seen >= ? "
                    f"AND root NOT LIKE 'kb:%' ORDER BY hour DESC LIMIT ?",
                    (*profile_ids, hour, format_utc_ms(since), DEVICE_SCAN_ROWS)).fetchall()
            except sqlite3.Error:
                buckets = []
    except sqlite3.Error:
        return {}
    finally:
        conn.close()
    if verdicts is not None and not verdicts.empty:
        gone = _dns_hidden(slug, profile_ids, hour, day_cut, format_utc_ms(since), verdicts,
                           hidden)
        buckets = [b for b in buckets if b["bucket_key"] not in gone]
    kb: dict[str, dict[str, int]] = {}
    real_high: dict[str, int] = {}
    real_medium: dict[str, int] = {}
    for r in ledger:
        if is_csam(r["reason_id"]) or r["reason_id"] == BYPASS_REASON:
            continue                          # B7's / not a threat: never a threat count
        level = classify_reason(r["reason_id"]).level
        n = int(r["n"] or 0)
        if r["kb"]:
            slot = kb.setdefault(r["profile_id"], {HIGH: 0, MEDIUM: 0, "other": 0})
            slot[level if level in (HIGH, MEDIUM) else "other"] += n
        elif level == HIGH:
            real_high[r["profile_id"]] = real_high.get(r["profile_id"], 0) + n
        elif level == MEDIUM:
            real_medium[r["profile_id"]] = real_medium.get(r["profile_id"], 0) + n
    kb_reason: dict[str, dict[str, int]] = {}
    for r in kb_rows:
        slot = kb_reason.setdefault(r["profile_id"], {})
        slot[str(r["reason_id"])] = slot.get(str(r["reason_id"]), 0) + int(r["n"] or 0)
    found_devices = _dns_devices(slug, buckets) if devices else {}
    out: dict[str, DnsCounts] = {}
    for r in rows:
        pid = r["profile_id"]
        reasons = by_reason.get(pid, {})
        csam = sum(n for rid, n in reasons.items() if is_csam(rid))
        bypass = int(reasons.get(BYPASS_REASON, 0))
        high = max(0, int(r["h"] or 0) - csam)
        med = max(0, int(r["m"] or 0) - bypass)
        b = kb.get(pid, {})
        b_high, b_med = min(high, b.get(HIGH, 0)), min(med, b.get(MEDIUM, 0))
        high_n = max(high - b_high, real_high.get(pid, 0))
        med_n = max(med - b_med, real_medium.get(pid, 0))
        out[pid] = DnsCounts(
            total=high_n + med_n, high=high_n, medium=med_n,
            benign=b_high + b_med, bypass=bypass,
            **_dns_extras(pid, reasons, by_reason_inside.get(pid, {}),
                          kb_reason.get(pid, {}), found_devices.get(pid, ())))
    for pid, n in real_high.items():
        if pid not in out and n:
            # The roll-up has no row yet (its first hour): the ledger's word.
            out[pid] = DnsCounts(total=n, high=n, medium=0, benign=0,
                                 **_dns_extras(pid, {}, {}, {}, found_devices.get(pid, ())))
    for pid, devs in found_devices.items():
        if pid not in out and devs:
            out[pid] = DnsCounts(total=0, high=0, medium=0, benign=0,
                                 **_dns_extras(pid, {}, {}, {}, devs))
    return out



def _dns_hidden(slug: str, profile_ids: list[str], hour: str, day_cut: str, since_iso: str,
                verdicts: Any, hidden: Optional[dict[str, int]]) -> set[str]:
    """The `bucket_key`s of the window's ledger buckets whose alert a human
    acknowledged / expected (`verdicts.state(...).hidden`), their hits added
    to `hidden[profile]` — including a DAY bucket that began before
    `day_cut` but whose first hit is inside the window (the drawer lists its
    alert). Known-benign (`kb:`) buckets are a rule's, not a human's: never
    here; a CSAM bucket never is either (rule B7's)."""
    from apps.octo.adapters.nextdns.classification import is_csam
    from apps.octo.verdicts import occurrences

    buckets = occurrences.nextdns_buckets(slug, profile_ids, hour, day_cut, since_iso=since_iso)
    linked = occurrences.linked_events(slug, [b["event_id"] for b in buckets if b["event_id"]])
    gone: set[str] = set()
    for b in buckets:
        if str(b["root"] or "").startswith("kb:") or is_csam(b["reason_id"]):
            continue
        st = verdicts.state(occurrences.nextdns_occurrence(
            b, linked=bool(b["event_id"]) and int(b["event_id"]) in linked))
        if not st.hidden:
            continue
        gone.add(str(b["bucket_key"]))
        if hidden is not None:
            hidden[b["profile_id"]] = hidden.get(b["profile_id"], 0) + int(b["hits"] or 0)
    return gone


def _dns_extras(pid: str, reasons: dict[str, int], inside: dict[str, int],
                kb_reason: dict[str, int], devs: tuple[DnsDevice, ...]) -> dict[str, Any]:
    """`reasons` (HIGH / MEDIUM threats — no CSAM, no filter bypass — with
    the known-benign hits taken out, most first), the devices, and the
    device-originated reasons no device accounts for (`inside`: the roll-ups
    of the clock hours wholly inside the window — the hour `since` falls in
    holds lookups from before it)."""
    from apps.octo.adapters.nextdns.classification import (
        BYPASS_REASON,
        HIGH,
        MEDIUM,
        classify_reason,
        is_csam,
        is_device_originated,
    )

    def threats(found: dict[str, int]) -> list[tuple[str, int]]:
        out = []
        for rid, n in found.items():
            if is_csam(rid) or rid == BYPASS_REASON \
                    or classify_reason(rid).level not in (HIGH, MEDIUM):
                continue
            n -= kb_reason.get(rid, 0)
            if n > 0:
                out.append((rid, n))
        return sorted(out, key=lambda x: (-x[1], x[0]))

    shown = threats(reasons)
    attributed = {rid for d in devs for rid, _n in d.originated}
    loose = tuple((rid, n) for rid, n in threats(inside) if is_device_originated(rid)
                  and rid not in attributed)
    return {"reasons": tuple(shown[:20]), "devices": devs, "originated_unattributed": loose}


def _dns_devices(slug: str, buckets: list[sqlite3.Row]) -> dict[str, tuple[DnsDevice, ...]]:
    """profile → the devices worth a look from the ledger's HOUR buckets
    (HIGH reasons only; CSAM and known-benign never count): ≥ 2 distinct
    clock hours, or any device-originated reason. Each named as its newest
    alert's device (events.db `source_host`), else its key. A key that is an
    IP address (no NextDNS device: the site's public address) is a NETWORK,
    never one device: the beacon hours are not counted for it, and it is a
    candidate only for a device-originated block."""
    from apps.octo.adapters.nextdns.classification import (
        HIGH,
        classify_reason,
        is_csam,
        is_device_originated,
    )

    hours: dict[tuple[str, str], set[str]] = {}
    origin: dict[tuple[str, str], dict[str, int]] = {}
    newest: dict[tuple[str, str], int] = {}
    for b in buckets:
        rid = b["reason_id"]
        if is_csam(rid) or classify_reason(rid).level != HIGH:
            continue
        k = (b["profile_id"], b["device"] or "")
        hours.setdefault(k, set()).add(str(b["hour"]))
        if is_device_originated(rid):
            slot = origin.setdefault(k, {})
            slot[rid] = slot.get(rid, 0) + int(b["hits"] or 1)
        if isinstance(b["event_id"], int) and b["event_id"] > newest.get(k, 0):
            newest[k] = int(b["event_id"])
    network = {k: bool(k[1]) and _is_ip(k[1]) for k in hours}
    keep = [k for k in hours
            if (k[1] and not network[k] and len(hours[k]) >= BEACON_HOURS_FLOOR) or k in origin]
    names = _event_hosts(slug, [newest[k] for k in keep if k in newest and not network[k]])
    out: dict[str, list[DnsDevice]] = {}
    for k in sorted(keep):
        pid, dev = k
        if network[k]:
            name = f"a device behind {dev}"
        else:
            name = names.get(newest.get(k, 0)) or dev or "an unidentified device"
        out.setdefault(pid, []).append(DnsDevice(
            key=dev, name=name, profile_id=pid,
            high_hours=len(hours[k]) if dev and not network[k] else 0,
            originated=tuple(sorted(origin.get(k, {}).items())), network=network[k]))
    return {pid: tuple(v) for pid, v in out.items()}



def _event_hosts(slug: str, event_ids: list[int]) -> dict[int, str]:
    """event id → its `source_host` (the device name the alert carried)."""
    ids = sorted(set(event_ids))[-500:]
    if not ids:
        return {}
    conn = _ro(paths.client_dir(slug) / "events.db")
    if conn is None:
        return {}
    try:
        rows = conn.execute(
            f"SELECT id, source_host FROM events WHERE id IN ({','.join('?' * len(ids))})",
            ids).fetchall()
    except sqlite3.Error:
        return {}
    finally:
        conn.close()
    return {int(r["id"]): str(r["source_host"]) for r in rows if r["source_host"]}


def dns_week(slug: str, profile_ids: list[str], now: datetime) -> int:
    """A5: security-category DNS blocks over the last 7 days (HIGH + MEDIUM
    threats — known-benign, filter-bypass and CSAM taken out) — "Threats
    stopped this week"."""
    found = dns_threats(slug, profile_ids, now - timedelta(days=7), devices=False)
    return sum(c.high + c.medium for c in found.values())


# ---------------------------------------------------------------------------
# RocketCyber
# ---------------------------------------------------------------------------

def _config_interval(record: Any, key: str, default: float, low: float,
                     high: float) -> float:
    """An instance's configured interval as its adapter reads it (a value
    out of range / not a number → the default)."""
    raw = (getattr(record, "instance_config", None) or {}).get(key)
    try:
        value = float(raw) if raw not in (None, "") else default
    except (TypeError, ValueError):
        return default
    if value != value or not (low <= value <= high):          # NaN / out of range
        return default
    return value


def rocketcyber_interval(record: Any) -> float:
    """The RocketCyber adapter's poll interval (`poll_interval_sec`, as its
    `start` bounds it: 0 < x <= 86400, else the 300 s default)."""
    value = _config_interval(record, "poll_interval_sec", DEFAULT_RC_INTERVAL_SEC, 0.0,
                             86_400.0)
    return value or DEFAULT_RC_INTERVAL_SEC


def datto_inventory_interval(record: Any) -> float:
    """The Datto inventory feed's interval (`inventory_interval_sec`, at
    least 1800 s — the InventoryPoller's floor, one read per site per 30
    minutes; 1800 s by default)."""
    if record is None:
        return DATTO_INVENTORY_INTERVAL_SEC
    raw = (getattr(record, "instance_config", None) or {}).get("inventory_interval_sec")
    try:
        value = float(raw) if raw not in (None, "") else DATTO_INVENTORY_INTERVAL_SEC
    except (TypeError, ValueError):
        value = DATTO_INVENTORY_INTERVAL_SEC
    if value != value:
        value = DATTO_INVENTORY_INTERVAL_SEC
    return max(DATTO_INVENTORY_INTERVAL_SEC, value)


def rocketcyber_tenants(now: datetime) -> dict[str, bool]:
    """slug → is the RocketCyber feed delivering into it fresh (an instance's
    last successful contact within two of ITS polls)."""
    from apps.octo.instances import tenant_map, vendor_contact

    out: dict[str, bool] = {}
    for record in instances("rocketcyber"):
        if record.disabled_at is not None:
            continue
        ok = fresh(vendor_contact.snapshot(record.id).get("last_ok_at"),
                   rocketcyber_interval(record), now)
        try:
            slugs = tenant_map.instance_tenant_slugs(record)
        except sqlite3.Error:
            slugs = set()
        for slug in slugs:
            out[slug] = out.get(slug, False) or ok
    return out


def rocketcyber_open(slug: str, now: datetime, *, verdicts: Any = None,
                     hidden: Optional[dict[str, int]] = None) -> Optional[int]:
    """Open incidents of the tenant: the LATEST stored version of each
    incident (by received_at, id) whose status is 'open' — read through the
    summary index the RocketCyber poller seeds from. None when unreadable.
    `verdicts` (v0.17.2): an incident whose latest version a human
    acknowledged (the ack read whatever its age) is not counted
    (`hidden["rocketcyber"]`); a version NEWER than the one acked re-
    surfaces it. (An incident names no device: never "expected", never
    "repeats for 24 h".)"""
    from apps.octo.adapters.rocketcyber.presentation import HEADLINE_PREFIX

    conn = _ro(paths.client_dir(slug) / "events.db")
    if conn is None:
        return 0
    hi = HEADLINE_PREFIX[:-1] + chr(ord(HEADLINE_PREFIX[-1]) + 1)
    try:
        rows = conn.execute(
            "SELECT id, received_at, json_extract(payload, '$.id') AS iid, "
            "json_extract(payload, '$.status') AS status, "
            "json_extract(payload, '$.title') AS title FROM events "
            "WHERE summary != '' AND summary >= ? AND summary < ? AND source = 'rocketcyber' "
            "AND received_at >= ? LIMIT ?",
            (HEADLINE_PREFIX, hi, format_utc_ms(now - RC_LOOKBACK), RC_SCAN_LIMIT),
        ).fetchall()
    except sqlite3.Error:
        return None
    finally:
        conn.close()
    latest: dict[str, tuple[str, int, str, str]] = {}
    for r in rows:
        if r["iid"] is None:
            continue
        key = (str(r["received_at"] or ""), int(r["id"]))
        held = latest.get(str(r["iid"]))
        if held is None or (held[0], held[1]) < key:
            latest[str(r["iid"])] = (key[0], key[1], str(r["status"] or "").strip().lower(),
                                     str(r["title"] or ""))
    opened = [(iid, *v) for iid, v in latest.items() if v[2] == "open"]
    if verdicts is None or not opened:
        return len(opened)
    from apps.octo.verdicts import occurrences

    # An incident may stay open for days: its acks are read by incident
    # (every version) WHATEVER their age — never only the last 48 h.
    verdicts.ensure(refs=[f"rocketcyber:{iid}" for iid, *_rest in opened])
    if verdicts.empty:
        return len(opened)
    linked = occurrences.linked_events(slug, [v[2] for v in opened])
    count = 0
    for iid, at, eid, _status, title in opened:
        row = {"id": eid, "received_at": at, "source": "rocketcyber",
               "event_type": "rocketcyber.incident", "source_host": None}
        st = verdicts.state(occurrences.row_occurrence(row, linked=eid in linked,
                                                       payload={"title": title, "id": iid}))
        if st.hidden:
            if hidden is not None:
                hidden["rocketcyber"] = hidden.get("rocketcyber", 0) + 1
            continue
        count += 1
    return count


# ---------------------------------------------------------------------------
# Datto inventory + entity links (entities.db)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class InventorySite:
    instance_id: int
    site_uid: str
    total: int
    online: int
    offline: int
    servers_offline: int
    updated_at: Optional[str]


def datto_inventory(slug: str, *, server_grace_min: int = 0,
                    now: Optional[datetime] = None) -> Optional[list[InventorySite]]:
    """The tenant's Datto inventory per Datto site (devices not missing), or
    None when there is none to read yet.
    `server_grace_min` (the `server_offline_grace_min` knob, 0–60): a server
    last seen less than that long ago is not counted offline yet (a reboot);
    one with no last-seen time always is (never guessed fresh)."""
    from apps.octo.entity.db import EntityPathError, TenantDB

    grace = max(0, int(server_grace_min or 0))
    cutoff = format_utc_ms((now or datetime.now(timezone.utc)) - timedelta(minutes=grace)) \
        if grace else None
    try:
        tdb = TenantDB.for_tenant(slug)
        with tdb.read() as conn:
            if conn is None:
                return None
            rows = conn.execute(
                "SELECT adapter_instance_id AS inst, site_uid, COUNT(*) AS total, "
                "SUM(CASE WHEN online = 1 THEN 1 ELSE 0 END) AS online, "
                "SUM(CASE WHEN online = 0 THEN 1 ELSE 0 END) AS offline, "
                "SUM(CASE WHEN online = 0 AND (lower(device_type) LIKE '%server%' "
                "     OR lower(device_type) LIKE '%esxi%') AND (? IS NULL OR last_seen IS NULL "
                "     OR last_seen <= ?) THEN 1 ELSE 0 END) AS srv_off, "
                "MAX(updated_at) AS updated_at FROM inv_device WHERE missing_since IS NULL "
                "GROUP BY adapter_instance_id, site_uid", (cutoff, cutoff)).fetchall()
    except (sqlite3.Error, EntityPathError, ValueError):
        return None
    if not rows:
        return None
    return [InventorySite(int(r["inst"]), str(r["site_uid"]), int(r["total"] or 0),
                          int(r["online"] or 0), int(r["offline"] or 0),
                          int(r["srv_off"] or 0), r["updated_at"]) for r in rows]


def entity_links(slug: str) -> dict[str, dict[str, set[str]]]:
    """UniFi scope → {'nextdns': {profile ids}, 'datto': {site uids}} from the
    tenant's OPEN auto / confirmed site links. {} when unreadable."""
    from apps.octo.entity.db import EntityPathError, TenantDB

    try:
        tdb = TenantDB.for_tenant(slug)
        with tdb.read() as conn:
            if conn is None:
                return {}
            rows = conn.execute(
                "SELECT site_id, vendor, vendor_scope_id FROM site_vendor_ref "
                "WHERE state IN ('auto','confirmed') AND valid_to IS NULL "
                "AND vendor IN ('unifi','nextdns','datto')").fetchall()
    except (sqlite3.Error, EntityPathError, ValueError):
        return {}
    by_site: dict[str, dict[str, set[str]]] = {}
    for r in rows:
        by_site.setdefault(r["site_id"], {}).setdefault(r["vendor"], set()).add(
            str(r["vendor_scope_id"]))
    out: dict[str, dict[str, set[str]]] = {}
    for refs in by_site.values():
        for scope in refs.get("unifi", set()):
            out[scope] = {"nextdns": set(refs.get("nextdns", set())),
                          "datto": set(refs.get("datto", set()))}
    return out


# ---------------------------------------------------------------------------
# Incidents (events.db, 044) — the threat layer's records
# ---------------------------------------------------------------------------

_last_incidents: dict[str, tuple[list[Any], str]] = {}


@dataclass
class IncidentRead:
    incidents: list[Any]
    ok: bool
    stale_since: Optional[str] = None
    """Set when the store could not be read and the last known set is shown."""


def open_incidents(slug: str, now: datetime) -> IncidentRead:
    """The tenant's open incidents and those closed ≤ 30 days ago
    (`status NOT IN ('closed','false_positive') OR closed_at > now-30d`).
    When the store cannot be read, the LAST KNOWN set (with when it was
    read) — an open incident never disappears because a file was busy."""
    from apps.octo.threat import store

    try:
        found = store.open_and_recent(slug, now)
    except (sqlite3.Error, OSError, ValueError) as exc:
        logger.warning("[fleet] incidents of %s not read (%s)", slug, type(exc).__name__)
        held = _last_incidents.get(slug)
        if held is not None:
            return IncidentRead(list(held[0]), False, held[1])
        return IncidentRead([], False, None)
    found = found or []
    _last_incidents[slug] = (found, format_utc_ms(now))
    return IncidentRead(found, True)


def reset_incident_cache() -> None:
    _last_incidents.clear()


def would_fire_counts(slug: str, now: datetime) -> dict[str, int]:
    """rule id → shadow would-fires in the last 24 h (operators only)."""
    from apps.octo.threat import store

    found = store.would_fires(slug, now - timedelta(hours=24)) or []
    out: dict[str, int] = {}
    for w in found:
        out[w["rule_id"]] = out.get(w["rule_id"], 0) + 1
    return out


def canary_touches(slug: str, now: datetime, *, verdicts: Any = None,
                   hidden: Optional[dict[str, int]] = None) -> Optional[int]:
    """Decoy touches in the last 24 h — the buoy layer's Yellow: port touches
    (R6's lesser outcome) AND credential attempts (R6 itself, shadow or
    live): while R6 is in shadow a credential tried on a decoy must never
    read quieter than a port scan of it. `verdicts` (v0.17.2): a PORT TOUCH
    whose alert a human acknowledged is not counted (`hidden["canary"]`); a
    credential attempt always is (R6's input), and a decoy alert is never
    "expected"."""
    from apps.octo.threat import store

    since = now - timedelta(hours=24)
    total = store.fact_counts(slug, ("canary_touch", "canary_credential"), since)
    if total is None or not total or verdicts is None or verdicts.empty:
        return total
    from apps.octo.verdicts import occurrences

    ids = store.fact_event_ids(slug, "canary_touch", since)
    if not ids:
        return total
    rows = occurrences.event_rows(slug, ids)
    gone = 0
    for eid in ids:
        row = rows.get(eid)
        if row is not None and verdicts.state(occurrences.row_occurrence(row)).hidden:
            gone += 1
    if gone and hidden is not None:
        hidden["canary"] = hidden.get("canary", 0) + gone
    return total - gone


def operator_display_names(ids: Any) -> dict[str, str]:
    """operator id (as stored on an incident: a string) → display name, else
    username. {} when unreadable."""
    wanted = sorted({int(i) for i in ids if isinstance(i, str) and i.isdigit()})
    if not wanted:
        return {}
    try:
        reg = connect(paths.registry_db_path(), read_only=True)
    except (sqlite3.Error, FileNotFoundError):
        return {}
    try:
        rows = reg.execute(
            f"SELECT id, COALESCE(NULLIF(display_name, ''), username) FROM operators "
            f"WHERE id IN ({','.join('?' * len(wanted))})", wanted).fetchall()
    except sqlite3.Error:
        return {}
    finally:
        reg.close()
    return {str(r[0]): str(r[1]) for r in rows}
