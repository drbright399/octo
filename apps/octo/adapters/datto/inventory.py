"""The Datto RMM INVENTORY feed (read-only) — per MAPPED Datto site, its
device list, for the Fleet's names and counts (v0.17.2, Rick's decision D:
EVERY Datto-mapped tenant) and for entity resolution (the "NextDNS stopped
reporting from a PC Datto says is online" check; device identity).

  READ   GET /api/v2/site/{siteUid}/devices?max=250[&page=N] — every page
         (250 is the vendor's ceiling), only the allowlisted fields
         (`client.INVENTORY_FIELDS`: uid, hostname, deviceType, online,
         lastSeen, intIpAddress, extIpAddress, operatingSystem, domain).
         NEVER a UDF (they may hold BitLocker recovery keys), never
         lastLoggedInUser, never webRemoteUrl — dropped at the client,
         unread.
  WHO    every site mapped to an ACTIVE tenant — whatever the tenant's entity
         switch (D). What the consumer does with the list is ITS rule: the
         device rows are kept for every tenant; identity LINKING runs only
         for a tenant switched shadow / on (`entity.feeders.datto`). No
         default tenant, no auto-create.
  BUDGET one device-list read per site per 30 minutes (`SITE_MIN_INTERVAL`,
         also the round's floor), paginated. PACE: at least `spacing_sec`
         (1 s) between calls; a site that fails is skipped until the next
         round (the alerts poller is never held). An HTTP 429 ENDS the round
         at once and holds the next ones (Retry-After, else doubling from
         THROTTLE_HOLD to THROTTLE_HOLD_CEILING): Datto blocks an IP that
         keeps calling after a 429, and the alerts poller shares that IP and
         token — the inventory always gives way.
  MAP    each device is mapped to OCSF Device Inventory Info (5001, Discovery
         5, activity Collect 2) HERE, at the adapter boundary (`ocsf_device`),
         and handed to the feed with the site's tenant slug.

  AUDIT  (v0.17.3, Rick's decision A of 2026-10-07: "useful to know what
         device is throwing the alert" — the list has no serial number)
         GET /api/v2/audit/device/{deviceUid}, after the round's lists, for
         the devices of the mapped sites' lists (NOT missing, not an ESXi
         host / printer / network device — they have no `device` audit) whose
         audit was never read or is older than `AUDIT_REFRESH` (7 days) — at
         most `AUDIT_MAX_PER_ROUND` (40) a round, never more often than one
         audit round per 30 minutes, the same spacing between calls. Only
         `client.AUDIT_FIELDS` are kept (the BIOS serial, else the base
         board's; the system manufacturer and model) — never the user name,
         a network interface, a MAC or an address, a UDF, a URL or the
         software (dropped at the client, unread). A placeholder serial ("To
         Be Filled By O.E.M.", "Default string", all zeros, …) is none
         (`audit_record`). An HTTP 429 ends the round and holds the next ones
         exactly like a device-list read (one hold for both); a 401 / 403
         ends the audits of the round (every call would fail alike); any
         other failure is that device's alone — it is tried again NEXT round
         (behind the devices not tried yet), never in a loop. An answer that
         names NONE of the four fields (an error object, another shape) is a
         FAILED audit (`DattoAuditShapeError`), never a stored "no serial":
         nothing is stamped, and the round says so. The serial is keyed by
         the device uid in the tenant's entities.db (`on_audit`). Each round
         logs COUNTS only ("audits read N · serials found M · failed K", and
         "K audits answered in a shape this build does not read" when any
         did) — never a serial, a model or a uid: the first live run is
         checked from those lines (the audit's shape could not be probed
         when this was built).

  SITE IDS (2026-10-08: the Fleet drawer's "Open in Datto RMM — <site>")
         GET /api/v2/account/sites (drained, 250 a page), after the round's
         lists and before the audits, only when `site_ids.due`: at most once
         a day, sooner only when a site was mapped since the last read (one
         try per mapped set a day, failed or not). Keeps the MAPPED sites'
         uid → numeric id (+ name) in adapter_poller_state — see `site_ids`.
         A 429 holds the inventory like any read.

Call math: one call per mapped site per round (two for a site with more than
250 devices) every 30 minutes — e.g. 40 mapped sites ≈ 80 calls an hour —
plus at most 40 audits a round (80 an hour), plus one site-list read a day;
under 3 a minute together, against Datto's documented 600 reads a minute. A
fleet of 2,000 devices is audited in about 25 hours, then ~300 a day (each
again after 7 days).
"""
from __future__ import annotations

import asyncio
import logging
import re
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

from apps.octo import paths
from apps.octo.adapters.datto import feed, site_ids
from apps.octo.adapters.datto.client import (
    DattoAuditShapeError,
    DattoAuthError,
    DattoClient,
    DattoClientError,
    DattoForbiddenError,
    DattoThrottledError,
)
from apps.octo.db import connect
from apps.octo.ingest.timestamps import format_utc_ms, normalize_timestamp

logger = logging.getLogger(__name__)

DEFAULT_INTERVAL_SEC = 1800.0
# One device-list read per site per 30 minutes (Rick, D) — the floor of the
# round interval too.
SITE_MIN_INTERVAL = timedelta(minutes=30)
DEFAULT_SPACING_SEC = 1.0
THROTTLE_HOLD = timedelta(minutes=15)
THROTTLE_HOLD_CEILING = timedelta(hours=2)
# The device audit (serial number): at most this many a round, a device again
# after AUDIT_REFRESH; never more than one audit round per SITE_MIN_INTERVAL.
AUDIT_MAX_PER_ROUND = 40
AUDIT_REFRESH = timedelta(days=7)
# Device types with no `device` audit (they have their own endpoints, or no
# agent): never asked — a call that can only fail would come back every round.
AUDIT_SKIP_TYPES = frozenset({"esxi host", "printer", "network device"})
# Failed audits remembered (in memory) to put them behind the untried ones.
AUDIT_TRIED_MAX = 5000
SERIAL_MAX = 64
HW_TEXT_MAX = 80
# What vendors write when there is no value (case-insensitive, whitespace
# collapsed, trailing dots ignored) — one list for the serial, the
# manufacturer and the model ("System manufacturer", "System Product Name").
PLACEHOLDERS = frozenset({
    "to be filled by o.e.m", "to be filled by oem", "default string", "default",
    "system serial number", "chassis serial number", "base board serial number",
    "serial number", "system manufacturer", "system product name", "system version",
    "0", "none", "null", "nil", "n/a", "na", "not available", "not specified",
    "not applicable", "unknown", "invalid", "empty", "oem", "o.e.m", "undefined",
    "123456789", "0123456789", "1234567890",
})
# All zeros (with separators), or nothing but punctuation / whitespace.
_PLACEHOLDER_RE = re.compile(r"^[0\s._:/-]*$|^[\W_]+$")
OCSF_VERSION = "1.3.0"
PRODUCT = {"name": "Datto RMM", "vendor_name": "Kaseya"}
# Datto deviceType.category → OCSF device type (id, name).
DEVICE_TYPES: dict[str, tuple[int, str]] = {
    "desktop": (2, "Desktop"), "laptop": (3, "Laptop"), "server": (1, "Server"),
    "esxi host": (6, "Virtual"), "virtual machine": (6, "Virtual"), "printer": (99, "Other"),
    "network device": (99, "Other"), "mobile": (5, "Mobile"), "tablet": (4, "Tablet"),
}


def _text(value: Any, limit: int) -> Optional[str]:
    if not isinstance(value, str):
        return None
    flat = " ".join("".join(c if c.isprintable() else " " for c in value).split())
    return flat[:limit] or None


def _ts(value: Any) -> Optional[str]:
    return normalize_timestamp(value, allow_epoch=True, naive_is_utc=True) or None


def ocsf_device(raw: dict[str, Any], *, site_uid: str, polled_at: str,
                audit: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """One Datto device as OCSF Device Inventory Info (5001). With `audit`
    (an `audit_record`): the serial as `device.hw_info.serial_number`, the
    manufacturer as `device.vendor_name`, the model as `device.model` (OCSF
    1.3's names) — only the values the audit actually gave."""
    dtype = (_text(raw.get("deviceType"), 40) or "").lower()
    type_id, type_name = DEVICE_TYPES.get(dtype, (0, "Unknown"))
    last_seen = _ts(raw.get("lastSeen"))
    audit = audit or {}
    device = {k: v for k, v in {
        "uid": _text(raw.get("uid"), 128), "hostname": _text(raw.get("hostname"), 128),
        "type_id": type_id, "type": type_name,
        "os": {"name": _text(raw.get("operatingSystem"), 120)} if raw.get("operatingSystem")
        else None,
        "ip": _text(raw.get("intIpAddress"), 45), "domain": _text(raw.get("domain"), 120),
        "is_managed": True, "last_seen_time_dt": last_seen,
        "org": {"ou_uid": f"datto:{site_uid}"},
        "hw_info": {"serial_number": audit["serial"]} if audit.get("serial") else None,
        "vendor_name": audit.get("manufacturer") or None,
        "model": audit.get("model") or None,
    }.items() if v is not None}
    return {
        "class_uid": 5001, "class_name": "Device Inventory Info",
        "category_uid": 5, "category_name": "Discovery",
        "activity_id": 2, "activity_name": "Collect", "type_uid": 500102,
        "severity_id": 1, "severity": "Informational",
        "time_dt": polled_at,
        "metadata": {"version": OCSF_VERSION, "product": dict(PRODUCT),
                     "labels": [f"datto:{site_uid}"]},
        "device": device,
        "unmapped": {"datto": {"online": raw.get("online") if isinstance(raw.get("online"), bool)
                               else None,
                               "ext_ip": _text(raw.get("extIpAddress"), 45)}},
    }


def record(raw: dict[str, Any], *, site_uid: str, polled_at: str) -> Optional[dict[str, Any]]:
    """The flat record the feed carries (with its OCSF object)."""
    uid = _text(raw.get("uid"), 128)
    if not uid:
        return None
    online = raw.get("online")
    return {
        "uid": uid, "hostname": _text(raw.get("hostname"), 128),
        "device_type": _text(raw.get("deviceType"), 40),
        "online": online if isinstance(online, bool) else None,
        "last_seen": _ts(raw.get("lastSeen")),
        "int_ip": _text(raw.get("intIpAddress"), 45),
        "ext_ip": _text(raw.get("extIpAddress"), 45),
        "os": _text(raw.get("operatingSystem"), 120),
        "domain": _text(raw.get("domain"), 120),
        "ocsf": ocsf_device(raw, site_uid=site_uid, polled_at=polled_at),
    }


def _hw_text(value: Any, limit: int) -> Optional[str]:
    """A cleaned, bounded audit value — None for a placeholder."""
    text = _text(value, limit)
    if text is None:
        return None
    key = " ".join(text.lower().split()).rstrip(".")
    if key in PLACEHOLDERS or _PLACEHOLDER_RE.match(text):
        return None
    return text


def is_placeholder_serial(value: Any) -> bool:
    """True when `value` says nothing about the machine: not a string, empty /
    whitespace, a placeholder, or one character repeated ("XXXXXXXX")."""
    text = _hw_text(value, SERIAL_MAX)
    return text is None or len(set(text.lower())) == 1


def audit_record(raw: dict[str, Any]) -> dict[str, Optional[str]]:
    """{serial, manufacturer, model} from `DattoClient.device_audit`'s four
    values — the BIOS serial, else the base board's; vendor text cleaned and
    bounded; a placeholder is None."""
    serial = None
    for name in ("bios.serialNumber", "baseBoard.serialNumber"):
        value = raw.get(name)
        if not is_placeholder_serial(value):
            serial = _hw_text(value, SERIAL_MAX)
            break
    return {"serial": serial,
            "manufacturer": _hw_text(raw.get("systemInfo.manufacturer"), HW_TEXT_MAX),
            "model": _hw_text(raw.get("systemInfo.model"), HW_TEXT_MAX)}


class InventoryPoller:
    def __init__(
        self,
        *,
        client: DattoClient,
        instance_id: Optional[int],
        interval_sec: float = DEFAULT_INTERVAL_SEC,
        spacing_sec: float = DEFAULT_SPACING_SEC,
        now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        sleep: Callable[[float], None] = time.sleep,
        consumer: Optional[Any] = None,
    ) -> None:
        self._client = client
        self._instance_id = instance_id
        self._interval = max(SITE_MIN_INTERVAL.total_seconds(), float(interval_sec))
        self._spacing = max(0.0, float(spacing_sec))
        self._now = now
        self._sleep = sleep
        self._consumer = consumer
        self._last_call: Optional[float] = None
        self._task: Optional[asyncio.Task] = None
        self._stopping = asyncio.Event()
        self._abort = threading.Event()
        self.rounds = 0
        self.last_round: dict[str, Any] = {}
        self._held_until: Optional[datetime] = None
        self._throttles = 0
        self._last_read: dict[str, datetime] = {}
        self._last_audit_round: Optional[datetime] = None
        # (slug, device uid) → when its audit last FAILED (in memory: after a
        # restart everything due is simply tried again, once).
        self._audit_tried: dict[tuple[str, str], datetime] = {}
        # When the site list was last TRIED, for which mapped uids (in
        # memory: at most one try per mapped set a day, failed or not).
        self._site_ids_tried: Optional[tuple[datetime, frozenset[str]]] = None

    def _feed(self) -> Any:
        return self._consumer if self._consumer is not None else feed.current()

    def mapped_sites(self) -> list[tuple[str, str]]:
        """(site uid, tenant slug) for every site mapped to an ACTIVE tenant."""
        if self._instance_id is None:
            return []
        try:
            reg = connect(paths.registry_db_path(), read_only=True)
            try:
                rows = reg.execute(
                    "SELECT m.vendor_tenant_id, m.octo_client_slug FROM adapter_tenant_map m "
                    "JOIN clients c ON c.slug = m.octo_client_slug WHERE m.adapter_instance_id = ? "
                    "AND c.status = 'active' ORDER BY m.vendor_tenant_id",
                    (self._instance_id,)).fetchall()
            finally:
                reg.close()
        except sqlite3.Error:
            return []
        return [(str(r[0]), str(r[1])) for r in rows]

    def _pace(self) -> None:
        if self._last_call is not None and self._spacing:
            wait = self._spacing - (time.monotonic() - self._last_call)
            if wait > 0:
                self._sleep(wait)
        self._last_call = time.monotonic()

    def _hold(self, exc: DattoThrottledError, out: dict[str, Any]) -> None:
        """HTTP 429 — on a device list or an audit alike: the round ends and
        the next ones wait (Retry-After, else doubling from THROTTLE_HOLD to
        THROTTLE_HOLD_CEILING)."""
        self._throttles += 1
        hold = min(THROTTLE_HOLD_CEILING, THROTTLE_HOLD * (2 ** min(self._throttles - 1, 8)))
        if exc.retry_after_sec:
            hold = max(hold, timedelta(seconds=exc.retry_after_sec))
        self._held_until = self._now() + hold
        out["held_until"] = format_utc_ms(self._held_until)
        logger.warning("[datto-inventory] Datto answered HTTP 429; the round ends and "
                       "the inventory waits %d min (the alerts poller shares the IP)",
                       int(hold.total_seconds() // 60))

    def run_once(self) -> dict[str, Any]:
        """One round over every mapped site (of every tenant — D), then the
        device audits due (`_audits`). Returns {sites, devices, errors,
        skipped, audits}; `skipped` = sites read less than 30 minutes ago
        (the per-site budget). Never raises for one site or one device."""
        consumer = self._feed()
        out: dict[str, Any] = {"sites": 0, "devices": 0, "errors": [], "skipped": 0}
        now = self._now()
        if self._held_until is not None and now < self._held_until:
            out["held_until"] = format_utc_ms(self._held_until)
            self.last_round = {**out, "at": format_utc_ms(now)}
            return out                  # Datto said 429: no call until the hold ends
        throttled = refused = False
        sites = self.mapped_sites()
        for site_uid, slug in sites:
            if self._abort.is_set():
                break
            last = self._last_read.get(site_uid)
            if last is not None and self._now() - last < SITE_MIN_INTERVAL:
                out["skipped"] += 1
                continue
            self._pace()
            self._last_read[site_uid] = self._now()
            polled_at = format_utc_ms(self._now())
            try:
                listing = self._client.site_devices(site_uid)
            except DattoThrottledError as exc:
                out["errors"].append(f"{site_uid}: {type(exc).__name__}")
                self._hold(exc, out)
                throttled = True
                break                       # never the next site after a 429
            except (DattoAuthError, DattoForbiddenError) as exc:
                out["errors"].append(f"{site_uid}: {type(exc).__name__}")
                refused = True
                break                       # the key / user: every site would fail alike
            except (DattoClientError, ValueError) as exc:
                out["errors"].append(f"{site_uid}: {type(exc).__name__}")
                feed.call(consumer, "on_inventory", slug, site_uid, {
                    "instance_id": self._instance_id, "site_uid": site_uid,
                    "polled_at": polled_at, "complete": False, "devices": []})
                continue
            records = [r for r in (record(d, site_uid=site_uid, polled_at=polled_at)
                                   for d in listing.devices) if r is not None]
            feed.call(consumer, "on_inventory", slug, site_uid, {
                "instance_id": self._instance_id, "site_uid": site_uid, "polled_at": polled_at,
                "complete": not listing.truncated, "devices": records})
            out["sites"] += 1
            out["devices"] += len(records)
        if not (throttled or refused or self._abort.is_set()):
            throttled = self._site_ids(sites, out)
        if not (throttled or refused or self._abort.is_set()):
            throttled = self._audits(consumer, sites, out)
        if not throttled and (out["sites"] or (out.get("audits") or {}).get("read")):
            self._throttles = 0
        self.rounds += 1
        self.last_round = {**out, "at": format_utc_ms(self._now())}
        return out

    # ----- the sites' portal ids (the Fleet's "Open in Datto RMM — <site>") -----

    def _site_ids(self, sites: list[tuple[str, str]], out: dict[str, Any]) -> bool:
        """Read the account's site list when `site_ids.due` (none stored, a
        day old, or a site mapped since) — at most one try per mapped set a
        day, failed or not — and keep the MAPPED sites' numeric ids. True
        when a 429 answered (the hold is set, as for any read). Logs counts
        only."""
        if self._instance_id is None:
            return False
        mapped = frozenset(uid for uid, _slug in sites)
        now = self._now()
        tried = self._site_ids_tried
        if tried is not None and mapped <= tried[1] and now - tried[0] < site_ids.REFRESH:
            return False
        previous = site_ids.load(self._instance_id)
        if not site_ids.due(previous, mapped, now):
            return False
        self._site_ids_tried = (now, mapped)
        self._pace()
        try:
            listing = self._client.list_sites_drained()
        except DattoThrottledError as exc:
            out["site_ids"] = {"error": type(exc).__name__}
            self._hold(exc, out)
            return True
        except (DattoAuthError, DattoClientError, ValueError) as exc:
            out["site_ids"] = {"error": type(exc).__name__}
            logger.warning("[datto-inventory] the site list was not read (%s): the sites' "
                           "portal links stay on the portal home until the next try",
                           type(exc).__name__)
            return False
        found = site_ids.extract(listing.sites, mapped)
        site_ids.save(self._instance_id, mapped=mapped, found=found, now=now,
                      previous=previous, complete=not listing.truncated)
        out["site_ids"] = {"mapped": len(mapped), "found": len(found)}
        logger.info("[datto-inventory] site portal ids: %d of %d mapped sites",
                    len(found), len(mapped))
        return False

    # ----- the device audits (serial number, manufacturer, model) -----

    def _audit_candidates(self, consumer: Any, sites: list[tuple[str, str]],
                          now: datetime) -> list[tuple[str, str, str]]:
        """(slug, device uid, site uid) of the devices due an audit, in the
        order they are read: the ones whose audit never failed before the
        ones that failed (the longest ago first), then never audited before
        the oldest audit."""
        by_slug: dict[str, list[str]] = {}
        for site_uid, slug in sites:
            by_slug.setdefault(slug, []).append(site_uid)
        before = format_utc_ms(now - AUDIT_REFRESH)
        floor = datetime.min.replace(tzinfo=timezone.utc)
        ranked: list[tuple[datetime, str, str, str, str]] = []
        for slug, site_uids in sorted(by_slug.items()):
            # Enough rows that the devices that failed cannot crowd out the
            # ones never tried.
            tried_here = sum(1 for (s, _u) in self._audit_tried if s == slug)
            limit = min(AUDIT_MAX_PER_ROUND + tried_here, AUDIT_TRIED_MAX)
            due = feed.call(consumer, "audit_due", slug, self._instance_id, sorted(site_uids),
                            before, limit, sorted(AUDIT_SKIP_TYPES), default=None)
            for item in due if isinstance(due, list) else []:
                if not (isinstance(item, (tuple, list)) and len(item) >= 3):
                    continue
                uid, site_uid, audit_at = item[0], item[1], item[2]
                if not isinstance(uid, str) or not isinstance(site_uid, str):
                    continue
                ranked.append((self._audit_tried.get((slug, uid), floor),
                               audit_at if isinstance(audit_at, str) else "", slug, uid,
                               site_uid))
        ranked.sort()
        return [(slug, uid, site_uid) for _t, _a, slug, uid, site_uid in ranked]

    def _audits(self, consumer: Any, sites: list[tuple[str, str]],
                out: dict[str, Any]) -> bool:
        """At most AUDIT_MAX_PER_ROUND device audits, at most once per 30
        minutes. True when a 429 ended them (the hold is set — the same one
        the device lists obey). Logs COUNTS only — never a serial, a model or
        a uid."""
        now = self._now()
        if self._last_audit_round is not None and \
                now - self._last_audit_round < SITE_MIN_INTERVAL:
            return False
        self._last_audit_round = now
        cutoff = now - AUDIT_REFRESH
        self._audit_tried = {k: t for k, t in self._audit_tried.items() if t >= cutoff}
        stats = {"read": 0, "serials": 0, "failed": 0}
        out["audits"] = stats
        throttled = False
        unread = 0                          # of `failed`: an answer in another shape
        due = self._audit_candidates(consumer, sites, now)[:AUDIT_MAX_PER_ROUND]
        for slug, uid, site_uid in due:
            if self._abort.is_set():
                break
            self._pace()
            try:
                raw = self._client.device_audit(uid)
            except DattoThrottledError as exc:
                stats["failed"] += 1
                self._audit_tried[(slug, uid)] = self._now()
                self._hold(exc, out)
                throttled = True
                break                       # never the next device after a 429
            except (DattoAuthError, DattoForbiddenError):
                stats["failed"] += 1
                self._audit_tried[(slug, uid)] = self._now()
                break                       # the key / user: every audit would fail alike
            except DattoAuditShapeError:
                # Not "no serial": nothing stamped, again next round (behind
                # the untried ones) — and the round says so.
                stats["failed"] += 1
                unread += 1
                self._audit_tried[(slug, uid)] = self._now()
                continue
            except (DattoClientError, ValueError):
                stats["failed"] += 1
                self._audit_tried[(slug, uid)] = self._now()
                continue                    # this device only: again next round
            audited_at = format_utc_ms(self._now())
            rec = audit_record(raw)
            stored = feed.call(consumer, "on_audit", slug, {
                "instance_id": self._instance_id, "site_uid": site_uid, "device_uid": uid,
                "audited_at": audited_at, **rec,
                "ocsf": ocsf_device({"uid": uid}, site_uid=site_uid, polled_at=audited_at,
                                    audit=rec)})
            if not stored:
                stats["failed"] += 1        # not kept: due again next round
                self._audit_tried[(slug, uid)] = self._now()
                continue
            self._audit_tried.pop((slug, uid), None)
            stats["read"] += 1
            stats["serials"] += 1 if rec["serial"] else 0
        if len(self._audit_tried) > AUDIT_TRIED_MAX:
            newest = sorted(self._audit_tried.items(), key=lambda kv: kv[1])[-AUDIT_TRIED_MAX:]
            self._audit_tried = dict(newest)
        logger.info("[datto-inventory] audits read %d · serials found %d · failed %d",
                    stats["read"], stats["serials"], stats["failed"])
        if unread:
            logger.warning("[datto-inventory] %d audits answered in a shape this build does "
                           "not read (no bios / baseBoard serialNumber, no systemInfo "
                           "manufacturer / model) — counted as failed, nothing stored", unread)
        return throttled

    # ----- async lifecycle (beside the alerts poller, on the API's loop) -----

    async def start(self) -> None:
        if self._task is not None and not self._task.done():
            return
        self._stopping.clear()
        self._abort.clear()
        self._task = asyncio.create_task(self._run(), name="datto-inventory")

    async def stop(self) -> None:
        if self._task is None:
            return
        self._stopping.set()
        self._abort.set()
        try:
            await asyncio.wait_for(self._task, timeout=15.0)
        except asyncio.TimeoutError:
            self._task.cancel()
        self._task = None

    async def _run(self) -> None:
        while not self._stopping.is_set():
            try:
                await asyncio.to_thread(self.run_once)
            except Exception as exc:  # noqa: BLE001
                logger.warning("[datto-inventory] round failed (%s)", type(exc).__name__)
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=self._interval)
            except asyncio.TimeoutError:
                pass

    def next_due(self) -> datetime:
        return self._now() + timedelta(seconds=self._interval)
