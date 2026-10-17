"""The device-silence check — "NextDNS stopped reporting from a PC that Datto
says is online" (Rick, 2026-10-01: at one client the NextDNS app stopped
silently on all 4 PCs between 09-19 and 09-29, and nothing said so).

For every LINKED pair (NextDNS app device ↔ Datto device, `device_link`
state auto or confirmed — a name-only suggestion is not watched until an
operator confirms it), in ONE tenant:

  SILENT when ALL of:
    * the NextDNS device has an established baseline: queries in at least
      BASELINE_HOURS read hours over at least BASELINE_DAYS distinct days in
      the last 14 days, OR — for a device whose app was ALREADY dead when the
      client was switched on — at least SEED_MIN_QUERIES queries on each of
      BASELINE_DAYS distinct days of the profile's 14-day SEED (read once,
      per UTC day, when the feed starts: `ndns_device_day`) (a device seen
      once is not "normally reporting");
    * the last SILENT_HOURS hours of its profile were READ and read WHOLE
      (an unread hour, or a sampled hour the device might have been missed
      in, breaks the run — unknown is never silent) and the device has 0
      queries in every one of them;
    * Datto shows the computer online, continuously since before the silent
      run began (`online_since`), with a fresh inventory (its site's Datto
      watermark within DATTO_FRESH).
  → ONE `nextdns.device_silent` alert (MEDIUM) per episode; the payload says
    when the whole profile is silent too (then the profile's own lapse alert
    is the root cause).
  RESTORED when the device reports again in any read hour after the silence
  began → ONE `nextdns.device_restored` (LOW) naming the silent alert.

The alert says when the device LAST reported (an hour, or a seed day) and
how long the silence has been VERIFIED (read hours with Datto online) —
never just "4 hours".

The switch: in `shadow` the state is tracked but no alert is raised; in `on`
the alert goes to the NextDNS poller's outbox (`device_watch.pending_*`),
which stores it (with its OCSF mapping) and confirms — exactly once. A
silence that began in shadow (or before the switch went on) and still holds
when the switch is `on` raises its alert then (Datto must still vouch for
it).
"""
from __future__ import annotations

import json
import sqlite3
from datetime import timedelta
from typing import Any, Optional

from apps.octo import paths
from apps.octo.entity import intervals as iv
from apps.octo.entity import normalize as nz

SILENT_HOURS = 4
BASELINE_HOURS = 8
BASELINE_DAYS = 2
BASELINE_WINDOW_DAYS = 14
SEED_MIN_QUERIES = 20
DATTO_FRESH = timedelta(minutes=45)


def _hours_back(last_hour: str, n: int) -> list[str]:
    return [nz.hour_start(nz.shift(last_hour, -3600 * i)) for i in range(n)][::-1]


def _profile_silent_too(slug: str, profile_id: str, hours: list[str]) -> bool:
    """Whether the profile's own hourly roll-ups (telemetry.db) show 0 queries
    for every one of `hours` — read-only, never creates the file."""
    path = paths.client_dir(slug) / "telemetry.db"
    if not path.exists():
        return False
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5.0)
    except sqlite3.Error:
        return False
    try:
        keys = [h[:19] + "Z" for h in hours]
        marks = ",".join("?" * len(keys))
        rows = conn.execute(f"SELECT hour, queries FROM nextdns_hourly WHERE profile_id = ? AND "
                            f"hour IN ({marks})", (profile_id, *keys)).fetchall()
    except sqlite3.Error:
        return False
    finally:
        conn.close()
    return len(rows) == len(keys) and all(int(r[1] or 0) == 0 for r in rows)


def _datto_vouches(conn: sqlite3.Connection, dd: sqlite3.Row, since: str, now: str) -> bool:
    """Datto shows the computer online, continuously since before `since`,
    with a fresh inventory of its site."""
    if not dd["online"] or not dd["online_since"] or dd["online_since"] > since:
        return False
    wm = iv.watermark(conn, "datto.devices", dd["site_uid"])
    fresh_at = wm["last_ok_at"] if wm is not None else None
    return bool(fresh_at) and nz.seconds_between(fresh_at, now) <= DATTO_FRESH.total_seconds()


def _silent_payload(slug: str, facts: dict[str, Any], *, pid: str, since: str, last_read: str,
                    window: list[str]) -> dict[str, Any]:
    hours_silent = int(nz.seconds_between(since, nz.shift(last_read, 3600)) // 3600)
    return {**facts, "kind": "device_silent", "silent_since": since,
            "silent_hours": hours_silent, "detected_at": nz.shift(last_read, 3600),
            "profile_silent_too": _profile_silent_too(slug, pid, window)}


def evaluate(conn: sqlite3.Connection, slug: str, *, mode: str, now: str,
             silent_hours: int = SILENT_HOURS) -> list[dict[str, Any]]:
    """Run the check for every watched link of the tenant. Returns the
    transitions (for tests / the run log)."""
    out: list[dict[str, Any]] = []
    links = conn.execute(
        "SELECT * FROM device_link WHERE state IN ('auto','confirmed') AND valid_to IS NULL "
        "ORDER BY id").fetchall()
    for link in links:
        pid, _, did = link["a_value"].partition(":")
        inst, _, uid = link["b_value"].partition(":")
        nd = conn.execute("SELECT * FROM ndns_device WHERE profile_id = ? AND device_id = ?",
                          (pid, did)).fetchone()
        dd = conn.execute("SELECT * FROM inv_device WHERE adapter_instance_id = ? AND "
                          "device_uid = ?", (int(inst or 0), uid)).fetchone()
        if nd is None or dd is None:
            continue
        watch = conn.execute("SELECT * FROM device_watch WHERE link_id = ?",
                             (link["id"],)).fetchone()
        if watch is None:
            conn.execute("INSERT INTO device_watch (link_id, state, updated_at) VALUES (?, 'ok', ?)",
                         (link["id"], now))
            watch = conn.execute("SELECT * FROM device_watch WHERE link_id = ?",
                                 (link["id"],)).fetchone()
        last_read = conn.execute(
            "SELECT MAX(hour) FROM ndns_presence_hour WHERE profile_id = ?", (pid,)).fetchone()[0]
        if not last_read:
            continue
        active = [r["hour"] for r in conn.execute(
            "SELECT hour FROM ndns_device_hour WHERE profile_id = ? AND device_id = ? AND "
            "queries > 0 ORDER BY hour", (pid, did)).fetchall()]
        seed_days = [r["day"] for r in conn.execute(
            "SELECT day FROM ndns_device_day WHERE profile_id = ? AND device_id = ? AND "
            "queries >= ? ORDER BY day", (pid, did, SEED_MIN_QUERIES)).fetchall()]
        last_active = active[-1] if active else None
        # When the device LAST reported: an hour it was read in, else the
        # last day of the seed it had queries on.
        if last_active and (not seed_days or last_active[:10] >= seed_days[-1]):
            last_report, precision = last_active, "hour"
        elif seed_days:
            last_report, precision = seed_days[-1], "day"
        else:
            last_report, precision = None, None
        facts = {"profile_id": pid, "profile_name": None,
                 "device": {"id": did, "name": nd["name"], "model": nd["model"]},
                 "datto": {"hostname": dd["hostname"], "device_uid": dd["device_uid"],
                           "os": dd["os"], "online_since": dd["online_since"],
                           "last_seen": dd["last_seen"]},
                 "link_state": link["state"], "link_rule": link["rule_id"],
                 "last_report": last_report, "last_report_precision": precision}
        if watch["state"] == "silent":
            since = watch["since"]
            if last_active and since and last_active >= since:
                payload = None
                if mode == "on" and watch["alert_event_id"] is not None:
                    payload = {**facts, "kind": "device_restored", "restored_hour": last_active,
                               "silent_since": since, "silent_event_id": watch["alert_event_id"],
                               "detected_at": nz.shift(last_active, 3600)}
                conn.execute(
                    "UPDATE device_watch SET state = 'ok', since = NULL, last_report_hour = ?, "
                    " pending_kind = ?, pending_payload = ?, updated_at = ? WHERE link_id = ?",
                    (last_active, "device_restored" if payload else None,
                     json.dumps(payload, sort_keys=True) if payload else None, now, link["id"]))
                out.append({"link_id": link["id"], "to": "ok", "alert": bool(payload)})
            elif mode == "on" and since and watch["alert_event_id"] is None \
                    and watch["pending_payload"] is None and _datto_vouches(conn, dd, since, now):
                # The silence began while the switch was shadow (or before it
                # was on) and still holds now that it is on: raise it now.
                window = _hours_back(last_read, silent_hours)
                payload = _silent_payload(slug, facts, pid=pid, since=since, last_read=last_read,
                                          window=window)
                conn.execute(
                    "UPDATE device_watch SET pending_kind = 'device_silent', pending_payload = ?, "
                    " updated_at = ? WHERE link_id = ?",
                    (json.dumps(payload, sort_keys=True), now, link["id"]))
                out.append({"link_id": link["id"], "to": "silent", "since": since, "alert": True})
            continue
        # state ok → silent?
        window = _hours_back(last_read, silent_hours)
        rows = {r["hour"]: r for r in conn.execute(
            f"SELECT hour, complete FROM ndns_presence_hour WHERE profile_id = ? AND hour IN "
            f"({','.join('?' * len(window))})", (pid, *window)).fetchall()}
        if len(rows) < silent_hours or not all(int(rows[h]["complete"]) for h in window):
            continue                                    # unknown hours: never silent
        if any(h in active for h in window):
            continue
        since_floor = nz.shift(nz.day_start(window[0]), -BASELINE_WINDOW_DAYS * 86400)
        recent = [h for h in active if since_floor <= h < window[0]]
        seeded = [d for d in seed_days if since_floor[:10] <= d < window[0][:10]]
        hourly_baseline = len(recent) >= BASELINE_HOURS and \
            len({h[:10] for h in recent}) >= BASELINE_DAYS
        if not hourly_baseline and len(set(seeded)) < BASELINE_DAYS:
            continue                                    # no established baseline
        # The VERIFIED silent run starts at the window (earlier hours may not
        # have been read whole); the device's last report is said separately.
        since = window[0]
        if not _datto_vouches(conn, dd, since, now):
            continue                                    # Datto does not vouch for the window
        payload = None
        if mode == "on":
            payload = _silent_payload(slug, facts, pid=pid, since=since, last_read=last_read,
                                      window=window)
        conn.execute(
            "UPDATE device_watch SET state = 'silent', since = ?, last_report_hour = ?, "
            " alert_event_id = NULL, restore_event_id = NULL, pending_kind = ?, "
            " pending_payload = ?, updated_at = ? WHERE link_id = ?",
            (since, last_report, "device_silent" if payload else None,
             json.dumps(payload, sort_keys=True) if payload else None, now, link["id"]))
        out.append({"link_id": link["id"], "to": "silent", "since": since, "alert": bool(payload)})
    return out


def pending(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    out = []
    for r in conn.execute("SELECT link_id, pending_kind, pending_payload FROM device_watch "
                          "WHERE pending_payload IS NOT NULL ORDER BY link_id").fetchall():
        try:
            payload = json.loads(r["pending_payload"])
        except ValueError:
            continue
        if not isinstance(payload, dict):
            continue
        payload["key"] = f"watch:{r['link_id']}:{r['pending_kind']}:" \
                         f"{payload.get('silent_since') or ''}"
        out.append(payload)
    return out


def stored(conn: sqlite3.Connection, key: str, event_id: int) -> Optional[int]:
    parts = key.split(":")
    if len(parts) < 3 or parts[0] != "watch" or not parts[1].isdigit():
        return None
    link_id, kind = int(parts[1]), parts[2]
    column = "alert_event_id" if kind == "device_silent" else "restore_event_id"
    conn.execute(f"UPDATE device_watch SET {column} = ?, pending_kind = NULL, "
                 f"pending_payload = NULL WHERE link_id = ? AND pending_kind = ?",
                 (int(event_id), link_id, kind))
    return link_id
