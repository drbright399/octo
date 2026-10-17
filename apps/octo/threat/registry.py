"""The registry facts the tier rules read (migration 044, registry section).

  asset tags        (tenant, device | path, ref, tag). `life_safety` FIRST
                    (Rick, 2026-10-02 23:21): "911 and life saving systems
                    should NEVER be blocked" — every lockdown request carves
                    the tagged assets and their paths out (`lockdown.py`).
                    Tags cap RESPONSE, never detection, except `lab` (capped
                    at Notice) and `evidence_hold` (excluded) — P6 / G5.
                    Who may set what: `life_safety` (and the other
                    response-only caps: cjis, patient_care, critical_24x7,
                    server, dc) — analyst+, because a protective tag never
                    hides anything; the tags that SUPPRESS detection (lab,
                    evidence_hold, dev, kiosk, hands_off) — admin+. Clearing
                    any tag — admin+ (it removes a protection). Every change
                    is audited BEFORE the write, with a reason; a tag is
                    cleared, never deleted.
  analyst verdicts  a false-positive close's exact key — blocks that key from
                    re-firing or reopening for 365 d.
  exceptions        super_admin + step-up, ≤ 90 d (read here; the rules that
                    honour them come with slice 2+).
  canary allowlist  the scanners allowed to touch a buoy's canary (N15) — R6's
                    precondition.
  tier settings     the Yellow / Notice knobs, BOUNDED here: no value can name
                    Red or Black, and no key reaches a Red or Black rule.
  worker state      the tier worker's heartbeat and per-tenant cursors.

Every reader is fail-soft where a page depends on it (a registry fault reads
as "nothing configured", which only ever makes things LOUDER: a missing
life-safety tag list makes a lockdown request refuse rather than include).
"""
from __future__ import annotations

import json
import logging
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from apps.octo import paths
from apps.octo.db import connect, transaction
from apps.octo.fleet.state import KNOB_DEFAULTS
from apps.octo.ingest.timestamps import format_utc_ms

logger = logging.getLogger(__name__)

TAGS = ("lab", "evidence_hold", "dev", "kiosk", "hands_off", "server", "dc", "cjis",
        "life_safety", "patient_care", "critical_24x7")
LIFE_SAFETY = "life_safety"
# Tags that only cap RESPONSE (never hide a detection): an analyst may set them.
PROTECTIVE_TAGS = ("life_safety", "cjis", "patient_care", "critical_24x7", "server", "dc")
# Tags that change what DETECTION does: admin+ only.
SUPPRESSIVE_TAGS = ("lab", "evidence_hold", "dev", "kiosk", "hands_off")
REF_KINDS = ("device", "path")
VERDICT_DAYS = 365
EXCEPTION_MAX_DAYS = 90


def _now_s(now: Optional[datetime] = None) -> str:
    return format_utc_ms(now or datetime.now(timezone.utc))


class RegistryUnavailable(Exception):
    """The registry could not be read (callers that must fail CLOSED raise)."""


# ---------------------------------------------------------------------------
# Asset tags
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AssetTag:
    id: int
    tenant_slug: str
    ref_kind: str
    device_ref: str
    tag: str
    set_by: int
    set_at: str
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {"id": self.id, "tenant_slug": self.tenant_slug, "ref_kind": self.ref_kind,
                "device_ref": self.device_ref, "tag": self.tag, "set_by": self.set_by,
                "set_at": self.set_at, "reason": self.reason}


def _tag(r: sqlite3.Row) -> AssetTag:
    return AssetTag(int(r["id"]), r["tenant_slug"], r["ref_kind"], r["device_ref"], r["tag"],
                    int(r["set_by"]), r["set_at"], r["reason"])


def asset_tags(slug: Optional[str] = None, *, tag: Optional[str] = None,
               strict: bool = False) -> list[AssetTag]:
    """Live (not cleared) tags, of one tenant or all. `strict`: a registry
    fault raises RegistryUnavailable instead of reading as none (the
    lockdown path must fail closed)."""
    sql = "SELECT * FROM asset_tag WHERE cleared_at IS NULL"
    args: list[Any] = []
    if slug is not None:
        sql += " AND tenant_slug = ?"
        args.append(slug)
    if tag is not None:
        sql += " AND tag = ?"
        args.append(tag)
    sql += " ORDER BY tenant_slug, ref_kind, device_ref, tag"
    try:
        reg = connect(paths.registry_db_path(), read_only=True)
        try:
            return [_tag(r) for r in reg.execute(sql, args).fetchall()]
        finally:
            reg.close()
    except sqlite3.Error as exc:
        if strict:
            raise RegistryUnavailable(type(exc).__name__) from None
        logger.warning("[threat-registry] asset tags not read (%s)", type(exc).__name__)
        return []


def life_safety(slug: str) -> list[AssetTag]:
    """The tenant's life-safety assets and paths — FAIL CLOSED (raises
    RegistryUnavailable): a lockdown request built without this list could
    include a 911 system."""
    return asset_tags(slug, tag=LIFE_SAFETY, strict=True)


def tags_for(slug: str, device_ref: Optional[str]) -> set[str]:
    """The tags on one device — matched by CANONICAL identity (`identity`:
    the short host name, case-blind; an address against a tagged address or
    path), never by spelling: `dispatch-01.example.local` carries the tags
    of a tagged `DISPATCH-01`."""
    from apps.octo.threat.identity import same_host

    if not device_ref:
        return set()
    return {t.tag for t in asset_tags(slug) if same_host(t.device_ref, device_ref)}


def validate_tag(*, ref_kind: str, device_ref: str, tag: str) -> None:
    """Raises ValueError for a tag that cannot be written (the API checks it
    BEFORE its audit row)."""
    from apps.octo.threat.identity import canonical

    if tag not in TAGS:
        raise ValueError(f"tag must be one of {', '.join(TAGS)}")
    if ref_kind not in REF_KINDS:
        raise ValueError("ref_kind must be 'device' or 'path'")
    if tag == LIFE_SAFETY:
        # The carve-out compares canonical identities: a life-safety tag
        # must HAVE one, or no lockdown target could ever be checked
        # against it. A device: a host name or an address; a path: an
        # address or a network (CIDR).
        ident = canonical(device_ref)
        if ref_kind == "path" and (ident is None or ident.kind != "net"):
            raise ValueError("a life-safety path is an address or a network (e.g. "
                             "192.0.2.0/24)")
        if ref_kind == "device" and ident is None:
            raise ValueError("a life-safety device is a host name or an address (not a "
                             "vendor id or free text)")


def add_tag(conn: sqlite3.Connection, *, slug: str, ref_kind: str, device_ref: str, tag: str,
            set_by: int, reason: str, now: Optional[datetime] = None) -> int:
    """Inside the caller's registry transaction. Raises ValueError on a bad
    value, sqlite3.IntegrityError when the same tag is already live."""
    validate_tag(ref_kind=ref_kind, device_ref=device_ref, tag=tag)
    cur = conn.execute(
        "INSERT INTO asset_tag (tenant_slug, ref_kind, device_ref, tag, set_by, set_at, reason) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (slug, ref_kind, device_ref.strip(), tag, set_by, _now_s(now), reason))
    return int(cur.lastrowid)


def get_tag(conn: sqlite3.Connection, tag_id: int) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM asset_tag WHERE id = ?", (tag_id,)).fetchone()


def clear_tag(conn: sqlite3.Connection, tag_id: int, *, by: int, reason: str,
              now: Optional[datetime] = None) -> bool:
    return conn.execute(
        "UPDATE asset_tag SET cleared_by = ?, cleared_at = ?, clear_reason = ? "
        "WHERE id = ? AND cleared_at IS NULL", (by, _now_s(now), reason, tag_id),
    ).rowcount == 1


# ---------------------------------------------------------------------------
# Analyst verdicts, exceptions, the remote-access registry (read views)
# ---------------------------------------------------------------------------

def verdict_blocks(slug: str, key: str, now: Optional[datetime] = None) -> bool:
    """A live analyst verdict on this exact key blocks re-firing and
    reopening. A registry fault reads as NOT blocked (louder, never
    quieter)."""
    try:
        reg = connect(paths.registry_db_path(), read_only=True)
        try:
            row = reg.execute(
                "SELECT 1 FROM analyst_verdict WHERE tenant_slug = ? AND verdict_key = ? "
                "AND void_at IS NULL AND expires_at > ? LIMIT 1",
                (slug, key, _now_s(now))).fetchone()
        finally:
            reg.close()
    except sqlite3.Error:
        return False
    return row is not None


def add_verdict(conn: sqlite3.Connection, *, slug: str, device_ref: Optional[str], key: str,
                rule_id: str, incident_id: int, reason: str, by: int,
                now: Optional[datetime] = None) -> int:
    at = now or datetime.now(timezone.utc)
    cur = conn.execute(
        "INSERT INTO analyst_verdict (tenant_slug, device_ref, verdict_key, rule_id, "
        "incident_id, reason, created_by, created_at, expires_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (slug, device_ref, key, rule_id, incident_id, reason, by, _now_s(at),
         _now_s(at + timedelta(days=VERDICT_DAYS))))
    return int(cur.lastrowid)


def rows(table: str, *, slug: Optional[str] = None, live_only: bool = False,
         limit: int = 500) -> list[dict[str, Any]]:
    """A read view of one registry table (admin UI). `slug` filters by the
    tenant column; '*' rows (MSP-global) are always included."""
    live = {
        "threat_exception": "revoked_at IS NULL",
        "analyst_verdict": "void_at IS NULL",
        "remote_access_registry": "ended_at IS NULL",
        "canary_scanner_allowlist": "removed_at IS NULL",
    }
    if table not in ("threat_exception", "analyst_verdict", "remote_access_registry",
                     "canary_scanner_allowlist"):
        raise ValueError("not a readable registry table")
    where, args = [], []
    if slug is not None:
        where.append("(tenant_slug = ? OR tenant_slug = '*')")
        args.append(slug)
    if live_only:
        where.append(live[table])
    sql = f"SELECT * FROM {table}" + (" WHERE " + " AND ".join(where) if where else "") + \
        " ORDER BY id DESC LIMIT ?"
    try:
        reg = connect(paths.registry_db_path(), read_only=True)
        try:
            return [dict(r) for r in reg.execute(sql, (*args, limit)).fetchall()]
        finally:
            reg.close()
    except sqlite3.Error as exc:
        logger.warning("[threat-registry] %s not read (%s)", table, type(exc).__name__)
        return []


def add_exception(conn: sqlite3.Connection, *, slug: str, binding_kind: str, binding: str,
                  rule_id: str, reason: str, by: int, days: int,
                  now: Optional[datetime] = None) -> int:
    if not 1 <= int(days) <= EXCEPTION_MAX_DAYS:
        raise ValueError(f"an exception lasts 1..{EXCEPTION_MAX_DAYS} days")
    at = now or datetime.now(timezone.utc)
    cur = conn.execute(
        "INSERT INTO threat_exception (tenant_slug, binding_kind, binding, rule_id, reason, "
        "created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (slug, binding_kind, binding, rule_id, reason, by, _now_s(at),
         _now_s(at + timedelta(days=int(days)))))
    return int(cur.lastrowid)


def revoke_exception(conn: sqlite3.Connection, exc_id: int, *, by: int, reason: str,
                     now: Optional[datetime] = None) -> bool:
    return conn.execute(
        "UPDATE threat_exception SET revoked_at = ?, revoked_by = ?, revoke_reason = ? "
        "WHERE id = ? AND revoked_at IS NULL", (_now_s(now), by, reason, exc_id)).rowcount == 1


# ---------------------------------------------------------------------------
# Canary scanner allowlist (N15)
# ---------------------------------------------------------------------------

def canary_allowlist(slug: str) -> Optional[set[str]]:
    """The tenant's allowed scanner IPs; None when unreadable (R6 then
    treats coverage as unknown — never "nothing is allowed")."""
    try:
        reg = connect(paths.registry_db_path(), read_only=True)
        try:
            found = reg.execute(
                "SELECT ip FROM canary_scanner_allowlist WHERE tenant_slug = ? "
                "AND removed_at IS NULL", (slug,)).fetchall()
        finally:
            reg.close()
    except sqlite3.Error:
        return None
    return {str(r[0]).strip() for r in found}


def add_allowlist(conn: sqlite3.Connection, *, slug: str, ip: str, label: str, by: int,
                  now: Optional[datetime] = None) -> int:
    cur = conn.execute(
        "INSERT INTO canary_scanner_allowlist (tenant_slug, ip, label, added_by, added_at) "
        "VALUES (?, ?, ?, ?, ?)", (slug, ip.strip(), label, by, _now_s(now)))
    return int(cur.lastrowid)


# ---------------------------------------------------------------------------
# Tier settings — bounded Yellow / Notice knobs only
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Knob:
    key: str
    default: Any
    choices: Optional[tuple[str, ...]] = None
    low: Optional[int] = None
    high: Optional[int] = None
    help: str = ""

    def valid(self, value: Any) -> Any:
        if self.choices is not None:
            if value not in self.choices:
                raise ValueError(f"{self.key} must be one of {', '.join(self.choices)}")
            return value
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{self.key} must be a whole number")
        if not (self.low <= value <= self.high):  # type: ignore[operator]
            raise ValueError(f"{self.key} must be between {self.low} and {self.high}")
        return value


# Every knob tunes Yellow ↔ Notice or a duration — none can name Red or
# Black, and none is read by a Red or Black rule (rules.py takes no
# settings at all).
KNOBS: dict[str, Knob] = {k.key: k for k in (
    Knob("issues_recur_entries", KNOB_DEFAULTS["issues_recur_entries"], low=2, high=10,
         help="new internet-issue entries in an hour that make a WARN"),
    Knob("server_offline_grace_min", KNOB_DEFAULTS["server_offline_grace_min"], low=0, high=60,
         help="minutes a server may be offline before it warns"),
    # (`dns_medium_level` is retired in v0.17.1: the daily DNS block count is
    # always a Notice — Rick, 2026-10-06, A1. A stored value is ignored.)
    Knob("dns_beacon_hours", KNOB_DEFAULTS["dns_beacon_hours"], low=2, high=12,
         help="distinct clock hours in 24 h with high-risk DNS blocks on ONE device that "
              "make it Yellow (repeated lookups — possible infection)"),
    Knob("ips_inbound_blocked_level", KNOB_DEFAULTS["ips_inbound_blocked_level"], choices=("notice", "warn"),
         help="IPS hits blocked on the way IN"),
    Knob("nextdns_pending_days", KNOB_DEFAULTS["nextdns_pending_days"], low=3, high=14,
         help="days a newly mapped NextDNS profile may stay pending as a notice"),
    Knob("watch_days", KNOB_DEFAULTS["watch_days"], low=3, high=30,
         help="days of Yellow post-incident watch after a true-positive close"),
    Knob("primary_on_backup_level", KNOB_DEFAULTS["primary_on_backup_level"],
         choices=("notice", "warn"),
         help="the primary internet line down while a backup carries the site"),
    Knob("critical_notifications_level", KNOB_DEFAULTS["critical_notifications_level"],
         choices=("notice", "warn"),
         help="UniFi critical notifications (vendor-rated, not a threat verdict)"),
)}


def defaults() -> dict[str, Any]:
    return {k: v.default for k, v in KNOBS.items()}


def settings(slug: Optional[str] = None) -> dict[str, Any]:
    """The effective knobs: defaults ← MSP ('msp') ← the tenant's own. A
    stored value that is no longer valid falls back to the layer below."""
    out = defaults()
    try:
        reg = connect(paths.registry_db_path(), read_only=True)
        try:
            scopes = ["msp"] + ([slug] if slug else [])
            found = reg.execute(
                f"SELECT scope, key, value_json FROM tier_settings WHERE scope IN "
                f"({','.join('?' * len(scopes))})", scopes).fetchall()
        finally:
            reg.close()
    except sqlite3.Error:
        return out
    for scope in ["msp"] + ([slug] if slug else []):
        for r in found:
            if r["scope"] != scope or r["key"] not in KNOBS:
                continue
            try:
                out[r["key"]] = KNOBS[r["key"]].valid(json.loads(r["value_json"]))
            except (ValueError, TypeError):
                continue
    return out


def stored_settings(scope: str) -> dict[str, Any]:
    try:
        reg = connect(paths.registry_db_path(), read_only=True)
        try:
            found = reg.execute("SELECT key, value_json FROM tier_settings WHERE scope = ?",
                                (scope,)).fetchall()
        finally:
            reg.close()
    except sqlite3.Error:
        return {}
    out = {}
    for r in found:
        try:
            out[r["key"]] = json.loads(r["value_json"])
        except ValueError:
            continue
    return out


def put_settings(conn: sqlite3.Connection, scope: str, values: dict[str, Any], *, by: int,
                 now: Optional[datetime] = None) -> None:
    for key, value in values.items():
        if key not in KNOBS:
            raise ValueError(f"unknown setting {key!r}")
        KNOBS[key].valid(value)
    for key, value in values.items():
        conn.execute(
            "INSERT INTO tier_settings (scope, key, value_json, updated_by, updated_at) "
            "VALUES (?, ?, ?, ?, ?) ON CONFLICT (scope, key) DO UPDATE SET "
            "value_json = excluded.value_json, updated_by = excluded.updated_by, "
            "updated_at = excluded.updated_at",
            (scope, key, json.dumps(value), by, _now_s(now)))


# ---------------------------------------------------------------------------
# Restricted incidents (B7, CSAM) — the MSP's client-notice switch
# ---------------------------------------------------------------------------

# Rick, 2026-10-06 (B6): "controlled by a setting (per MSP, default OFF =
# suppressed)". NOT a knob: it never tunes a colour; it decides whether a
# CLIENT user ever reads the neutral 60-minute line of a restricted incident.
# Stored in `tier_settings` under the 'msp' scope only (no per-tenant value);
# admin+ with an all-tenant scope, audited before the write, the other admins
# told (the route). A value that cannot be read is OFF — suppressed.
CSAM_CLIENT_NOTICE = "csam_client_notice"
RESTRICTED_SETTINGS: dict[str, bool] = {CSAM_CLIENT_NOTICE: False}


def restricted_settings() -> dict[str, bool]:
    """The effective restricted-incident switches (defaults ← 'msp')."""
    out = dict(RESTRICTED_SETTINGS)
    stored = stored_settings("msp")
    for key in RESTRICTED_SETTINGS:
        if isinstance(stored.get(key), bool):
            out[key] = stored[key]
    return out


def csam_client_notice() -> bool:
    """May a client user see the neutral line of a restricted incident?
    False (suppressed) by default and whenever the setting cannot be read."""
    try:
        return bool(restricted_settings().get(CSAM_CLIENT_NOTICE, False))
    except Exception:  # noqa: BLE001 — fail quiet: suppressed
        return False


def put_restricted(conn: sqlite3.Connection, values: dict[str, Any], *, by: int,
                   now: Optional[datetime] = None) -> None:
    for key, value in values.items():
        if key not in RESTRICTED_SETTINGS:
            raise ValueError(f"unknown setting {key!r}")
        if not isinstance(value, bool):
            raise ValueError(f"{key} is true or false")
    for key, value in values.items():
        conn.execute(
            "INSERT INTO tier_settings (scope, key, value_json, updated_by, updated_at) "
            "VALUES ('msp', ?, ?, ?, ?) ON CONFLICT (scope, key) DO UPDATE SET "
            "value_json = excluded.value_json, updated_by = excluded.updated_by, "
            "updated_at = excluded.updated_at",
            (key, json.dumps(value), by, _now_s(now)))


# ---------------------------------------------------------------------------
# Worker state (heartbeat, cursors)
# ---------------------------------------------------------------------------

def state_get(key: str) -> Optional[Any]:
    try:
        reg = connect(paths.registry_db_path(), read_only=True)
        try:
            row = reg.execute("SELECT value_json FROM threat_worker_state WHERE key = ?",
                              (key,)).fetchone()
        finally:
            reg.close()
    except sqlite3.Error:
        return None
    if row is None:
        return None
    try:
        return json.loads(row[0])
    except ValueError:
        return None


def state_put(key: str, value: Any, now: Optional[datetime] = None) -> bool:
    try:
        reg = connect(paths.registry_db_path())
        try:
            with transaction(reg):
                reg.execute(
                    "INSERT INTO threat_worker_state (key, value_json, updated_at) "
                    "VALUES (?, ?, ?) ON CONFLICT (key) DO UPDATE SET "
                    "value_json = excluded.value_json, updated_at = excluded.updated_at",
                    (key, json.dumps(value), _now_s(now)))
        finally:
            reg.close()
    except sqlite3.Error as exc:
        logger.warning("[threat-registry] state %s not written (%s)", key, type(exc).__name__)
        return False
    return True
