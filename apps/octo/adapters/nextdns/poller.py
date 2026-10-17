"""NextDNSPoller — ask the cheap question first; the firehose never comes in.

A NextDNS account sees every profile it owns or edits (on a production
account, a good share route no DNS in a given 24 h, and some are personal /
test profiles that must never be ingested). Per MAPPED profile only:

  SECURITY (every `poll_interval_sec`, default 10 min; ACTIVE and LAPSED
  profiles)  GET analytics/reasons for the window since the last check,
             overlapping it by `overlap_sec` (5 min: analytics lag a few
             minutes). NextDNS counts EVERY reason of a multi-reason block
             (verified live 2026-09-30: reason counts summed to 2.2× the
             blocked queries), so a signal reason behind a blocklist is never
             hidden. Only if a SIGNAL-class reason (classification.py) has a
             count in that window: GET the blocked logs of the window (paged
             by cursor, oldest first, bounded pages per profile, per cycle,
             per profile-hour and per window — a longer backlog resumes next
             cycle from the newest line processed; a cursor that stops making
             progress ends the window) and keep ONLY the lines with a
             signal-class reason. Otherwise no log call at all.
  COALESCING (owner decision 2026-09-30, "split by severity") the first
             security block of a bucket creates ONE signal
             (`nextdns.security_block`); later hits only count in the bucket
             (store.py) — the stored alert is never rewritten:
               * HIGH: (profile, device id or client IP, ROOT domain, reason)
                 per CLOCK HOUR;
               * DGA: (profile, device, reason) per clock hour, any domain;
               * MEDIUM / LOW: (profile, device, reason) per UTC DAY, any
                 domain.
             RESTRICTED (v0.17.1, Rick 2026-10-06): a line with a CSAM
             reason anywhere among its reasons is NEVER an alert and never in
             the ledger: it is kept only as restricted evidence (events.db
             `restricted_evidence`, exactly once, append-only) and the tier
             engine is woken — rule B7 opens an automated, restricted Black
             (`apps.octo.threat.restricted`).
             When the span is over — and the profile's lines are read up to
             its end (a log backlog after downtime, a throttle or the
             profile's own backoff hold it open) — a bucket with more than
             one hit gets one note on its alert: how many lookups (and,
             without the root in the key, how many distinct domains, with up
             to 5 DISTINCT masked samples).
  HOURLY     (ACTIVE and LAPSED profiles) each closed clock hour, read 5 min
             after it closes: analytics/status (+ analytics/reasons when
             anything was blocked) → one `nextdns_hourly` row in the tenant's
             telemetry.db (telemetry tier, 180 days) and one step of the
             protection-health state machine.
  PENDING    a profile without ACTIVE_THRESHOLD (100) queries in 24 h is
             silent: only a 24-hour status read every `pending_check_sec`
             (6 h) until it has (plus, at most daily, its logging settings:
             logging off or a short retention is shown as such, never as
             "rollout pending"). 1–99 queries a day stay PENDING — no alert,
             never promoted (without NextDNS history, one lapsed "before
             Athena watched" that wakes up with fewer than 100 in 24 h goes
             back to PENDING: a note on that alert, no restore alert).
  BASELINE   "Learn the site's week" (owner decisions 2026-09-30): an hour
             is judged against the SAME HOUR OF THE WEEK on the previous 3
             weeks — the profile's own roll-ups, and before they cover 3
             weeks its NextDNS history: ONE analytics/status;series call
             (from=-21d, hourly) when it is first watched, health priority,
             at most once per profile id per 24 h (an unmapped and re-mapped
             profile too: its seed is kept a day), kept as two bitmasks (busy
             hours, hours with any query) in its own state row, from where
             its SUSTAINED traffic starts (the first 24 h with ≥ 100 queries
             — a stray test query weeks before a rollout is not its week).
             Its own roll-up of an hour replaces the history's; a seed that
             no longer reaches them (re-mapped to another tenant) is read
             again. Hours inside the profile's LAPSES (since → restore) it
             normally has queries in are UNKNOWN: an outage or a closure is
             never learnt as its normal week. A series call that fails → local learning (7 days before
             the hourly rule; the backstop alone before that) and one retry
             a day; a throttle on it is no answer — asked again after the
             backoff (a 403 on it inside a roll-up holds that call only:
             the roll-ups go on; a profile being classified is left as it
             was).
             A 403 on the history call ALONE, REFUSED_BEFORE_PROBLEM times
             with the profile still listed and the key answering, is a
             failed read (local learning, one retry a day — no problem).
  PROTECTION PENDING → ACTIVE (≥ 100 queries / 24 h, the fleet tool's gate).
             An ACTIVE profile LAPSES — ONE `nextdns.protection_lapsed`
             signal (medium), no repeats while LAPSED — ONLY when it is
             silent while it NORMALLY has traffic:
               * the HOURLY RULE: 2 zero hours IN A ROW in hours the site is
                 normally busy — at least half of the same hours of the week
                 with BASELINE_BUSY_QUERIES; a zero hour it is not normally
                 busy in (a closed night between two quiet shoulder hours)
                 breaks the run. Since: the run's first normally-busy zero
                 hour. Needs 7 days of baseline (seeded: from the first day);
               * the WHOLE-DAY BACKSTOP: 0 queries in the trailing 24 h (an
                 ever-active profile) that holds at least 2 hours the site
                 normally has queries in (any query on at least half of the
                 same hours of the previous weeks) — for sites too quiet for
                 the hourly rule. A weekend-closed or part-week office that
                 is always silent then never lapses for it; a public holiday
                 on a normally-busy day may (accepted). Since: the first of
                 those hours. Without a baseline for the day (no history,
                 under 7 days, or under half of its hours known) the plain
                 rule: any silent day, since the run's first zero hour. Its
                 FLOOR: 7 × 24 rolled-up zero hours in a row lapse an
                 ever-active profile whatever its baseline (never a weekend
                 or a long weekend);
               * already dark when mapped: 0 queries in 24 h AND ≥ 100 in the
                 7 days AND (with history) the silent 24 h hold at least 2
                 hours the site normally has queries in — LAPSED from the
                 start ("before Athena watched"). Silent now as it normally
                 is (mapped on a weekend): no alert — ACTIVE when its busiest
                 24 h of the last week reach 100, else PENDING;
               * NextDNS stops showing it to the key (HTTP 404 twice, or a
                 403 — and the profile list no longer shows it). Decided at
                 the cycle's end, waiting (≤ 2 intervals) while another
                 profile's 404 / 403 is still being checked, so profiles lost
                 at once are decided — and grouped — together.
             Queries resume → ACTIVE and ONE `nextdns.protection_restored`
             signal (low) with a deterministic L1 note linking the lapse. A
             restore needs RESTORE_MIN_QUERIES in the hour or RESTORE_HOURS
             non-zero hours in a row; a relapse within 24 h of the restore
             is the SAME episode (notes on the earlier alerts, no new ones).
             After a lapse for lost visibility, only hours after the lapse
             count and the restore is dated when the profile is seen again
             (never before the lapse it resolves).
  VENDOR GAP A zero hour shared by most ACTIVE profiles (≥ 3, and ≥ half of
             those for which the hour is normally busy WITH vendor evidence
             — a read for that hour FAILED: an error, a timeout, a 5xx, a
             malformed answer — or ≥ 80 % without it) is a NextDNS-side
             analytics gap: it counts toward no lapse (the card says so).
             An EMPTY data array is not evidence: it is what a silent hour
             normally looks like (verified live). At most
             VENDOR_GAP_MAX_HOURS (2) hours in a row: a third expires the
             gap and every one of its hours counts — a real mass outage
             lapses its sites (since its first hour).
  FLEET      When at least half of the watched sites (≥ 3) are dark at once
             — lapsing now, or lapsed within the day (no queries, logging
             off, or no longer visible to the key) and still so — ONE
             `nextdns.fleet_dns_outage` signal (HIGH: "N sites stopped
             reporting to NextDNS — check NextDNS status and the UniFi DNS
             template") goes to the operator's own tenant (the ACTIVE client
             of kind 'internal'; none → shown on the card, logged, not
             stored), and each site's lapse carries the grouping (its L1 note
             is 'pattern', not one escalation per site). Fewer than half
             dark → the incident closes with a note counting the sites that
             REALLY report again (restored) and those still silent; within
             24 h it reopens as the same incident.
  DISCOVERY  the profile list: first thing after a start, then every poll
             interval while no profile is active or lapsed (it is then the
             contact that says the key works), else every 6 h — lowest
             priority (card counts: mapped / ignored / unmapped).

ENTITY FEED (feed.py; only for a tenant whose consumer `wants` it — entity
             resolution switched on): per mapped profile, ONE
             analytics/devices read per closed hour (the NextDNS app's
             devices and their counts; refused → one log page sampled, the
             hour "whole" only when the page held all of it) and ONE
             analytics/ips read per UTC day — per PROFILE, never per device;
             at most 6 hours caught up, 2 per profile per cycle, 30 calls a
             cycle, health priority, yielding to security. The consumer's
             device-silence findings come back as `nextdns.device_silent` /
             `device_restored` signals built here (with their OCSF mapping).
KNOWN BENIGN (instances.known_benign, registry, operator-editable): a block a
             rule matches — its domain AND every signal reason of the line —
             is filed at the rule's level (LOW) in its own bucket and
             labelled "known benign"; NextDNS keeps blocking it (never an
             allowlist). Seed: the Samsung connectivity probe.

UNMAPPED PROFILES ARE NEVER POLLED beyond discovery. A profile mapped to a
tenant that is not active (offboarded, archived, disabled) is not polled
either, and the mapping is re-read before every profile task (a profile
unmapped or re-mapped mid-cycle is dropped at once; an unreadable tenant map
polls NOTHING). NextDNS never auto-creates a tenant: signals go to the
profile's mapped tenant or nowhere (the fleet signal: the internal tenant).
FIRST IMPORT: nothing is polled until an operator saves a mapping; a newly
mapped profile then back-fills 24 h of SECURITY blocks only (never hourly
rows or policy blocks). A re-mapped profile starts its protection afresh in
the new tenant (no back-fill, no cross-tenant note or event id).

FAILURES ARE PER PROFILE: a profile whose calls fail (timeout, 5xx, 400, a
404) or whose tenant's telemetry store cannot be written backs off on its own
schedule and is shown with its problem on the card / in source health; every
other profile keeps being polled. A 403 on one profile is held against the
ENDPOINT CLASS that got it — the profile's reads as a whole (security checks,
log pulls, its 24-hour / 7-day / settings reads), its hourly ROLL-UP reads,
or its HISTORY series — each with its own streak (an answer on one class
never resets another's) and a backoff that grows while it lasts (the
interval, doubling to an hour): a 403 on its reads holds back EVERY read of
the profile; on its roll-ups, its roll-ups only (its security checks go on);
on its history call, that call only (its roll-ups go on). One refused
profile never stalls the others' roll-ups or lapse detection. It is read as
rate limiting (the cycle ends, normal backoff — never for the history call
inside a roll-up) unless the profile list — asked at low priority, at most
once per profile per 30 min — no longer shows the profile: then it is NOT
ACCESSIBLE (shown, one lapse if it was active, re-probed like a missing
one). A 403 that keeps coming back on one class of that profile ALONE (no
other refusal on the key between two of them — a repeat 403 of a profile
class already refused once does not count, so several profiles refused at
once are each alone — the key answering other calls) while the list still
shows it is the profile's own problem, REFUSED: "NextDNS refuses this
profile — check sharing/permissions" (its reads), or "NextDNS refuses this
profile's hourly analytics — check sharing/permissions" (its roll-ups: its
blocks are still read, its protection cannot be judged) on the card, the
panel and source health (no lapse; the key is not blamed; its 403s no
longer end the cycle). On its history call it is a failed read (local
learning, one retry a day — no problem shown). A 404 is checked again next
interval; a second one asks the same list (this cycle's end): still listed
→ a vendor-side failure (backoff, shown, no lapse — a short 404 storm is
not N lapses); not listed → MISSING. Only a throttle, a rejected key, or a
run of transport failures across profiles ends a cycle. A missing profile
is re-probed every `pending_check_sec` and as soon as the profile list
shows it again.

UNREACHABLE: whatever the fleet size (per-profile backoffs spread the
failures of a small fleet over many cycles), when no NextDNS call has
succeeded for UNREACHABLE_AFTER_INTERVALS poll intervals since calls
started failing (connection errors, timeouts, 5xx, malformed answers — not
a throttle, a 404 or a rejected key: those are answers), the instance row
says 'error': "NextDNS unreachable since <time>". The next successful call
clears it. (FLEET_FAILURE_RUN such failures in a row inside one cycle say
so at once and end the cycle.)

RATE: every call goes through the key's ONE limiter (limiter.py: ≥ 2 s
apart, priority with a starvation guard, 403-after-success = throttled).
When the hour's planned calls cannot fit the spacing, the cycle STRETCHES
(logged once), it never bursts.

RESTART-SAFE, WITHOUT CHURN: the state lives in `adapter_poller_state` — ONE
row per profile (`nextdns_state:p:<id>`: high-water marks, the log pull's
resume point, protection — its 48 h of per-hour evidence packed as one
bitmask per list), its baseline seed in a row of its own
(`nextdns_state:b:<id>`, written once per seed) and one global row
(`nextdns_state`). Only rows that
CHANGED are written, in one transaction, at the end of a cycle and at most
every SAVE_EVERY_SEC (30 s) — not after every task. What that can lose
in a crash is harmless: overlapping windows re-read lines already seen (the
bucket ledger counts each line exactly once, the sink's identity guard
stores an alert once — no duplicate signal, and no gap: the next window
starts at the persisted mark minus the overlap, however long Athena was
down). Protection / fleet signals go through an OUTBOX in that state: they
are written only after the state that decided them is durable, re-delivered
after a crash (the sink finds the same alert), and never lost.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
import sqlite3
import threading
from dataclasses import MISSING, asdict, dataclass, field, fields
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

from apps.octo import paths
from apps.octo.adapters.nextdns import classification, feed, ocsf, store
from apps.octo.adapters.nextdns.client import (
    NextDNSAborted,
    NextDNSAuthError,
    NextDNSClient,
    NextDNSClientError,
    NextDNSNotFoundError,
    NextDNSThrottledError,
    valid_profile_id,
)
from apps.octo.adapters.nextdns.limiter import (
    PRIORITY_DISCOVERY,
    PRIORITY_HEALTH,
    PRIORITY_SECURITY,
)
from apps.octo.adapters.nextdns.presentation import (
    EVENT_BLOCK,
    EVENT_FLEET,
    EVENT_LAPSED,
    EVENT_RESTORED,
)
from apps.octo.db import connect
from apps.octo.ingest.timestamps import format_utc_ms, normalize_timestamp
from apps.octo.instances import freshness, known_benign, poller_state, tenant_map
from apps.octo.instances.vendor_contact import ContactReporter, FailureBackoff

logger = logging.getLogger(__name__)

VENDOR = "nextdns"

DEFAULT_POLL_INTERVAL_SEC = 600.0
MIN_POLL_INTERVAL_SEC = 60.0
MAX_POLL_INTERVAL_SEC = 3600.0
DEFAULT_OVERLAP_SEC = 300.0
HOURLY_DELAY_SEC = 300.0
DEFAULT_PENDING_CHECK_SEC = 6 * 3600.0
DISCOVERY_EVERY_SEC = 6 * 3600.0
SETTINGS_EVERY = timedelta(hours=24)
BACKFILL = timedelta(hours=24)
BEFORE_WATCH_LOOKBACK = timedelta(days=7)
ACTIVE_THRESHOLD = 100
LAPSE_ZERO_HOURS = 2
# The hourly rule's baseline: an hour is normally busy when, on the same
# hour of the week of the previous BASELINE_WEEKS weeks that have a row, at
# least half had BASELINE_BUSY_QUERIES queries. Without BASELINE_MIN of
# roll-ups (the profile's first row) the hourly rule does not apply.
BASELINE_WEEKS = 3
BASELINE_MIN = timedelta(days=7)
BASELINE_BUSY_QUERIES = 10
# The baseline's SEED (owner decision 2026-09-30: no first-weeks blind spot):
# the profile's own NextDNS history — ONE analytics/status;series call
# (from=-21d, hourly: 504 buckets), at health priority, when a profile is
# first watched and whenever its local baseline has less than 3 weeks, at
# most once per profile per SEED_EVERY. Kept compactly: the busy hours
# (≥ BASELINE_BUSY_QUERIES) and the hours with any query as one bitmask each
# (no counts, no raw series), plus its busiest 24 hours of the last 7 days.
# Local roll-ups replace it hour by hour as they accumulate.
SEED_FROM = "-21d"
SEED_INTERVAL_SEC = 3600
SEED_EVERY = timedelta(hours=24)
SEED_SPAN_HOURS = 22 * 24
# Local roll-ups in the trailing 3 weeks that make a seed needless.
SEED_LOCAL_FULL_ROWS = 20 * 24
# A seed no lookup can reach any more (3 weeks + a day's window + the
# roll-up look-back) is dropped.
SEED_KEEP = timedelta(days=23)
# The whole-day backstop: SILENT_DAY_HOURS zero hours in a row (the hours of
# them the site normally has queries in decide, see `_backstop_since`) — and
# its floor: SILENT_WEEK_HOURS zero hours in a row lapse an ever-active
# profile WHATEVER its baseline ("silent forever" can never pass; a weekend
# or a long weekend never reaches it).
SILENT_DAY_HOURS = 24
SILENT_WEEK_HOURS = 7 * 24
# A LAPSED profile is restored by an hour with this many queries, or by
# RESTORE_HOURS non-zero hours in a row (a lone wake-up is not a restore).
RESTORE_MIN_QUERIES = 25
RESTORE_HOURS = 2
# A lapse within this long of the profile's last restore is the same episode.
RELAPSE_WINDOW = timedelta(hours=24)
# Lapse causes: NextDNS stopped showing the profile to the key.
VISIBILITY_CAUSES = ("not_visible", "not_accessible")
# Lapse causes of a site that is dark now (they count toward a fleet-wide
# outage while the site stays silent / unseen).
DARK_CAUSES = ("no_queries", "logs_off", *VISIBILITY_CAUSES)
# A zero hour shared by at least VENDOR_GAP_MIN_PROFILES ACTIVE profiles —
# and VENDOR_GAP_SHARE of those for which the hour is normally busy when
# NextDNS gave evidence (a FAILED read for the hour: error, timeout, 5xx,
# malformed answer — never an empty data array, which is normal silence), or
# VENDOR_GAP_SHARE_NO_EVIDENCE without — is a NextDNS-side gap. At most
# VENDOR_GAP_MAX_HOURS in a row.
VENDOR_GAP_MIN_PROFILES = 3
VENDOR_GAP_SHARE = 0.5
VENDOR_GAP_SHARE_NO_EVIDENCE = 0.8
VENDOR_GAP_MAX_HOURS = 2
# How long a lapse candidate waits for the other profiles to read its hour.
VENDOR_GAP_WAIT = timedelta(hours=1)
VENDOR_GAP_READY_SHARE = 0.8
# A fleet-wide outage: at least half of the watched sites (and at least
# VENDOR_GAP_MIN_PROFILES) dark at once — lapsing now, or lapsed (no
# queries) within FLEET_WINDOW and still silent.
FLEET_WINDOW = timedelta(hours=24)
FLEET_RELAPSE_WINDOW = timedelta(hours=24)
FLEET_LIST_MAX = 25
MAX_LOG_PAGES_PER_PROFILE = 5
MAX_LOG_PAGES_PER_CYCLE = 40
# The ENTITY FEED (feed.py): per mapped profile whose tenant wants it, one
# analytics/devices read per closed hour (catching up at most this many hours,
# at most ENTITY_HOURS_PER_PROFILE per cycle) and one analytics/ips read per
# UTC day; at most ENTITY_CALLS_PER_CYCLE such calls a cycle, yielding to
# security checks.
ENTITY_HOURS_BACK = 6
ENTITY_HOURS_PER_PROFILE = 2
ENTITY_CALLS_PER_CYCLE = 30
ENTITY_MIN_CALLS_BEFORE_YIELD = 5
# The SEED: the 14 UTC days before today, one analytics/devices read per day
# per profile, once (a device whose app was already dead at switch-on is
# known and watched) — at most this many per profile per cycle.
ENTITY_SEED_DAYS = 14
ENTITY_SEED_DAYS_PER_CYCLE = 2
# analytics/devices refused (400 / 404) this many times in a row ON ONE
# PROFILE: that profile samples one log page per hour instead — and asks
# analytics/devices again every ENTITY_DEVICES_REPROBE (one hiccup never
# switches every profile to sampling for good).
ENTITY_DEVICES_REFUSALS = 3
ENTITY_DEVICES_REPROBE = timedelta(hours=6)
# An entity read NextDNS refuses (403) or fails on for one profile waits on
# its own (doubling to the ceiling) — never the key, never the cycle.
ENTITY_HOLD_BASE = timedelta(minutes=15)
ENTITY_HOLD_CEILING = timedelta(hours=6)
# Bounds that make a runaway cursor or a backlog unable to hold the limiter.
MAX_LOG_PAGES_PER_WINDOW = 120
MAX_LOG_PAGES_PER_PROFILE_PER_HOUR = 60
LOG_PAGE_SIZE = 1000
MAX_HOURS_PER_PROFILE_PER_CYCLE = 6
# Health tasks (a profile's hourly roll-up / a pending check) a cycle runs
# even while security checks are due again (a stretched cycle).
MIN_HEALTH_TASKS_PER_CYCLE = 5
# Share of the limiter's hour kept free for log pulls, searches, discovery
# when deciding whether the planned polling fits.
LOG_ALLOWANCE_SHARE = 0.1
HOURLY_LOOKBACK = timedelta(hours=24)
# A 403 on one profile is checked against the profile list at most this often.
LIST_CHECK_EVERY = timedelta(minutes=30)
# Per-hour evidence lists kept per profile.
RECENT_HOURS = 48

STATE_KEY = "nextdns_state"
PROFILE_KEY_PREFIX = STATE_KEY + ":p:"
# The baseline seed of a profile: its own row, written once per seed (the
# profile row is rewritten about every 10 minutes; the seed never changes).
SEED_KEY_PREFIX = STATE_KEY + ":b:"
STATE_VERSION = 2
# The state is written at the end of a cycle, at most this often.
SAVE_EVERY_SEC = 30.0
# The "the key has worked" mark is persisted at most this often (it only
# has to say "ever").
KEY_OK_PERSIST_EVERY = timedelta(hours=1)

CREDENTIAL_BACKOFF_BASE_SEC = 60.0
CREDENTIAL_BACKOFF_CEILING_SEC = 900.0
TRANSPORT_BACKOFF_BASE_SEC = 60.0
TRANSPORT_BACKOFF_CEILING_SEC = 900.0
AUTH_FAILURES_BEFORE_REPLACE_ADVICE = 3
# A throttle this long gets a hint to check the key (never "re-add it").
LONG_THROTTLE = timedelta(hours=1)

# Per-profile failure backoff (one profile never stops the others).
NOT_FOUND_BEFORE_MISSING = 2
# A profile NextDNS refuses (403) while still listing it: retried after the
# interval, doubling to this; after this many 403s on it ALONE (and the list
# still showing it) it is the profile's own problem, not a throttle.
REFUSED_RETRY_CEILING_SEC = 3600.0
REFUSED_BEFORE_PROBLEM = 3
# The endpoint classes NextDNS can refuse (403) separately on one profile —
# its reads as a whole (security checks, log pulls, the 24-h / 7-day /
# settings reads), its hourly roll-up reads, its history series. Each keeps
# its own 403 streak: an answer on one never resets another's.
EP_PROFILE, EP_HOURLY, EP_SERIES = "profile", "hourly", "series"
FLEET_FAILURE_RUN = 3
# No call has succeeded for this many poll intervals since calls started
# failing (transport level): NextDNS is UNREACHABLE (the row says 'error').
UNREACHABLE_AFTER_INTERVALS = 2
PROFILE_BACKOFF = {                # kind → (base s, ceiling s)
    "vendor": (60.0, 900.0),
    "store": (600.0, 3600.0),
}

# Notes this poller writes on stored alerts.
NOTE_KIND_VENDOR = "vendor_update"
NOTE_KIND_TRIAGE = "auto_enrich"

PENDING, ACTIVE, LAPSED, NEW = "pending", "active", "lapsed", "new"
STATES = (PENDING, ACTIVE, LAPSED)
HEALTH_PATH, SECURITY_PATH, HOURLY_PATH = "health", "security", "hourly"


def profile_state_key(pid: str) -> str:
    """The `adapter_poller_state` key of one profile's state row."""
    return PROFILE_KEY_PREFIX + pid


def seed_state_key(pid: str) -> str:
    """The `adapter_poller_state` key of one profile's baseline seed."""
    return SEED_KEY_PREFIX + pid


class _StoreError(Exception):
    """A tenant's local store could not be written — a local fault of ONE
    tenant, never reported as a NextDNS failure."""


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------

def _dt(value: Optional[str]) -> Optional[datetime]:
    canonical = normalize_timestamp(value, naive_is_utc=True) if value else ""
    if not canonical:
        return None
    return datetime.strptime(canonical, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


def _hour_floor(dt: datetime) -> datetime:
    return dt.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)


def hour_key(dt: datetime) -> str:
    """'YYYY-MM-DDTHH:00:00Z' — the roll-up / bucket hour key."""
    return _hour_floor(dt).strftime("%Y-%m-%dT%H:00:00Z")


def _hour_start(key: str) -> datetime:
    return datetime.strptime(key, "%Y-%m-%dT%H:00:00Z").replace(tzinfo=timezone.utc)


def _hour_text(key: Optional[str]) -> str:
    text = key or ""
    return f"{text[:10]} {text[11:16]} UTC" if len(text) >= 16 else "an unknown time"


def _hours_between(first: Optional[str], last: Optional[str]) -> int:
    """Hours from `first` to `last`, both included (0 when unknown)."""
    try:
        a, b = _hour_start(first or ""), _hour_start(last or "")
    except ValueError:
        return 0
    return max(0, int((b - a).total_seconds() // 3600) + 1)


# The per-hour evidence lists of a profile (hour keys, oldest first).
HOUR_LISTS = ("zero_list", "recent_zero", "error_hours")
# A packed list keeps hours at most this far before its newest one.
PACK_SPAN_HOURS = 7 * 24


def pack_hours(hours: Any, span: int = PACK_SPAN_HOURS) -> Any:
    """Hour keys → 'YYYYMMDDHH:<hex>' — the newest hour, and a bitmask of
    the hours before it (bit i = i hours earlier, at most `span` back):
    ~25 bytes for a whole 48-hour list instead of ~25 bytes PER HOUR (the
    row is rewritten about every 10 minutes). Anything else is returned as
    it is."""
    if not isinstance(hours, list) or not hours:
        return hours
    try:
        starts = sorted({_hour_start(h) for h in hours if isinstance(h, str)})
    except ValueError:
        return hours
    if not starts:
        return []
    newest = starts[-1]
    bits = 0
    for h in starts:
        back = int((newest - h).total_seconds() // 3600)
        if back < span:
            bits |= 1 << back
    return f"{newest.strftime('%Y%m%d%H')}:{bits:x}"


def unpack_hours(value: Any, span: int = PACK_SPAN_HOURS) -> list[str]:
    """The inverse of `pack_hours` (a plain list of keys is accepted too);
    anything unreadable → []."""
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    if not isinstance(value, str) or ":" not in value:
        return []
    head, _, tail = value.partition(":")
    try:
        newest = datetime.strptime(head, "%Y%m%d%H").replace(tzinfo=timezone.utc)
        bits = int(tail, 16)
    except ValueError:
        return []
    out = []
    for back in range(min(bits.bit_length(), span) - 1, -1, -1):
        if bits >> back & 1:
            out.append(hour_key(newest - timedelta(hours=back)))
    return out


def packed_bits(value: Any) -> Optional[tuple[datetime, int]]:
    """A `pack_hours` value as (newest hour, bitmask) — looked up without
    unpacking (`has_hour`); None when it is not one."""
    if not isinstance(value, str) or ":" not in value:
        return None
    head, _, tail = value.partition(":")
    try:
        return (datetime.strptime(head, "%Y%m%d%H").replace(tzinfo=timezone.utc),
                int(tail, 16))
    except ValueError:
        return None


def has_hour(packed: Optional[tuple[datetime, int]], key: str,
             span: int = PACK_SPAN_HOURS) -> bool:
    """Is hour `key` in a packed list (`packed_bits`)?"""
    if packed is None:
        return False
    newest, bits = packed
    back = int((newest - _hour_start(key)).total_seconds() // 3600)
    return 0 <= back < span and bool(bits >> back & 1)


def mark_span(value: Optional[str], first: str, last: str,
              span: int = SEED_SPAN_HOURS) -> Optional[str]:
    """Add the hours `first`..`last` (both included) to a packed list
    (`pack_hours`' 'YYYYMMDDHH:<hex>': the newest hour and a bitmask of the
    hours before it, at most `span` back) — without unpacking it."""
    try:
        a, b = _hour_start(first), _hour_start(last)
    except ValueError:
        return value
    if b < a:
        return value
    packed = packed_bits(value)
    newest, bits = packed if packed is not None else (b, 0)
    if b > newest:
        bits <<= int((b - newest).total_seconds() // 3600)
        newest = b
    lo = int((newest - b).total_seconds() // 3600)
    hi = min(int((newest - a).total_seconds() // 3600), span - 1)
    if lo <= hi:
        bits |= ((1 << (hi - lo + 1)) - 1) << lo
    bits &= (1 << span) - 1
    return f"{newest.strftime('%Y%m%d%H')}:{bits:x}" if bits else None


def _sustained_start(keys: list[str], counts: dict[str, int]) -> Optional[int]:
    """Where a history series' SUSTAINED traffic starts: the first hour with
    queries of the first 24 hours in a row with at least ACTIVE_THRESHOLD
    (one stray test query weeks before a rollout is not the site's week);
    a profile that never reaches that — a low-volume one — from its first
    query. None: no query at all."""
    window = 0
    for i, key in enumerate(keys):
        window += counts[key]
        if i >= 24:
            window -= counts[keys[i - 24]]
        if window >= ACTIVE_THRESHOLD:
            lo = max(0, i - 23)
            return next(j for j in range(lo, i + 1) if counts[keys[j]] > 0)
    return next((i for i, k in enumerate(keys) if counts[k] > 0), None)


def make_seed(points: list[tuple[datetime, int]], now: datetime, *,
              interval_sec: int = SEED_INTERVAL_SEC) -> dict[str, Any]:
    """The compact baseline seed of a history series: only buckets that
    have CLOSED, from where the profile's SUSTAINED traffic starts on
    (`_sustained_start` — NextDNS answers 0 for the hours before a profile
    routed anything, and a stray test query weeks before the rollout does
    not make them the site's quiet week: they are unknown, not silent) — the
    busy hours (≥ BASELINE_BUSY_QUERIES) and the hours with any query as one
    bitmask each, and `peak24`: the busiest 24 hours in a row of its last 7
    days (is it an active site on its busy days?). No counts or raw series
    are kept."""
    counts: dict[str, int] = {}
    for start, queries in points:
        if start + timedelta(seconds=interval_sec) <= now:
            key = hour_key(start)
            counts[key] = counts.get(key, 0) + max(0, int(queries))
    keys = sorted(counts)
    first = _sustained_start(keys, counts)
    seed: dict[str, Any] = {"v": 1, "at": format_utc_ms(now), "from": None, "to": None,
                            "busy": None, "seen": None, "peak24": 0}
    if first is None:
        return seed
    kept = keys[first:]
    seed["from"], seed["to"] = kept[0], kept[-1]
    seed["busy"] = pack_hours([k for k in kept if counts[k] >= BASELINE_BUSY_QUERIES],
                              SEED_SPAN_HOURS) or None
    seed["seen"] = pack_hours([k for k in kept if counts[k] > 0], SEED_SPAN_HOURS) or None
    last = _hour_start(kept[-1])
    hourly = [counts.get(hour_key(last - timedelta(hours=back)), 0)
              for back in range(7 * 24 + 23 - 1, -1, -1)]
    seed["peak24"] = max(sum(hourly[i:i + 24]) for i in range(len(hourly) - 23))
    return seed


def valid_seed(value: Any) -> Optional[dict[str, Any]]:
    """A stored seed as the poller reads it, or None when it is not one."""
    if not isinstance(value, dict) or not isinstance(value.get("at"), str):
        return None
    out = {"v": 1, "at": value["at"], "from": None, "to": None, "busy": None, "seen": None,
           "peak24": 0}
    frm, to = value.get("from"), value.get("to")
    if isinstance(frm, str) and isinstance(to, str):
        try:
            _hour_start(frm), _hour_start(to)
        except ValueError:
            return out
        out["from"], out["to"] = frm, to
        out["busy"] = value.get("busy") if isinstance(value.get("busy"), str) else None
        out["seen"] = value.get("seen") if isinstance(value.get("seen"), str) else None
    peak = value.get("peak24")
    out["peak24"] = peak if isinstance(peak, int) and not isinstance(peak, bool) else 0
    return out


# ---------------------------------------------------------------------------
# Line identity
# ---------------------------------------------------------------------------

def line_identity(line: dict[str, Any]) -> str:
    """The identity of one log line: a hash of timestamp + domain + device +
    client IP + reasons (the design's ingest identity). Two lines the API
    cannot tell apart (same millisecond, same everything) are one hit."""
    device = line.get("device") if isinstance(line.get("device"), dict) else {}
    reasons = line.get("reasons") if isinstance(line.get("reasons"), list) else []
    ident = {
        "timestamp": line.get("timestamp"),
        "domain": line.get("domain"),
        "device": {k: device.get(k) for k in ("id", "name", "model")},
        "clientIp": line.get("clientIp"),
        "reasons": [r.get("id") if isinstance(r, dict) else r for r in reasons],
    }
    text = json.dumps(ident, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:32]


def _text(value: Any, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    text = " ".join("".join(c if c.isprintable() else " " for c in value).split())
    return text[:limit]


# ---------------------------------------------------------------------------
# Per-profile state
# ---------------------------------------------------------------------------

@dataclass
class ProfileState:
    pid: str
    slug: str
    label: str = ""
    state: str = NEW
    state_since: Optional[str] = None
    ever_active: bool = False
    # SECURITY: the `to` of the last analytics check (the high-water mark —
    # also when it ran); a pending log pull {"from", "to", "resume", "pages"}.
    checked_to: Optional[str] = None
    logs: Optional[dict[str, Any]] = None
    pages_hour: Optional[str] = None
    pages_in_hour: int = 0
    # HOURLY / PROTECTION
    hour_done: Optional[str] = None
    first_hour: Optional[str] = None    # the oldest roll-up row: the baseline's start
    zero_hours: int = 0                 # LAPSED: zero hours since the lapse
    zero_since: Optional[str] = None    # the first zero hour of the current run
    busy_since: Optional[str] = None    # …its first normally-busy zero hour
    # Normally-busy zero hours in a row (a zero hour that is NOT normally
    # busy — a closed night between two shoulder hours — breaks the run).
    zero_list: list[str] = field(default_factory=list)
    recent_zero: list[str] = field(default_factory=list)   # last 48 h, any zero hour
    error_hours: list[str] = field(default_factory=list)   # …a read for the hour FAILED
    lapse_pending: Optional[dict[str, Any]] = None
    lapse: Optional[dict[str, Any]] = None
    restore_streak: int = 0
    last_restore: Optional[dict[str, Any]] = None
    health_at: Optional[str] = None
    q24: Optional[int] = None
    q24_at: Optional[str] = None
    # BASELINE SEED: what the profile's NextDNS history gave — persisted in
    # its own row (`seed_state_key`), never in this one. (The history call's
    # budget is the poller's, per profile id: it outlives an unmapping.)
    seed: Optional[dict[str, Any]] = None
    # The hours inside its lapses (from `since` to the restore) it normally
    # has queries in, packed over SEED_SPAN_HOURS: UNKNOWN to the baseline —
    # an outage or a closure is never learnt as the site's normal week.
    dark_hours: Optional[str] = None
    # Logging settings at NextDNS (read for pending profiles, at most daily).
    logs_enabled: Optional[bool] = None
    retention_sec: Optional[int] = None
    settings_at: Optional[str] = None
    # FAILURES (per profile; `retry_at` gates the security / health path,
    # `hourly_retry_at` the roll-up path).
    missing: bool = False       # NextDNS no longer shows the profile (404 ×2 / 403 + unlisted)
    probe_due: bool = False     # a missing profile the list shows again
    not_found: int = 0
    # 403s on this profile alone in a row, per endpoint class (reset by an
    # answer on THAT class only): its reads as a whole, its roll-up reads,
    # its history series.
    refused: int = 0
    refused_hourly: int = 0
    refused_series: int = 0
    denied_at: Optional[str] = None         # a 403 / repeated 404, not yet checked against the list
    denied_kind: Optional[str] = None       # "access" (403) | "missing" (404)
    list_checked_at: Optional[str] = None
    failures: int = 0
    retry_at: Optional[str] = None
    hourly_failures: int = 0
    hourly_retry_at: Optional[str] = None
    problem: Optional[str] = None
    problem_kind: Optional[str] = None
    problem_path: Optional[str] = None
    problem_at: Optional[str] = None
    # Protection signals / notes decided but not yet written (written only
    # once the state that decided them is durable).
    outbox: list[dict[str, Any]] = field(default_factory=list)

    @property
    def last_check_at(self) -> Optional[str]:
        return self.checked_to

    def to_json(self) -> dict[str, Any]:
        """The persisted row: every field that differs from its default (a
        row is rewritten whenever it changes — about every 10 minutes for a
        watched profile, as its security mark moves — so it stays small: the
        per-hour evidence lists are stored as one bitmask each)."""
        out = {}
        for name, value in asdict(self).items():
            if name in ("pid", "seed") or value == _DEFAULTS.get(name):
                continue
            out[name] = pack_hours(value) if name in HOUR_LISTS else value
        return out

    @classmethod
    def from_json(cls, pid: str, raw: Any) -> Optional["ProfileState"]:
        if not isinstance(raw, dict):
            return None
        names = {f.name for f in fields(cls)}
        data = {k: v for k, v in raw.items() if k in names and k != "seed"}
        data["pid"] = pid
        if not isinstance(data.get("slug"), str):
            return None
        try:
            st = cls(**data)
        except TypeError:
            return None
        if st.state not in (*STATES, NEW):
            st.state = NEW
        for name in ("logs", "lapse", "lapse_pending", "last_restore"):
            if not isinstance(getattr(st, name), dict):
                setattr(st, name, None)
        for name in HOUR_LISTS:
            setattr(st, name, unpack_hours(getattr(st, name))[-RECENT_HOURS:])
        if packed_bits(st.dark_hours) is None:
            st.dark_hours = None
        for name in ("zero_hours", "restore_streak", "pages_in_hour", "not_found",
                     "refused", "refused_hourly", "refused_series", "failures",
                     "hourly_failures"):
            if not isinstance(getattr(st, name), int):
                setattr(st, name, 0)
        st.outbox = [i for i in st.outbox if isinstance(i, dict)
                     and isinstance(i.get("seq"), int) and i.get("op") in ("event", "note")] \
            if isinstance(st.outbox, list) else []
        return st


_DEFAULTS: dict[str, Any] = {
    f.name: (f.default if f.default is not MISSING else f.default_factory())  # type: ignore[misc]
    for f in fields(ProfileState)
    if f.default is not MISSING or f.default_factory is not MISSING  # type: ignore[misc]
}


@dataclass
class CycleReport:
    held: bool = False
    contacted: bool = False
    security_checks: int = 0
    log_pages: int = 0
    signals: int = 0
    counted: int = 0
    hourly_rows: int = 0
    health_checks: int = 0
    discovery: bool = False
    stretched: bool = False
    next_due_in: float = DEFAULT_POLL_INTERVAL_SEC
    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# The poller
# ---------------------------------------------------------------------------

class NextDNSPoller:
    def __init__(
        self,
        *,
        adapter: Any,
        client: NextDNSClient,
        sink: Any,
        instance_id: Optional[int],
        poll_interval_sec: float = DEFAULT_POLL_INTERVAL_SEC,
        overlap_sec: float = DEFAULT_OVERLAP_SEC,
        pending_check_sec: float = DEFAULT_PENDING_CHECK_SEC,
        max_log_pages_per_profile: int = MAX_LOG_PAGES_PER_PROFILE,
        max_log_pages_per_cycle: int = MAX_LOG_PAGES_PER_CYCLE,
        now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        reporter: Optional[ContactReporter] = None,
        credential_backoff: Optional[FailureBackoff] = None,
        transport_backoff: Optional[FailureBackoff] = None,
    ) -> None:
        self._adapter = adapter
        self._client = client
        self._sink = sink
        self._instance_id = instance_id
        self._interval = max(MIN_POLL_INTERVAL_SEC, min(MAX_POLL_INTERVAL_SEC, poll_interval_sec))
        self._overlap = timedelta(seconds=max(0.0, min(3600.0, overlap_sec)))
        self._pending_every = timedelta(seconds=max(600.0, pending_check_sec))
        self._max_pages_profile = max(1, int(max_log_pages_per_profile))
        self._max_pages_cycle = max(1, int(max_log_pages_per_cycle))
        self._now = now
        self._reporter = reporter or ContactReporter(instance_id, what="nextdns-poller")
        self._credential_backoff = credential_backoff or FailureBackoff(
            base_sec=CREDENTIAL_BACKOFF_BASE_SEC, ceiling_sec=CREDENTIAL_BACKOFF_CEILING_SEC,
        )
        self._transport_backoff = transport_backoff or FailureBackoff(
            base_sec=TRANSPORT_BACKOFF_BASE_SEC, ceiling_sec=TRANSPORT_BACKOFF_CEILING_SEC,
        )
        self._abort = threading.Event()
        set_abort = getattr(client, "set_abort", None)
        if callable(set_abort):
            set_abort(self._abort)
        self._profiles: dict[str, ProfileState] = {}
        # (pid, endpoint class) → (the limiter's throttle events, successes)
        # at its last 403: tells a 403 on this profile alone from a key-wide
        # throttle.
        self._refusal_mark: dict[tuple[str, str], tuple[int, int]] = {}
        # The endpoint class of the call a profile task is making, when it
        # is not the task's own (the history call inside a roll-up or a
        # classification).
        self._ep: Optional[str] = None
        # pid → when its history call may be asked again after a throttle /
        # a 403 on it (only that call waits; its roll-ups go on).
        self._seed_retry: dict[str, datetime] = {}
        # Reachability: the first failed call (transport level) since the
        # last successful one, and the latest failure's text.
        self._fail_since: Optional[datetime] = None
        self._fail_text = ""
        self._unreachable_logged = False
        self._prepared = False
        # analytics/devices is not verified live: per PROFILE, after
        # ENTITY_DEVICES_REFUSALS refusals (400 / 404) in a row, device
        # presence samples one log page per hour instead, until the re-probe.
        self._devices_refused: dict[str, int] = {}
        self._devices_fallback_until: dict[str, datetime] = {}
        # (pid, read) → (held until, failures): an entity read a profile
        # refuses (403) or fails on waits on its own.
        self._entity_hold: dict[tuple[str, str], tuple[datetime, int]] = {}
        # pid → the UTC day whose analytics/ips NextDNS refused (400 / 403 /
        # 404): never asked again that day.
        self._ips_refused_day: dict[str, str] = {}
        # Which profile the entity feed starts with (rotates every cycle, so
        # profile order can never starve the tail).
        self._entity_turn = 0
        # Persistence: the stored text of every row, the last write, and the
        # outbox sequence (items up to `_durable_seq` are in a stored row).
        self._persisted: dict[str, str] = {}
        self._flushed_at: Optional[datetime] = None
        self._seq = 0
        self._durable_seq = 0
        self._outbox: list[dict[str, Any]] = []            # global (the fleet signal)
        self._key_ok_at: Optional[str] = None
        self._key_ok_persisted: Optional[str] = None
        self._known: Optional[dict[str, str]] = None      # discovery: id → name
        self._known_at: Optional[datetime] = None
        self._discovery_due: Optional[datetime] = None
        self._gap_hours: list[str] = []                   # NextDNS-side analytics gaps
        self._gap_expired: list[str] = []                 # …that lasted past the bound
        self._fleet: Optional[dict[str, Any]] = None      # the fleet-wide outage
        self._fleet_warned: Optional[str] = None
        self._shape_cache: dict[str, tuple[bool, bool]] = {}
        self._busy_cache: dict[tuple[str, str], bool] = {}
        # pid → (seed identity, (from, to, busy hours, hours with queries)):
        # the two lists as (newest hour, bitmask) — never unpacked.
        self._seed_views: dict[str, tuple[tuple[str, str], tuple[str, str, Any, Any]]] = {}
        # pid → when its local roll-ups were last found to cover 3 weeks
        self._local_full: dict[str, datetime] = {}
        # The history call's budget: pid → its last attempt (persisted in
        # the global row, kept SEED_EVERY) — an unmapped and re-mapped
        # profile is still asked at most once a day.
        self._seed_calls: dict[str, str] = {}
        # The seeds of profiles no longer mapped, kept (with their rows)
        # until SEED_EVERY old: a re-mapping within the day reuses its own.
        self._parked_seeds: dict[str, dict[str, Any]] = {}
        # Listed-profile 403s on profiles already refused once (`_refusal_mark`):
        # they never make another refused profile look like a key-wide throttle.
        self._suspect_403s = 0
        self._reading_hour: Optional[str] = None
        self._stretch_logged = False
        self._stretched = False
        self._throttled_until: Optional[datetime] = None
        self._throttled_since: Optional[datetime] = None
        self._auth_failures = 0
        self._fail_run = 0
        self._cycle_pages = 0
        self._last_event_at: Optional[str] = None
        self._snapshot: dict[str, Any] = {}
        self._snap_lock = threading.Lock()
        self._publish: Optional[Callable[[str, Any], None]] = None
        # async plumbing
        self._task: Optional[asyncio.Task] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._stopping = asyncio.Event()
        self._wake = asyncio.Event()

    # ----- read side (API threads) -----

    @property
    def last_event_at(self) -> Optional[str]:
        return self._last_event_at

    @property
    def interval_sec(self) -> float:
        return self._interval

    def snapshot(self) -> dict[str, Any]:
        """A copy of what the card / source health show — never a vendor call."""
        with self._snap_lock:
            snap = json.loads(json.dumps(self._snapshot)) if self._snapshot else {}
        throttled = self._throttled_until
        now = self._now()
        left = (throttled - now).total_seconds() if throttled else 0.0
        snap["throttled"] = left > 0
        snap["throttled_for_sec"] = int(left) if left > 0 else 0
        return snap

    def profile_states(self) -> dict[str, dict[str, Any]]:
        with self._snap_lock:
            return json.loads(json.dumps(self._snapshot.get("states", {})))

    # ----- async lifecycle -----

    async def start(self) -> None:
        if self._task is not None and not self._task.done():
            return
        self._stopping.clear()
        self._abort.clear()
        self._loop = asyncio.get_running_loop()
        self._publish = self._publish_on_loop
        self._task = asyncio.create_task(self._run(), name="nextdns-poller")

    def poll_now(self) -> None:
        loop = self._loop
        if loop is None or loop.is_closed():
            return
        loop.call_soon_threadsafe(self._wake.set)

    async def stop(self) -> None:
        if self._task is None:
            return
        self._stopping.set()
        self._abort.set()
        self._client.limiter.poke()
        finished = False
        try:
            await asyncio.wait_for(self._task, timeout=20.0)
            finished = True
        except asyncio.TimeoutError:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
        self._task = None
        if finished:
            # No cycle is running: write what the last one left (best effort —
            # a restart without it only re-reads a few seconds).
            try:
                await asyncio.to_thread(self.flush_now)
            except Exception:  # noqa: BLE001
                logger.debug("[nextdns-poller] final state write skipped")

    async def _run(self) -> None:
        logger.info(
            "[nextdns-poller] starting (security every %.0fs, overlap %.0fs, spacing %.1fs)",
            self._interval, self._overlap.total_seconds(), self._client.limiter.min_spacing_sec,
        )
        try:
            while not self._stopping.is_set():
                self._wake.clear()
                delay = await asyncio.to_thread(self.cycle_with_reporting)
                await self._sleep_or_stop(delay)
        finally:
            logger.info("[nextdns-poller] stopped")

    async def _sleep_or_stop(self, seconds: float) -> None:
        waiters = [
            asyncio.ensure_future(self._stopping.wait()),
            asyncio.ensure_future(self._wake.wait()),
        ]
        try:
            await asyncio.wait(waiters, timeout=max(0.0, seconds),
                               return_when=asyncio.FIRST_COMPLETED)
        finally:
            for w in waiters:
                w.cancel()

    def _publish_on_loop(self, slug: str, event: Any) -> None:
        """Live (SSE) fan-out of a stored alert, scheduled on the API loop
        (the cycle runs on a worker thread)."""
        loop = self._loop
        if loop is None or loop.is_closed():
            return
        from apps.octo.ingest import SqliteIngestSink

        publisher = SqliteIngestSink(publish_to_stream=True)
        try:
            loop.call_soon_threadsafe(publisher._publish, slug, VENDOR, event)  # noqa: SLF001
        except RuntimeError:
            pass

    # ----- one cycle, with the outcome reported -----

    def cycle_with_reporting(self) -> float:
        """Run one cycle and report its outcome (ContactReporter); return
        how long to wait before the next. Never raises."""
        try:
            report = self.run_cycle()
        except NextDNSAborted:
            return 0.0
        except NextDNSThrottledError as exc:
            now = self._now()
            if exc.status is not None:
                self._vendor_answered()
            wait = max(1.0, exc.retry_in_sec)
            self._throttled_until = now + timedelta(seconds=wait)
            self._throttled_since = self._throttled_since or now
            hint = ""
            if now - self._throttled_since >= LONG_THROTTLE:
                hint = (
                    " NextDNS has refused Athena's calls for over an hour. If this "
                    "continues, check the key at my.nextdns.io → Account → API (a "
                    "regenerated key is answered with HTTP 401, which Athena reports "
                    "as such)."
                )
            self._reporter.throttled(
                "NextDNS is rate limiting Athena (it answers a burst with HTTP 403). "
                f"Every NextDNS call waits {int(wait)} s and backs off further if it "
                "persists (up to 10 minutes). Not a failure: nothing is lost — the "
                "next checks cover the whole gap." + hint
            )
            logger.warning("[nextdns-poller] throttled by NextDNS (retry in %.0fs)", wait)
            self._update_snapshot()
            return wait
        except NextDNSAuthError as exc:
            self._vendor_answered()
            delay = self._credential_backoff.next()
            self._auth_failures += 1
            if exc.status == 401:
                advice = (
                    " Nothing to do yet: a single rejection can be a vendor-side blip."
                    if self._auth_failures < AUTH_FAILURES_BEFORE_REPLACE_ADVICE else
                    " The stored API key no longer works — it may have been regenerated "
                    "at my.nextdns.io → Account → API. Stored keys cannot be edited: "
                    "Disable this integration, then Add integration again with the "
                    "current key (map your profiles again afterwards)."
                )
            else:
                advice = (
                    " This key has never worked here: check it was copied whole from "
                    "my.nextdns.io → Account → API."
                )
            self._reporter.failed(
                "auth", f"{exc}.{advice} Athena keeps retrying on its own (at most "
                f"every {int(CREDENTIAL_BACKOFF_CEILING_SEC // 60)} minutes).",
            )
            logger.warning("[nextdns-poller] auth failed: %s (retry in %.0fs)", exc, delay)
            self._update_snapshot()
            return delay
        except NextDNSClientError as exc:
            delay = self._transport_backoff.next()
            since = self._unreachable_since(self._now())
            self._reporter.failed(
                "transport", self._unreachable_text(since) if since is not None else
                f"Could not read from NextDNS: {exc}. Retrying automatically "
                f"(backing off up to {int(TRANSPORT_BACKOFF_CEILING_SEC // 60)} minutes).",
            )
            logger.warning("[nextdns-poller] transport error: %s (retry in %.0fs)", exc, delay)
            self._update_snapshot()
            return delay
        except Exception as exc:  # noqa: BLE001
            logger.exception("[nextdns-poller] unexpected error: %s", type(exc).__name__)
            self._reporter.failed(
                "internal", "The NextDNS poll failed inside Athena "
                f"({type(exc).__name__}); see the server log. Retrying automatically.",
            )
            self._update_snapshot()
            return self._interval
        self._throttled_until = None
        self._throttled_since = None
        self._credential_backoff.reset()
        self._transport_backoff.reset()
        self._auth_failures = 0
        since = self._unreachable_since(self._now())
        if since is not None:
            # Every call has failed for UNREACHABLE_AFTER_INTERVALS intervals
            # — however few profiles (and so calls) a cycle had.
            self._reporter.failed("transport", self._unreachable_text(since))
            if not self._unreachable_logged:
                self._unreachable_logged = True
                logger.warning("[nextdns-poller] no NextDNS call has succeeded since %s (%s)",
                               format_utc_ms(since), self._fail_text)
            return report.next_due_in
        if report.contacted:
            self._unreachable_logged = False
            self._reporter.ok()
        return report.next_due_in

    # ----- reachability (instance-wide, whatever the fleet size) -----

    def _vendor_failed(self, exc: Exception) -> None:
        """A call failed at transport level (unreachable, a timeout, a 5xx,
        a malformed answer): the first since the last success starts the
        unreachable clock."""
        if self._fail_since is None:
            self._fail_since = self._now()
        self._fail_text = _text(str(exc), 200)

    def _vendor_answered(self) -> None:
        """NextDNS answered (a success, a 404, a 403 / 429, a 401): it is
        reachable."""
        self._fail_since = None
        self._fail_text = ""

    def _unreachable_since(self, now: datetime) -> Optional[datetime]:
        """When calls started failing — if no call has succeeded for
        UNREACHABLE_AFTER_INTERVALS poll intervals since; else None."""
        since = self._fail_since
        if since is None:
            return None
        if (now - since).total_seconds() < UNREACHABLE_AFTER_INTERVALS * self._interval:
            return None
        return since

    def _unreachable_text(self, since: datetime) -> str:
        when = since.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        last = f" (the last error: {self._fail_text})" if self._fail_text else ""
        return (
            f"NextDNS unreachable since {when}: no NextDNS call has succeeded since "
            f"then{last}. Every profile keeps being retried on its own backoff (at most "
            f"every {int(PROFILE_BACKOFF['vendor'][1] // 60)} minutes); this clears with "
            "the next successful call."
        )

    # ----- one cycle -----

    def run_cycle(self) -> CycleReport:
        """One pass over everything that is due. Synchronous (a worker
        thread): every vendor call blocks on the shared limiter. Raises the
        client's errors (throttled / auth / a run of transport failures)
        after saving state; one profile's failure never ends the cycle."""
        report = CycleReport()
        self._cycle_pages = 0
        self._fail_run = 0
        self._shape_cache = {}
        self._busy_cache = {}
        if not self._prepared:
            self._prepare()
        try:
            mapped = self._mapped_profiles()
            if mapped is None:
                # The tenant map is unreadable: poll NOTHING (never a profile
                # that may have been unmapped since the last cycle).
                report.held = True
                report.errors.append("tenant map unreadable")
                report.next_due_in = min(self._interval, 60.0)
                return report
            self._sync(mapped)
            self._update_snapshot()
            now = self._now()
            if self._known is None:
                # After a start the panel needs the list (and it is the
                # cheapest first contact).
                self._maybe_discover(now, report, force=True, priority=PRIORITY_DISCOVERY,
                                     swallow=bool(mapped))
            if not mapped:
                report.held = True
                self._maybe_discover(now, report, swallow=False)
                report.next_due_in = self._until_discovery(self._interval)
                return report
            self._check_stretch(report)
            self._check_denied(report)
            # --- security first ---
            for st in self._new_profiles():
                if self._abort.is_set():
                    break
                self._profile_task(st, HEALTH_PATH, report,
                                   lambda s=st: self._initial_classification(s, report))
            for st in self._missing_due():
                if self._abort.is_set():
                    break
                self._profile_task(st, HEALTH_PATH, report, lambda s=st: self._probe_missing(s, report))
            for st in self._security_due():
                if self._abort.is_set():
                    break
                if st.pid not in self._profiles:
                    continue
                if self._backlog_due(st, self._now()):
                    self._profile_task(st, SECURITY_PATH, report, lambda s=st: self._pull_logs(s, report))
                if st.pid in self._profiles and self._is_security_due(st, self._now()) \
                        and not self._blocked(st, SECURITY_PATH, self._now()):
                    self._profile_task(st, SECURITY_PATH, report,
                                       lambda s=st: self._security_check(s, report))
            # --- then health, yielding to security as soon as it is due —
            # after a minimum share, so a stretched cycle (security always
            # due) still rolls up hours and still detects a lapse.
            health = 0
            for st in [*self._hourly_due(), *self._pending_due()]:
                if self._abort.is_set():
                    break
                if st.pid not in self._profiles:
                    continue
                if health >= MIN_HEALTH_TASKS_PER_CYCLE and self._any_security_due():
                    break
                health += 1
                if st.state == PENDING:
                    self._profile_task(st, HEALTH_PATH, report, lambda s=st: self._pending_check(s, report))
                else:
                    yield_now = health > MIN_HEALTH_TASKS_PER_CYCLE
                    self._profile_task(st, HOURLY_PATH, report,
                                       lambda s=st, y=yield_now: self._hourly(s, report, yield_to_security=y))
            # Profiles flagged this cycle (a second 404) are checked against
            # the profile list now, so a lapse they cause is decided — and
            # grouped — with the others of this cycle (a throttle on that
            # read still lets this cycle's decisions happen first).
            throttled: Optional[NextDNSThrottledError] = None
            try:
                self._check_denied(report)
            except NextDNSThrottledError as exc:
                throttled = exc
            self._resolve_lapses()
            self._close_buckets()
            if throttled is not None:
                raise throttled
            # The entity feed LAST: device presence + per-IP volume, per
            # profile — an optional read never preempts a lapse decision or a
            # bucket close.
            self._entity_feed(report)
            self._maybe_discover(self._now(), report, swallow=True)
            report.next_due_in = self._next_due_in()
            return report
        finally:
            self._end_of_cycle()

    def _end_of_cycle(self) -> None:
        """Write the changed state (at most every SAVE_EVERY_SEC), THEN the
        protection signals it decided."""
        if self._flush() != "skipped":
            self._deliver()
        self._update_snapshot()

    def flush_now(self) -> None:
        """Write everything now (a stop): the state, the outbox, the state again."""
        if self._flush(force=True) != "skipped":
            self._deliver()
        self._flush(force=True)

    # ----- one profile task, its failure isolated -----

    def _profile_task(self, st: ProfileState, path: str, report: CycleReport,
                      fn: Callable[[], None]) -> None:
        """Run one profile task. The profile's OWN failures (a vendor error,
        a 404, its tenant's store) are recorded on it and backed off; the
        cycle goes on with the other profiles. A throttle (a 403 included —
        counted on the endpoint class that got it — until the profile list
        says the profile is gone or that class is shown refused), a rejected
        key, a stop — or FLEET_FAILURE_RUN vendor failures in a row with no
        success between (NextDNS itself is down) — end the cycle."""
        if not self._still_mapped(st):
            return
        self._reading_hour = None
        self._ep = None
        try:
            fn()
        except (NextDNSAborted, NextDNSAuthError):
            raise
        except NextDNSThrottledError as exc:
            if exc.status is not None:
                self._vendor_answered()
            cls = self._ep or (EP_HOURLY if path == HOURLY_PATH else EP_PROFILE)
            if self._profile_denied(st, exc, cls, path):
                return
            raise
        except NextDNSNotFoundError:
            self._vendor_answered()
            self._not_found(st)
            return
        except NextDNSClientError as exc:
            self._fail_run += 1
            self._vendor_failed(exc)
            report.errors.append(f"{st.pid}: {exc}")
            # Vendor evidence for the gap rule: the hour being read (or the
            # current one) had a failed analytics call.
            hour = self._reading_hour or hour_key(self._now())
            st.error_hours = [h for h in st.error_hours if h != hour][-(RECENT_HOURS - 1):] + [hour]
            self._profile_failed(st, path, "vendor", f"NextDNS: {exc}")
            if self._fail_run >= FLEET_FAILURE_RUN:
                raise
            return
        except _StoreError as exc:
            report.errors.append(f"{st.pid}: {exc}")
            self._profile_failed(st, path, "store", str(exc))
            return
        self._profile_ok(st, path)
        self._update_snapshot()

    def _blocked(self, st: ProfileState, path: str, now: datetime) -> bool:
        mark = st.hourly_retry_at if path == HOURLY_PATH else st.retry_at
        at = _dt(mark)
        return at is not None and now < at

    def _profile_ok(self, st: ProfileState, path: str) -> None:
        """A profile task answered: its failures on that path are over. A
        403 streak ends only for the endpoint class that answered (the
        profile's reads, or its roll-ups) — an answer on its security path
        never hides that its roll-ups are being refused."""
        if st.pid not in self._profiles:
            return
        st.not_found = 0
        cls = EP_HOURLY if path == HOURLY_PATH else EP_PROFILE
        self._set_refused(st, cls, 0)
        self._refusal_mark.pop((st.pid, cls), None)
        if st.denied_kind != "access" or not (st.refused or st.refused_hourly
                                              or st.refused_series):
            st.denied_at = st.denied_kind = None
        if path == HOURLY_PATH:
            st.hourly_failures, st.hourly_retry_at = 0, None
        else:
            st.failures, st.retry_at = 0, None
        # A 'refused' problem is the class's that showed it: its roll-ups
        # (problem_path HOURLY_PATH) or its reads (any other path).
        refused_here = st.problem_kind == "refused" and (
            (st.problem_path == HOURLY_PATH) == (path == HOURLY_PATH))
        if st.problem_path == path or refused_here or (
                st.problem_kind in ("not_found", "access") and not st.missing):
            if st.problem_kind != "logs_off":
                st.problem = st.problem_kind = st.problem_path = st.problem_at = None

    @staticmethod
    def _refused_count(st: ProfileState, cls: str) -> int:
        return {EP_HOURLY: st.refused_hourly, EP_SERIES: st.refused_series}.get(cls, st.refused)

    @staticmethod
    def _set_refused(st: ProfileState, cls: str, n: int) -> None:
        if cls == EP_HOURLY:
            st.refused_hourly = n
        elif cls == EP_SERIES:
            st.refused_series = n
        else:
            st.refused = n

    def _forget_refusals(self, st: ProfileState) -> None:
        st.refused = st.refused_hourly = st.refused_series = 0
        for key in [k for k in self._refusal_mark if k[0] == st.pid]:
            del self._refusal_mark[key]
        self._seed_retry.pop(st.pid, None)

    def _profile_failed(self, st: ProfileState, path: str, kind: str, text: str) -> None:
        """Record one profile's failure and back it off. A vendor failure is
        about the PROFILE (every path waits); a local store failure only
        holds the path that writes (security or roll-up)."""
        now = self._now()
        base, ceiling = PROFILE_BACKOFF.get(kind, PROFILE_BACKOFF["vendor"])
        hourly_only = kind == "store" and path == HOURLY_PATH
        if hourly_only:
            st.hourly_failures += 1
            n = st.hourly_failures
        else:
            st.failures += 1
            n = st.failures
        delay = min(ceiling, base * (2.0 ** min(n - 1, 16)))
        retry = format_utc_ms(now + timedelta(seconds=delay))
        if hourly_only:
            st.hourly_retry_at = retry
        else:
            st.retry_at = retry
            if kind != "store":
                st.hourly_retry_at = max(st.hourly_retry_at or "", retry)
        if st.problem_kind != kind or st.problem_at is None:
            st.problem_at = format_utc_ms(now)
        st.problem, st.problem_kind, st.problem_path = _text(text, 240), kind, path
        log = logger.warning if n == 1 or (n & (n - 1)) == 0 else logger.debug
        log("[nextdns-poller] profile %s: %s task failed (%s, %d in a row); retrying in %.0fs "
            "— the other profiles go on", st.pid, path, kind, n, delay)

    def _profile_denied(self, st: ProfileState, exc: NextDNSThrottledError,
                        cls: str = EP_PROFILE, path: str = SECURITY_PATH) -> bool:
        """A 403 on one ENDPOINT CLASS of a profile (`cls`: its reads as a
        whole, its roll-up reads, its history call), counted on that class
        alone — an answer on another class never resets it. What it holds
        back, the interval doubling to REFUSED_RETRY_CEILING_SEC while it
        lasts: its reads → EVERY read of the profile; its roll-ups → its
        roll-ups only (its security checks go on); its history call → that
        call only (and, while the profile is being classified, the
        classification: it is never judged without its history after a
        mere throttle). A profile NextDNS keeps refusing never stalls the
        other profiles' roll-ups and lapse detection. Read at first as the
        throttle it usually is (a busy key is refused call by call): False —
        the cycle ends with the normal backoff. Whether the profile is
        really gone is the profile list's answer (`_check_denied`); a 403
        repeating on one class of this profile ALONE while the list still
        shows it becomes the profile's own problem ('refused': its reads,
        or its roll-ups) — True from then on: the cycle goes on and the key
        is not blamed; on its history call it is a failed read (counted: one
        retry a day, local learning) — True. A missing / inaccessible
        profile's re-probe refused again: True — still gone, the cycle goes
        on."""
        if exc.status != 403:
            return False
        now = self._now()
        if st.missing:
            st.health_at, st.probe_due = format_utc_ms(now), False
            return True
        # Alone: no other refusal on the key since this class's last 403 on
        # this profile, and the key answered other calls in between (a
        # key-wide throttle refuses the others too). A repeat 403 of a
        # profile class already refused once (this one's own included) is
        # not "another refusal": several profiles refused at once (one owner
        # account un-sharing them) each still count as alone.
        key = (st.pid, cls)
        last = self._refusal_mark.get(key)
        if last is not None:
            self._suspect_403s += 1
        limiter = self._client.limiter
        mark = (int(getattr(limiter, "throttle_events", 0)) - self._suspect_403s,
                int(getattr(limiter, "successes", 0)))
        alone = last is None or (mark[0] <= last[0] and mark[1] > last[1])
        n = self._refused_count(st, cls) + 1 if alone else 1
        self._set_refused(st, cls, n)
        self._refusal_mark[key] = mark
        delay = min(REFUSED_RETRY_CEILING_SEC, self._interval * 2.0 ** min(n - 1, 16))
        retry = now + timedelta(seconds=delay)
        st.denied_at = st.denied_at or format_utc_ms(now)
        st.denied_kind = st.denied_kind or "access"
        if cls == EP_SERIES:
            if n >= REFUSED_BEFORE_PROBLEM and st.pid in (self._known or {}):
                # Refused again and again, on this call alone, the profile
                # still listed: a failed read — its baseline is learnt from
                # Athena's own roll-ups; asked again in a day (the budget).
                self._seed_calls[st.pid] = format_utc_ms(now)
                self._seed_retry.pop(st.pid, None)
                log = logger.warning if n == REFUSED_BEFORE_PROBLEM else logger.info
                log("[nextdns-poller] profile %s: NextDNS refuses its history (HTTP 403 %d times "
                    "in a row, on that call alone) although it lists the profile — its baseline "
                    "is learnt from Athena's own roll-ups; asked again in %d h", st.pid, n,
                    int(SEED_EVERY.total_seconds() // 3600))
                return True
            self._seed_retry[st.pid] = retry
            if path != HOURLY_PATH:
                st.retry_at = max(st.retry_at or "", format_utc_ms(retry))
            return False
        if cls == EP_HOURLY:
            st.hourly_retry_at = format_utc_ms(retry)
            return st.problem_kind == "refused"
        st.retry_at = st.hourly_retry_at = format_utc_ms(retry)
        return st.problem_kind == "refused" and st.problem_path != HOURLY_PATH

    def _refused_problem(self, st: ProfileState, cls: str = EP_PROFILE) -> None:
        """NextDNS keeps refusing this profile (403 on it alone, again and
        again) although the profile list still shows it: the profile's own
        problem — sharing / permissions at NextDNS — shown on the card, the
        panel and source health, never 'the key is rate limited'. No lapse:
        whether the site's DNS still works cannot be seen. `cls` EP_HOURLY:
        only its roll-up reads are refused — its blocks are still read."""
        hourly = cls == EP_HOURLY
        path = HOURLY_PATH if hourly else HEALTH_PATH
        if st.problem_kind != "refused" or st.problem_path != path:
            st.problem_at = format_utc_ms(self._now())
            logger.warning(
                "[nextdns-poller] NextDNS refuses %s of mapped profile %s (HTTP 403 %d times in "
                "a row, on it alone) although it still lists it: shown as the profile's own "
                "problem, retried at most hourly — the other profiles go on",
                "the hourly analytics" if hourly else "the data", st.pid,
                self._refused_count(st, cls))
        if hourly:
            st.problem = ("NextDNS refuses this profile's hourly analytics — check sharing/"
                          "permissions at my.nextdns.io: the profile is still listed for this "
                          "API key and its blocks are still read, but its analytics status "
                          "answers HTTP 403. Its hourly roll-ups and protection (lapse "
                          "detection) cannot be read until then; Athena retries it every hour.")
        else:
            st.problem = ("NextDNS refuses this profile — check sharing/permissions at "
                          "my.nextdns.io: the profile is still listed for this API key, but its "
                          "data answers HTTP 403 while every other profile answers. Its blocks "
                          "and protection cannot be read until then; Athena retries it every "
                          "hour.")
        st.problem_kind, st.problem_path = "refused", path

    def _check_denied(self, report: CycleReport) -> None:
        """Profiles NextDNS refused (403) or answered 404 twice since the list
        last spoke for them: is each still on GET /profiles (asked at low
        priority, at most once per profile per LIST_CHECK_EVERY; a listing
        read since the refusal answers without a call)? Listed → it was rate
        limiting / a vendor-side failure (normal backoff, nothing to report).
        Not listed → NOT ACCESSIBLE (403) / MISSING (404): shown, one lapse
        if active."""
        now = self._now()
        due = []
        for st in self._profiles.values():
            if not st.denied_at or st.missing:
                continue
            checked = _dt(st.list_checked_at)
            if checked is not None and now - checked < LIST_CHECK_EVERY:
                continue
            due.append(st)
        if not due:
            return
        oldest = min(_dt(st.denied_at) or now for st in due)
        if self._known is None or self._known_at is None or self._known_at < oldest:
            before = self._known_at
            self._maybe_discover(now, report, force=True, priority=PRIORITY_DISCOVERY,
                                 swallow=True)
            if self._known is None or self._known_at == before:
                return                      # not read: asked again next cycle
        for st in due:
            st.list_checked_at = format_utc_ms(now)
            kind = st.denied_kind or "access"
            if st.pid in (self._known or {}):
                if kind == "missing":
                    logger.info("[nextdns-poller] profile %s answered HTTP 404 but is still "
                                "listed: a vendor-side failure, retried with backoff", st.pid)
                    if st.problem_kind == "not_found":
                        st.problem = ("NextDNS answers HTTP 404 for this profile although it "
                                      "still lists it — a vendor-side failure, retried with "
                                      "backoff (no lapse).")
                elif st.refused >= REFUSED_BEFORE_PROBLEM:
                    self._refused_problem(st, EP_PROFILE)
                elif st.refused_hourly >= REFUSED_BEFORE_PROBLEM and not (
                        st.problem_kind == "refused" and st.problem_path != HOURLY_PATH):
                    self._refused_problem(st, EP_HOURLY)
                else:
                    logger.info("[nextdns-poller] profile %s was refused (HTTP 403) but is "
                                "still listed: read as rate limiting", st.pid)
                st.denied_at = st.denied_kind = None
            elif self._still_mapped(st):
                self._mark_missing(st, kind=kind)

    def _not_found(self, st: ProfileState) -> None:
        """A 404 on one profile. Once: checked again next interval. Again:
        is the profile still on GET /profiles (`_check_denied`, this cycle's
        end)? Only a profile the list no longer shows is MISSING; a listed
        one is a vendor-side failure — backed off like any other, no lapse
        (a short 404 storm on listed profiles is not N lapses)."""
        now = self._now()
        if st.missing:
            st.health_at, st.probe_due = format_utc_ms(now), False
            return
        st.not_found += 1
        if st.not_found >= NOT_FOUND_BEFORE_MISSING:
            if not st.denied_at:
                st.denied_at, st.denied_kind = format_utc_ms(now), "missing"
            st.failures += 1
            base, ceiling = PROFILE_BACKOFF["vendor"]
            delay = min(ceiling, base * (2.0 ** min(st.failures - 1, 16)))
            st.retry_at = st.hourly_retry_at = format_utc_ms(now + timedelta(seconds=delay))
            if st.problem_kind != "not_found" or st.problem_at is None:
                st.problem_at = format_utc_ms(now)
            st.problem = (f"NextDNS answered HTTP 404 for this profile {st.not_found} times in a "
                          "row — checking whether it still lists the profile; retried with "
                          "backoff meanwhile.")
            st.problem_kind, st.problem_path = "not_found", SECURITY_PATH
            return
        retry = format_utc_ms(now + timedelta(seconds=self._interval))
        st.retry_at = st.hourly_retry_at = retry
        st.problem = "NextDNS answered HTTP 404 for this profile once — checking it again."
        st.problem_kind, st.problem_path, st.problem_at = "not_found", SECURITY_PATH, format_utc_ms(now)
        logger.warning("[nextdns-poller] NextDNS answered 404 for mapped profile %s; "
                       "checking again in %.0fs", st.pid, self._interval)

    # ----- preparation and persistence -----

    def _prepare(self) -> None:
        self._prepared = True
        if self._instance_id is None:
            return
        raw = poller_state.load(self._instance_id, STATE_KEY)
        rows = poller_state.load_prefix(self._instance_id, PROFILE_KEY_PREFIX) or {}
        for key, value in rows.items():
            pid = valid_profile_id(key[len(PROFILE_KEY_PREFIX):])
            if pid is None:
                continue
            st = ProfileState.from_json(pid, value)
            if st is not None:
                self._profiles[pid] = st
                self._persisted[key] = poller_state.dumps(value)
                tried = _dt(value.get("seed_tried_at"))       # a pre-round-5 row
                if tried is not None:
                    self._seed_calls[pid] = format_utc_ms(tried)
        if isinstance(raw, dict) and isinstance(raw.get("seed_calls"), dict):
            for pid, at in raw["seed_calls"].items():
                when = _dt(at) if isinstance(at, str) else None
                if valid_profile_id(pid) is not None and when is not None:
                    self._seed_calls[pid] = max(self._seed_calls.get(pid, ""),
                                                format_utc_ms(when))
        seeds = poller_state.load_prefix(self._instance_id, SEED_KEY_PREFIX)
        if seeds is None:
            # Unreadable now: a stored seed may exist — no history call for a
            # day (the one-call-a-day budget holds), local learning meanwhile.
            mark = format_utc_ms(self._now())
            for pid in self._profiles:
                self._seed_calls.setdefault(pid, mark)
            seeds = {}
        for key, value in seeds.items():
            # Every stored seed row is remembered; a profile's own is
            # loaded, an unmapped profile's is parked (a re-mapping within
            # the day reuses it; deleted by a later write once a day old).
            self._persisted[key] = poller_state.dumps(value)
            pid = valid_profile_id(key[len(SEED_KEY_PREFIX):]) or ""
            owner = self._profiles.get(pid)
            if owner is not None:
                owner.seed = valid_seed(value)
            elif pid and valid_seed(value) is not None:
                self._parked_seeds[pid] = valid_seed(value)  # type: ignore[assignment]
        if isinstance(raw, dict):
            self._persisted[STATE_KEY] = poller_state.dumps(raw)
            legacy = raw.get("profiles")             # a v1 single-row state
            if isinstance(legacy, dict):
                for pid, value in legacy.items():
                    if valid_profile_id(pid) is None or pid in self._profiles:
                        continue
                    st = ProfileState.from_json(pid, value)
                    if st is not None:
                        self._profiles[pid] = st
            for name, target in (("gaps", "_gap_hours"), ("gaps_expired", "_gap_expired")):
                value = raw.get(name)
                if isinstance(value, list):
                    setattr(self, target, [g for g in value if isinstance(g, str)][-RECENT_HOURS:])
            if isinstance(raw.get("fleet"), dict):
                self._fleet = raw["fleet"]
            outbox = raw.get("outbox")
            if isinstance(outbox, list):
                self._outbox = [i for i in outbox if isinstance(i, dict)
                                and isinstance(i.get("seq"), int)
                                and i.get("op") in ("event", "note")]
            if isinstance(raw.get("seq"), int):
                self._seq = raw["seq"]
            key_ok = _dt(raw.get("key_ok_at"))
            if key_ok is not None:
                self._key_ok_at = self._key_ok_persisted = format_utc_ms(key_ok)
                age = (self._now() - key_ok).total_seconds()
                self._client.limiter.seed_success_age(max(0.0, age))
        seqs = [i["seq"] for st in self._profiles.values() for i in st.outbox]
        seqs += [i["seq"] for i in self._outbox]
        self._seq = max([self._seq, *seqs])
        self._durable_seq = self._seq                  # everything loaded is stored

    def _global_state(self) -> dict[str, Any]:
        out: dict[str, Any] = {"v": STATE_VERSION, "seq": self._seq}
        if self._key_ok_persisted:
            out["key_ok_at"] = self._key_ok_persisted
        if self._gap_hours:
            out["gaps"] = self._gap_hours
        if self._gap_expired:
            out["gaps_expired"] = self._gap_expired
        if self._fleet:
            out["fleet"] = self._fleet
        if self._outbox:
            out["outbox"] = self._outbox
        self._prune_seed_budget()
        if self._seed_calls:
            out["seed_calls"] = dict(sorted(self._seed_calls.items()))
        return out

    def _prune_seed_budget(self) -> None:
        """Forget history attempts (and parked seeds) a day old: the budget
        allows a new call then anyway."""
        now = self._now()
        for pid, at in list(self._seed_calls.items()):
            when = _dt(at)
            if when is None or now - when >= SEED_EVERY:
                del self._seed_calls[pid]
        for pid, seed in list(self._parked_seeds.items()):
            when = _dt(seed.get("at"))
            if pid in self._profiles or when is None or now - when >= SEED_EVERY:
                del self._parked_seeds[pid]

    def _flush(self, *, force: bool = False) -> str:
        """Write the rows that changed since they were last written — one
        transaction, at most every SAVE_EVERY_SEC unless `force`. Returns
        'ok' (durable), 'skipped' (too soon: the next cycle's end), or
        'failed' (the registry refused: logged; the outbox is delivered
        anyway — a restart may then repeat a signal, never lose one)."""
        if self._instance_id is None:
            self._durable_seq = self._seq
            return "ok"
        now = self._now()
        if (not force and self._flushed_at is not None
                and (now - self._flushed_at).total_seconds() < SAVE_EVERY_SEC):
            return "skipped"
        values: dict[str, Any] = {}
        texts: dict[str, str] = {}
        gstate = self._global_state()
        gtext = poller_state.dumps(gstate)
        if gtext != self._persisted.get(STATE_KEY):
            values[STATE_KEY], texts[STATE_KEY] = gstate, gtext
        for pid, st in self._profiles.items():
            key = profile_state_key(pid)
            data = st.to_json()
            text = poller_state.dumps(data)
            if text != self._persisted.get(key):
                values[key], texts[key] = data, text
            if st.seed is not None:
                key = seed_state_key(pid)
                text = poller_state.dumps(st.seed)
                if text != self._persisted.get(key):
                    values[key], texts[key] = st.seed, text
        for pid, seed in self._parked_seeds.items():
            key = seed_state_key(pid)
            text = poller_state.dumps(seed)
            if text != self._persisted.get(key):
                values[key], texts[key] = seed, text

        def gone_row(key: str) -> bool:
            if key.startswith(PROFILE_KEY_PREFIX):
                return key[len(PROFILE_KEY_PREFIX):] not in self._profiles
            if key.startswith(SEED_KEY_PREFIX):
                pid = key[len(SEED_KEY_PREFIX):]
                owner = self._profiles.get(pid)
                if owner is None:
                    return pid not in self._parked_seeds
                return owner.seed is None
            return False
        gone = [k for k in self._persisted if gone_row(k)]
        seq = self._seq
        if not values and not gone:
            self._durable_seq = seq
            return "ok"
        ok = poller_state.save_many(self._instance_id, values, delete=gone)
        self._flushed_at = now
        self._durable_seq = seq
        if not ok:
            return "failed"
        self._persisted.update(texts)
        for key in gone:
            self._persisted.pop(key, None)
        return "ok"

    def _contact_ok(self) -> None:
        now = self._now()
        self._key_ok_at = format_utc_ms(now)
        persisted = _dt(self._key_ok_persisted)
        if persisted is None or now - persisted >= KEY_OK_PERSIST_EVERY:
            self._key_ok_persisted = self._key_ok_at
        self._fail_run = 0
        self._vendor_answered()

    # ----- the outbox: protection signals, written once their state is stored -----

    def _queue(self, st: Optional[ProfileState], item: dict[str, Any]) -> None:
        self._seq += 1
        item["seq"] = self._seq
        (st.outbox if st is not None else self._outbox).append(item)

    def _undurable(self) -> bool:
        """Is a queued item waiting for its state to be written?"""
        return any(i.get("seq", 0) > self._durable_seq
                   for box in (self._outbox, *(st.outbox for st in self._profiles.values()))
                   for i in box)

    def _deliver(self) -> None:
        """Write every queued signal / note whose state is stored. An item a
        local fault cannot write stays queued (next cycle); a crash after
        the write is harmless: the next start writes it again and the sink /
        the note marker find the same one."""
        owners: list[Optional[ProfileState]] = [*sorted(self._profiles.values(), key=lambda s: s.pid), None]
        for st in owners:
            box = st.outbox if st is not None else self._outbox
            while box and box[0].get("seq", 0) <= self._durable_seq:
                item = box[0]
                try:
                    self._deliver_item(st, item, box)
                except (sqlite3.Error, OSError) as exc:
                    logger.warning("[nextdns-poller] a queued %s was not written (%s); "
                                   "retried next cycle", item.get("kind") or item.get("op"),
                                   type(exc).__name__)
                    break
                box.pop(0)

    def _deliver_item(self, st: Optional[ProfileState], item: dict[str, Any],
                      box: list[dict[str, Any]]) -> None:
        slug = item.get("slug")
        if not isinstance(slug, str):
            return
        if item["op"] == "note":
            event_id = item.get("event_id")
            if isinstance(event_id, int):
                write_note(slug, event_id, str(item.get("text") or ""),
                           marker=str(item.get("marker") or ""),
                           query_kind=str(item.get("query_kind") or NOTE_KIND_VENDOR))
            return
        payload = item.get("payload")
        if not isinstance(payload, dict):
            return
        event_id = self._ingest(slug, payload)
        if event_id is None:
            return
        vid = item.get("vid")
        for later in box[1:]:
            # What waited for this alert's id: a restoration linking its
            # lapse, a note on it.
            if later.get("lapse_vid") == vid and isinstance(later.get("payload"), dict):
                later["payload"]["lapse_event_id"] = event_id
                later["lapse_vid"] = None
            if later.get("event_vid") == vid:
                later["event_id"] = event_id
        kind = item.get("kind")
        if kind == "fleet":
            if self._fleet is not None and self._fleet.get("vid") == vid:
                self._fleet["event_id"] = event_id
            return
        if st is None:
            return
        if kind == "lapse":
            if st.lapse and st.lapse.get("vid") == vid:
                st.lapse["event_id"] = event_id
            if st.last_restore and st.last_restore.get("lapse_vid") == vid:
                st.last_restore["lapse_event_id"] = event_id
        elif kind == "restore":
            if st.last_restore and st.last_restore.get("restored_vid") == vid:
                st.last_restore["restored_event_id"] = event_id
            lapse = item.get("lapse") if isinstance(item.get("lapse"), dict) else {}
            lapse_event = payload.get("lapse_event_id")
            self._restoration_notes(
                slug, st.label or st.pid, event_id,
                lapse_event if isinstance(lapse_event, int) else None,
                lapse, str(item.get("restored_hour") or ""),
            )

    # ----- the mapped set -----

    def _mapped_profiles(self) -> Optional[dict[str, tuple[str, str]]]:
        """profile id → (tenant slug, label) for every profile mapped to an
        ACTIVE tenant. Everything else is never polled. None when the tenant
        map cannot be read (the caller then polls nothing)."""
        if self._instance_id is None:
            return {}
        try:
            mappings = tenant_map.get_mappings(self._instance_id)
            reg = connect(paths.registry_db_path(), read_only=True)
            try:
                active = {
                    r[0] for r in reg.execute("SELECT slug FROM clients WHERE status = 'active'")
                }
            finally:
                reg.close()
        except sqlite3.Error as exc:
            logger.warning("[nextdns-poller] tenant map unreadable (%s); polling nothing "
                           "this cycle", type(exc).__name__)
            return None
        out: dict[str, tuple[str, str]] = {}
        for m in mappings:
            pid = valid_profile_id(m.vendor_tenant_id)
            if pid is None or m.octo_client_slug not in active:
                continue
            label = m.vendor_tenant_label or (self._known or {}).get(pid) or ""
            out[pid] = (m.octo_client_slug, _text(label, 120))
        return out

    def _mapped_slug(self, pid: str) -> Optional[str]:
        """The ACTIVE tenant `pid` maps to right now (one small registry
        read). Raises sqlite3.Error."""
        if self._instance_id is None:
            return None
        reg = connect(paths.registry_db_path(), read_only=True)
        try:
            row = reg.execute(
                "SELECT m.octo_client_slug FROM adapter_tenant_map m "
                "JOIN clients c ON c.slug = m.octo_client_slug "
                "WHERE m.adapter_instance_id = ? AND m.vendor_tenant_id = ? "
                "AND c.status = 'active'",
                (self._instance_id, pid),
            ).fetchone()
        finally:
            reg.close()
        return row[0] if row else None

    def _still_mapped(self, st: ProfileState) -> bool:
        """Re-read the profile's mapping right before touching it: unmapped
        (or its tenant left) → dropped now; re-mapped → skipped (the next
        cycle re-points it); unreadable → skipped (fail closed)."""
        if st.pid not in self._profiles:
            return False
        if self._instance_id is None:
            return True
        try:
            slug = self._mapped_slug(st.pid)
        except sqlite3.Error:
            return False
        if slug is None:
            logger.info("[nextdns-poller] profile %s was unmapped; not polled again", st.pid)
            self._drop(st.pid)
            return False
        return slug == st.slug

    def _drop(self, pid: str) -> None:
        """An unmapped profile (or its tenant left): never polled again. Its
        NextDNS history seed is parked — not a call, the site's own — so a
        re-mapping within the day reuses it (the history budget holds)."""
        st = self._profiles.pop(pid, None)
        if st is not None and st.seed is not None:
            self._parked_seeds[pid] = st.seed
        for key in [k for k in self._refusal_mark if k[0] == pid]:
            del self._refusal_mark[key]
        self._seed_retry.pop(pid, None)
        self._seed_views.pop(pid, None)
        self._local_full.pop(pid, None)

    def _internal_tenant(self) -> Optional[str]:
        """The operator's own tenant — the ACTIVE client of kind 'internal'
        (the oldest when there are several) — where fleet-wide signals go."""
        try:
            reg = connect(paths.registry_db_path(), read_only=True)
            try:
                row = reg.execute(
                    "SELECT slug FROM clients WHERE kind = 'internal' AND status = 'active' "
                    "ORDER BY onboarded_at, slug LIMIT 1").fetchone()
            finally:
                reg.close()
        except sqlite3.Error:
            return None
        return row[0] if row else None

    def _sync(self, mapped: dict[str, tuple[str, str]]) -> None:
        for pid, (slug, label) in mapped.items():
            st = self._profiles.get(pid)
            if st is None:
                self._profiles[pid] = ProfileState(pid=pid, slug=slug, label=label,
                                                   seed=self._parked_seeds.pop(pid, None))
                continue
            if st.slug != slug:
                self._remapped(st, slug)
            st.label = label or st.label
        for pid in [p for p in self._profiles if p not in mapped]:
            # Unmapped (or its tenant left): never polled again; a later
            # re-mapping starts afresh (24 h back-fill, deduplicated).
            self._drop(pid)

    def _remapped(self, st: ProfileState, slug: str) -> None:
        """Re-pointed to another tenant: NEW rows go there, the security
        marks stay (no back-fill into the new tenant, and a pending log pull
        of the old mapping is dropped), and protection starts afresh — the
        old tenant's open lapse gets a neutral note (never the new tenant's
        name or event ids); anything still queued for the old tenant is
        dropped. The NextDNS history seed and the hours inside its lapses
        are kept: they are the site's own (a seed that no longer reaches the
        new tenant's roll-ups is read again — `_seed_needed`)."""
        old = st.slug
        lapse = st.lapse or {}
        event_id = lapse.get("event_id")
        if isinstance(event_id, int) and lapse.get("slug") == old:
            write_note(
                old, event_id,
                "The NextDNS profile was re-mapped to another client: its DNS-filtering "
                "protection is no longer tracked on this alert.",
                marker=f"remapped:{st.pid}:{event_id}", query_kind=NOTE_KIND_VENDOR,
            )
        logger.info("[nextdns-poller] profile %s re-mapped; protection re-checked", st.pid)
        st.slug = slug
        st.logs = None
        st.state, st.state_since, st.ever_active = NEW, None, False
        st.zero_hours, st.zero_since, st.busy_since, st.zero_list = 0, None, None, []
        st.recent_zero, st.error_hours = [], []
        st.first_hour = None
        self._local_full.pop(st.pid, None)       # the new tenant's roll-ups start now
        self._seed_retry.pop(st.pid, None)       # classified afresh: with its history
        st.lapse = st.lapse_pending = st.last_restore = None
        st.restore_streak = 0
        st.outbox = []

    # ----- scheduling -----

    def _new_profiles(self) -> list[ProfileState]:
        now = self._now()
        return [st for st in self._profiles.values()
                if st.state == NEW and not st.missing
                and not self._blocked(st, HEALTH_PATH, now)]

    def _missing_due(self) -> list[ProfileState]:
        now = self._now()
        out = []
        for st in self._profiles.values():
            if not st.missing or self._blocked(st, HEALTH_PATH, now):
                continue
            last = _dt(st.health_at)
            if st.probe_due or last is None or now - last >= self._pending_every:
                out.append(st)
        return sorted(out, key=lambda s: (s.health_at or "", s.pid))

    def _is_security_due(self, st: ProfileState, now: datetime) -> bool:
        if st.state not in (ACTIVE, LAPSED) or st.missing:
            return False
        last = _dt(st.checked_to)
        return last is None or (now - last).total_seconds() >= self._interval

    def _page_budget_left(self, st: ProfileState, now: datetime) -> bool:
        return st.pages_hour != hour_key(now) or st.pages_in_hour < MAX_LOG_PAGES_PER_PROFILE_PER_HOUR

    def _backlog_due(self, st: ProfileState, now: datetime) -> bool:
        return bool(
            st.logs and st.state in (ACTIVE, LAPSED) and not st.missing
            and not self._blocked(st, SECURITY_PATH, now)
            and self._page_budget_left(st, now)
        )

    def _any_security_due(self) -> bool:
        now = self._now()
        return any(
            not self._blocked(st, SECURITY_PATH, now)
            and (self._is_security_due(st, now) or self._backlog_due(st, now))
            for st in self._profiles.values()
        )

    def _security_due(self) -> list[ProfileState]:
        now = self._now()
        due = [
            st for st in self._profiles.values()
            if not self._blocked(st, SECURITY_PATH, now)
            and (self._backlog_due(st, now) or self._is_security_due(st, now))
        ]
        # A pending log pull first, then the most overdue check.
        return sorted(due, key=lambda s: (0 if s.logs else 1, s.checked_to or "", s.pid))

    def _closed_hours(self, st: ProfileState, now: datetime) -> list[datetime]:
        """Closed clock hours not yet rolled up (read HOURLY_DELAY_SEC after
        they close), oldest first, never more than 24 h back. A profile's
        first roll-up is the most recent closed hour."""
        latest = _hour_floor(now - timedelta(seconds=HOURLY_DELAY_SEC)) - timedelta(hours=1)
        floor = _hour_floor(now) - HOURLY_LOOKBACK
        done = _dt(st.hour_done)
        start = latest if done is None else max(done + timedelta(hours=1), floor)
        hours: list[datetime] = []
        h = start
        while h <= latest and len(hours) < MAX_HOURS_PER_PROFILE_PER_CYCLE:
            hours.append(h)
            h += timedelta(hours=1)
        return hours

    def _hourly_due(self) -> list[ProfileState]:
        now = self._now()
        return sorted(
            (st for st in self._profiles.values()
             if st.state in (ACTIVE, LAPSED) and not st.missing
             and not self._blocked(st, HOURLY_PATH, now)
             and self._closed_hours(st, now)),
            key=lambda s: (s.hour_done or "", s.pid),
        )

    def _pending_due(self) -> list[ProfileState]:
        now = self._now()
        out = []
        for st in self._profiles.values():
            if st.state != PENDING or st.missing or self._blocked(st, HEALTH_PATH, now):
                continue
            last = _dt(st.health_at)
            if last is None or now - last >= self._pending_every:
                out.append(st)
        return sorted(out, key=lambda s: (s.health_at or "", s.pid))

    def _until_discovery(self, default: float) -> float:
        if self._discovery_due is None:
            return default
        return max(1.0, min(default, (self._discovery_due - self._now()).total_seconds()))

    def _next_due_in(self) -> float:
        now = self._now()
        waits = [self._interval, self._until_discovery(DISCOVERY_EVERY_SEC)]

        def until(mark: Optional[str]) -> float:
            at = _dt(mark)
            return 0.0 if at is None else (at - now).total_seconds()

        if self._flushed_at is not None and self._undurable():
            # A queued signal waits for the next state write.
            waits.append(SAVE_EVERY_SEC - (now - self._flushed_at).total_seconds())
        for st in self._profiles.values():
            if st.missing:
                last = _dt(st.health_at)
                if st.probe_due or last is None:
                    waits.append(max(0.0, until(st.retry_at)))
                else:
                    waits.append(max(until(st.retry_at),
                                     (last + self._pending_every - now).total_seconds()))
                continue
            if st.state in (ACTIVE, LAPSED):
                if self._blocked(st, SECURITY_PATH, now):
                    waits.append(until(st.retry_at))
                else:
                    if self._backlog_due(st, now):
                        waits.append(0.0)
                    elif st.logs:
                        # This profile's page budget for the hour is spent.
                        waits.append((_hour_floor(now) + timedelta(hours=1) - now).total_seconds())
                    last = _dt(st.checked_to)
                    waits.append(0.0 if last is None
                                 else self._interval - (now - last).total_seconds())
                if self._blocked(st, HOURLY_PATH, now):
                    waits.append(until(st.hourly_retry_at))
                elif self._closed_hours(st, now):
                    waits.append(0.0)
                else:
                    # The next hour becomes readable HOURLY_DELAY_SEC after
                    # it closes.
                    delay = timedelta(seconds=HOURLY_DELAY_SEC)
                    nxt = _hour_floor(now - delay) + timedelta(hours=1) + delay
                    waits.append((nxt - now).total_seconds())
            elif st.state == PENDING:
                last = _dt(st.health_at)
                due = 0.0 if last is None else (last + self._pending_every - now).total_seconds()
                waits.append(max(due, until(st.retry_at)))
            elif st.state == NEW:
                waits.append(max(0.0, until(st.retry_at)))
        return max(1.0, min(waits))

    def planned_calls_per_hour(self) -> dict[str, float]:
        """The steady-state budget for the current mapped set (no log pulls):
        security 3600/interval per ACTIVE/LAPSED profile, 2 hourly reads
        each (status + reasons — the reasons read is skipped for an hour
        with no blocks), a 24-h status read per PENDING profile every
        pending_check_sec (+ its logging settings at most daily), discovery
        every 6 h."""
        watched = sum(1 for s in self._profiles.values()
                      if s.state in (ACTIVE, LAPSED) and not s.missing)
        pending = sum(1 for s in self._profiles.values() if s.state == PENDING or s.missing)
        security = watched * 3600.0 / self._interval
        hourly = watched * 2.0
        pend = pending * 3600.0 / self._pending_every.total_seconds() + pending / 24.0
        discovery = 3600.0 / DISCOVERY_EVERY_SEC
        return {
            "security": security, "hourly": hourly, "pending": pend,
            "discovery": discovery, "total": security + hourly + pend + discovery,
        }

    def _rollup_lag_hours(self, now: datetime) -> int:
        """How far the roll-ups lag behind (the stretch). A profile whose own
        reads fail (refused, 404, errors, its store) is left out: it lags for
        its own problem, shown as such on it — a profile NextDNS is refusing
        (403) too, before it is shown as refused."""
        latest = _hour_floor(now - timedelta(seconds=HOURLY_DELAY_SEC)) - timedelta(hours=1)
        lag = 0
        for st in self._profiles.values():
            if st.state not in (ACTIVE, LAPSED) or st.missing or st.refused or st.refused_hourly:
                continue
            if st.problem and st.problem_kind != "logs_off":
                continue
            done = _dt(st.hour_done)
            if done is not None:
                lag = max(lag, int((latest - done).total_seconds() // 3600))
        return lag

    def _security_round_sec(self, planned_per_hour: float) -> float:
        """The effective security round: `interval`, stretched by the
        limiter when a round of checks (watched × spacing) or the hour's
        planned calls do not fit (`_check_stretch`)."""
        watched = sum(1 for s in self._profiles.values()
                      if s.state in (ACTIVE, LAPSED) and not s.missing)
        spacing = float(self._client.limiter.min_spacing_sec)
        out = max(self._interval, watched * spacing)
        room = 3600.0 * (1.0 - LOG_ALLOWANCE_SHARE)
        if room > 0 and planned_per_hour * spacing > room:
            out = max(out, self._interval * planned_per_hour * spacing / room)
        return out

    def _check_stretch(self, report: CycleReport) -> None:
        """Does the planned polling fit the limiter? A round of security
        checks needs watched × spacing seconds (≤ the interval), and the
        hour's planned calls (security + roll-ups + pending + discovery) ×
        spacing must leave LOG_ALLOWANCE_SHARE of the hour for log pulls
        and searches. When not, the cycle STRETCHES (the limiter never lets
        calls bunch): checks come less often and roll-ups lag. Said once
        per episode."""
        watched = sum(1 for s in self._profiles.values()
                      if s.state in (ACTIVE, LAPSED) and not s.missing)
        spacing = self._client.limiter.min_spacing_sec
        need_round = watched * spacing
        planned = self.planned_calls_per_hour()["total"]
        need_hour = planned * spacing
        stretched = (need_round > self._interval
                     or need_hour > 3600.0 * (1.0 - LOG_ALLOWANCE_SHARE))
        report.stretched = stretched
        self._stretched = stretched
        if stretched and not self._stretch_logged:
            self._stretch_logged = True
            logger.warning(
                "[nextdns-poller] %d watched profiles need %.0f calls/h × %.1f s spacing = "
                "%.0f s of every hour (a security round %.0f s against the %.0f s interval): "
                "the cycle stretches — each profile is checked less often and hourly "
                "roll-ups lag (calls are never bunched)",
                watched, planned, spacing, need_hour, need_round, self._interval,
            )
        elif not stretched and self._stretch_logged:
            self._stretch_logged = False
            logger.info("[nextdns-poller] the planned polling fits the limiter again")

    # ----- tasks: classification / pending / missing -----

    def _status_total(self, st: ProfileState, since: timedelta) -> int:
        now = self._now()
        status = self._client.analytics_status(
            st.pid, from_=now - since, to=now, priority=PRIORITY_HEALTH,
        )
        self._contact_ok()
        return sum(status.values())

    def _status_24h(self, st: ProfileState) -> int:
        total = self._status_total(st, timedelta(hours=24))
        st.q24, st.q24_at = total, format_utc_ms(self._now())
        if total > 0:
            self._logging_seen(st)
        return total

    def _logging_seen(self, st: ProfileState) -> None:
        """Queries are being reported: logging is on at NextDNS."""
        if st.problem_kind == "logs_off":
            st.problem = st.problem_kind = st.problem_path = st.problem_at = None
            st.logs_enabled = True

    def _active_threshold(self, st: ProfileState) -> int:
        """ACTIVE_THRESHOLD over 24 h — scaled down when the profile keeps
        its logs (and so its analytics) for less than 24 h."""
        retention = st.retention_sec
        if retention and retention < 86400:
            return max(1, math.ceil(ACTIVE_THRESHOLD * retention / 86400.0))
        return ACTIVE_THRESHOLD

    def _read_settings(self, st: ProfileState, *, force: bool = False) -> None:
        """The profile's logging settings (one call, at most daily unless
        forced). Logging off is shown as its own problem."""
        now = self._now()
        last = _dt(st.settings_at)
        if not force and last is not None and now - last < SETTINGS_EVERY:
            return
        enabled, retention = self._client.profile_logs(st.pid, priority=PRIORITY_HEALTH)
        self._contact_ok()
        st.logs_enabled, st.retention_sec, st.settings_at = enabled, retention, format_utc_ms(now)
        if enabled is False:
            if st.problem_kind != "logs_off":
                st.problem_at = format_utc_ms(now)
            st.problem = ("Logging is turned off for this profile at NextDNS, so neither "
                          "NextDNS analytics nor Athena can see its queries.")
            st.problem_kind, st.problem_path = "logs_off", HEALTH_PATH
        elif st.problem_kind == "logs_off":
            st.problem = st.problem_kind = st.problem_path = st.problem_at = None

    def _classify(self, st: ProfileState, total: int, report: CycleReport) -> None:
        """A newly mapped (or re-appearing NEW) profile: ACTIVE; or — with
        NO queries in 24 h — a 7-day look: ≥ 100 then means dark since
        before it was mapped (LAPSED, one lapse signal) — unless its NextDNS
        history says it is normally silent at this time of the week (a
        weekend-closed office mapped on a Sunday): then ACTIVE without an
        alert when its busiest 24 h of the last week reach the gate, else
        PENDING. Anything else (1–99 a day included) is PENDING (plus its
        logging settings)."""
        now = format_utc_ms(self._now())
        st.health_at = now
        if total >= self._active_threshold(st):
            st.state, st.ever_active, st.state_since = ACTIVE, True, now
            return
        if total == 0:
            week = self._status_total(st, BEFORE_WATCH_LOOKBACK)
            report.health_checks += 1
            if week >= ACTIVE_THRESHOLD:
                dark = self._dark_when_mapped(st, report)
                if dark is not False:
                    st.ever_active = True
                    st.state, st.state_since = ACTIVE, now
                    self._raise_lapse(st, {
                        "hour": hour_key(self._now()), "since": None, "at": now,
                        "cause": "before_watch", "queries_7d": int(week),
                    })
                    return
                if self._peak24(st) >= self._active_threshold(st):
                    st.state, st.ever_active, st.state_since = ACTIVE, True, now
                    logger.info("[nextdns-poller] profile %s is silent now, as it normally is "
                                "at this time of the week: active, no lapse", st.pid)
                    return
        self._read_settings(st, force=True)
        if total >= self._active_threshold(st):
            st.state, st.ever_active, st.state_since = ACTIVE, True, now
            return
        st.state, st.state_since = PENDING, now

    def _initial_classification(self, st: ProfileState, report: CycleReport) -> None:
        total = self._status_24h(st)
        report.contacted = True
        report.health_checks += 1
        self._classify(st, total, report)
        self._update_snapshot()

    def _pending_check(self, st: ProfileState, report: CycleReport) -> None:
        total = self._status_24h(st)
        report.contacted = True
        report.health_checks += 1
        now = format_utc_ms(self._now())
        st.health_at = now
        if total < self._active_threshold(st):
            self._read_settings(st)
        if total >= self._active_threshold(st):
            st.state, st.ever_active, st.state_since = ACTIVE, True, now
            logger.info("[nextdns-poller] profile %s is now routing DNS (active)", st.pid)

    def _probe_missing(self, st: ProfileState, report: CycleReport) -> None:
        """A missing / inaccessible profile, re-checked (every
        pending_check_sec, or at once when the profile list shows it again):
        a 404 / 403 keeps it so; an answer brings it back where it was."""
        total = self._status_24h(st)
        report.contacted = True
        report.health_checks += 1
        now = format_utc_ms(self._now())
        st.missing, st.probe_due, st.not_found, st.health_at = False, False, 0, now
        st.denied_at = st.denied_kind = None
        if (st.lapse_pending or {}).get("cause") in VISIBILITY_CAUSES:
            st.lapse_pending = None             # visible again before it was decided
        if st.problem_kind in ("missing", "not_found", "access", "refused"):
            st.problem = st.problem_kind = st.problem_path = st.problem_at = None
        logger.info("[nextdns-poller] profile %s is visible to the key again", st.pid)
        if st.state == NEW:
            self._classify(st, total, report)
        elif st.state == PENDING and total >= self._active_threshold(st):
            st.state, st.ever_active, st.state_since = ACTIVE, True, now

    def _mark_missing(self, st: ProfileState, *, kind: str = "missing") -> None:
        """NextDNS no longer shows the profile to the key: 404 twice
        (`missing`), or a 403 while the profile list no longer has it
        (`access`). Re-probed every pending_check_sec and as soon as the
        list shows it again; an ACTIVE profile lapses once."""
        now = self._now()
        if not st.missing:
            logger.warning(
                "[nextdns-poller] NextDNS no longer shows mapped profile %s to the key (%s); "
                "re-checked every %.0f h and when the profile list shows it again", st.pid,
                "HTTP 404 twice" if kind == "missing" else "HTTP 403, not listed",
                self._pending_every.total_seconds() / 3600,
            )
        st.missing = True
        st.logs = None
        st.probe_due = False
        self._forget_refusals(st)
        st.denied_at = st.denied_kind = None
        st.health_at = format_utc_ms(now)
        st.retry_at = st.hourly_retry_at = None
        if kind == "access":
            st.problem = ("NextDNS refuses this profile (HTTP 403) and no longer lists it for "
                          "this API key — it may no longer be shared with this account. "
                          "Re-checked every few hours and as soon as the profile list shows "
                          "it again.")
        else:
            st.problem = ("NextDNS does not show this profile to the API key any more (HTTP "
                          "404): deleted, or no longer shared with this account. Re-checked "
                          "every few hours and as soon as the profile list shows it again.")
        st.problem_kind, st.problem_path, st.problem_at = kind, HEALTH_PATH, format_utc_ms(now)
        if st.state == ACTIVE:
            self._lost_visibility(st, "not_accessible" if kind == "access" else "not_visible")

    def _lost_visibility(self, st: ProfileState, cause: str) -> None:
        """An ACTIVE profile NextDNS stopped showing to the key: the site's
        filtering can no longer be watched — ONE lapse signal, decided at
        this cycle's end with the others (many at once = the fleet step
        groups them under ONE incident)."""
        now = format_utc_ms(self._now())
        st.lapse_pending = {"hour": hour_key(self._now()), "since": None, "at": now,
                            "cause": cause, "decided": True, "first": now}

    # ----- tasks: security -----

    def _security_check(self, st: ProfileState, report: CycleReport) -> None:
        now = self._now()
        checked = _dt(st.checked_to)
        window_from = (checked - self._overlap) if checked else (now - BACKFILL)
        reasons = self._client.analytics_reasons(
            st.pid, from_=window_from, to=now, priority=PRIORITY_SECURITY,
        )
        self._contact_ok()
        report.contacted = True
        report.security_checks += 1
        signals = classification.signal_reason_counts(reasons)
        st.checked_to = format_utc_ms(now)
        if signals:
            window = st.logs or {"from": format_utc_ms(window_from), "to": None,
                                 "resume": None, "pages": 0}
            window["from"] = min(window["from"] or format_utc_ms(window_from),
                                 format_utc_ms(window_from))
            window["to"] = format_utc_ms(now)
            st.logs = window
        if st.logs and self._backlog_due(st, self._now()):
            self._pull_logs(st, report)

    def _end_window(self, st: ProfileState, why: Optional[str]) -> None:
        if why:
            logger.warning("[nextdns-poller] profile %s: log pull window ended early (%s); "
                           "the next checks go on from now", st.pid, why)
        st.logs = None

    def _pull_logs(self, st: ProfileState, report: CycleReport) -> None:
        window = st.logs
        if not window:
            return
        start = window.get("resume") or window.get("from")
        end = window.get("to")
        if not start or not end:
            st.logs = None
            return
        now_hour = hour_key(self._now())
        if st.pages_hour != now_hour:
            st.pages_hour, st.pages_in_hour = now_hour, 0
        cursor: Optional[str] = None
        pages = 0
        while (pages < self._max_pages_profile and self._cycle_pages < self._max_pages_cycle
               and st.pages_in_hour < MAX_LOG_PAGES_PER_PROFILE_PER_HOUR):
            if self._abort.is_set():
                return
            page = self._client.logs(
                st.pid, from_=start, to=end, status="blocked", cursor=cursor,
                sort="asc", limit=LOG_PAGE_SIZE, priority=PRIORITY_SECURITY,
            )
            self._contact_ok()
            report.contacted = True
            pages += 1
            self._cycle_pages += 1
            st.pages_in_hour += 1
            report.log_pages += 1
            window["pages"] = int(window.get("pages") or 0) + 1
            if not self._still_mapped(st):
                return
            newest = self._process_page(st, page.lines, report)
            if newest and (not window.get("resume") or newest > window["resume"]):
                window["resume"] = newest
            if not page.cursor:
                self._end_window(st, None)
                return
            if page.cursor == cursor:
                self._end_window(st, "NextDNS returned the same page cursor again")
                return
            if not page.lines:
                self._end_window(st, "an empty page still carried a cursor")
                return
            if window["pages"] >= MAX_LOG_PAGES_PER_WINDOW:
                self._end_window(st, f"more than {MAX_LOG_PAGES_PER_WINDOW} pages in one "
                                     "window — the rest of it is not read")
                return
            cursor = page.cursor
            st.logs = window
        # Page budget spent: the next cycle resumes from the newest line
        # processed (a fresh query — cursors are not kept across cycles).
        # Lines AT that millisecond are read again and counted once (the
        # bucket ledger); pages that all sat at the resume point itself
        # would never progress, so it steps one millisecond on — only when
        # pages WERE read this time (a spent cycle budget moves nothing).
        if pages > 0 and (window.get("resume") or "") <= start:
            window["resume"] = format_utc_ms(_dt(start) + timedelta(milliseconds=1))
        st.logs = window

    def _process_page(
        self, st: ProfileState, lines: list[dict[str, Any]], report: CycleReport,
    ) -> Optional[str]:
        """Count one page's signal lines in their buckets (ONE transaction),
        then write the alert of every bucket this page opened (or that a
        crash left claimed). Returns the newest line timestamp seen."""
        newest: Optional[str] = None
        items: list[tuple[store.Bucket, str, str, dict[str, Any], Any, str]] = []
        for line in lines:
            ts = normalize_timestamp(line.get("timestamp"), naive_is_utc=True)
            if not ts:
                continue
            if newest is None or ts > newest:
                newest = ts
            if classification.line_is_csam(line.get("reasons")):
                # RESTRICTED (rule B7, Rick 2026-10-06): never an ordinary
                # alert, never in the ledger — kept ONLY as restricted
                # evidence; the tier engine opens the Black.
                self._restricted(st, line, ts)
                continue
            lc = classification.classify_line(line.get("reasons"))
            if not lc.is_signal or lc.primary is None:
                continue
            device = line.get("device") if isinstance(line.get("device"), dict) else {}
            device_key = _text(device.get("id"), 64) or _text(line.get("clientIp"), 64)
            domain = _text(line.get("domain"), 253).lower().rstrip(".")
            root = _text(line.get("root"), 253).lower().rstrip(".") or domain
            reason = lc.primary.id or "unknown"
            # KNOWN BENIGN (registry, operator-editable): a matching rule files
            # the block at its level (LOW) in its OWN bucket — still blocked.
            benign = known_benign.match(
                "nextdns", domain, [r.id for r in lc.reasons if r.is_signal])
            if benign is not None:
                lc = classification.LineClass(benign.level, lc.primary, lc.reasons)
            span = classification.bucket_span(lc.level)
            start = ts[:13] + ":00:00Z" if span == store.SPAN_HOUR else ts[:10] + "T00:00:00Z"
            if benign is not None:
                key_root = f"kb:{benign.id}"
            else:
                key_root = (store.CROSS_DOMAIN_ROOT
                            if classification.is_cross_domain(reason, lc.level) else root)
            bucket = store.Bucket(
                key=store.bucket_key(st.pid, device_key, key_root, reason, start, span),
                hour=start, profile_id=st.pid, reason_id=reason, root=key_root,
                device=device_key, span=span,
            )
            items.append((bucket, ts, line_identity(line), line, lc, root))
        if not items:
            return newest
        items.sort(key=lambda it: (it[1], it[2]))
        try:
            outcomes = store.count_hits(
                st.slug, [(b, ts, lid, root) for b, ts, lid, _l, _c, root in items],
                arrived=format_utc_ms(self._now()),
            )
        except (sqlite3.Error, OSError, ValueError) as exc:
            raise _StoreError(
                "The tenant's telemetry store could not be written "
                f"({type(exc).__name__}) — a local fault in Athena, not NextDNS."
            ) from None
        for (bucket, _ts, line_id, line, lc, _root), outcome in zip(items, outcomes):
            if outcome.kind == "counted":
                report.counted += 1
            if outcome.kind not in ("new", "unfinished"):
                continue
            event_id = self._ingest_block(st, line, lc, line_id, bucket)
            if event_id is not None:
                try:
                    store.set_event(st.slug, bucket.key, event_id)
                except (sqlite3.Error, OSError) as exc:
                    raise _StoreError(
                        "The tenant's telemetry store could not be written "
                        f"({type(exc).__name__}) — a local fault in Athena, not NextDNS."
                    ) from None
                report.signals += 1
        return newest

    def _restricted(self, st: ProfileState, line: dict[str, Any], ts: str) -> None:
        """A CSAM line → restricted evidence (exactly once), then the tier
        engine is woken so the Black opens and pages within seconds. A store
        fault is the tenant store's (the page is read again next cycle)."""
        from apps.octo.threat import restricted

        try:
            new = restricted.record_nextdns(
                st.slug, profile_id=st.pid, profile_name=st.label, line=line,
                line_id=line_identity(line), observed_at=ts,
                arrived=format_utc_ms(self._now()))
        except (sqlite3.Error, OSError) as exc:
            raise _StoreError(
                "The tenant's event store could not be written "
                f"({type(exc).__name__}) — a local fault in Athena, not NextDNS."
            ) from None
        if new is not None:
            logger.warning("[nextdns-poller] profile %s: a RESTRICTED lookup was kept as "
                           "evidence (rule B7) — the tier engine opens the incident", st.pid)
            try:
                from apps.octo.threat import engine as tier_engine

                tier_engine.poke(st.slug)
            except Exception:  # noqa: BLE001 — the next pass picks it up anyway
                pass

    def _payload_block(
        self, st: ProfileState, line: dict[str, Any], lc: classification.LineClass,
        line_id: str, bucket: store.Bucket,
    ) -> dict[str, Any]:
        keep = ("timestamp", "domain", "root", "tracker", "encrypted", "protocol",
                "clientIp", "client", "device", "status", "reasons")
        log = {k: line[k] for k in keep if k in line}
        assert lc.primary is not None
        benign: Optional[dict[str, Any]] = None
        if bucket.root.startswith("kb:"):
            rule = next((r for r in known_benign.load() if f"kb:{r.id}" == bucket.root), None)
            benign = {"rule_id": rule.id, "label": rule.label, "note": rule.note[:300],
                      "still_blocked": True} if rule else {"rule_id": bucket.root[3:],
                                                            "still_blocked": True}
        return {
            "vendor_event_id": line_id,
            "kind": "security_block",
            "profile_id": st.pid,
            "profile_name": st.label,
            "log": log,
            "signal": {
                "level": lc.level,
                "reason_id": lc.primary.id,
                "reason_label": lc.primary.label,
                "bucket_hour": bucket.hour,
                "bucket_span": bucket.span,
                "cross_domain": bucket.cross_domain,
                **({"known_benign": benign} if benign else {}),
            },
        }

    def _ingest(self, slug: str, payload: dict[str, Any]) -> Optional[int]:
        """Store one alert under `slug` — directly: a NextDNS profile never
        auto-creates or auto-links a tenant. An alert already stored (the
        same payload and time) answers its existing id."""
        try:
            event = self._adapter.extract_event(payload)
        except Exception as exc:  # noqa: BLE001
            logger.warning("[nextdns-poller] extract failed (%s)", type(exc).__name__)
            return None
        inner = getattr(self._sink, "inner", self._sink)
        try:
            outcome = inner.ingest(slug, VENDOR, event)
        except FileNotFoundError:
            logger.warning("[nextdns-poller] tenant %s has no event store; alert not stored",
                           slug)
            return None
        event_id = getattr(outcome, "event_id", None)
        if not getattr(outcome, "duplicate", False):
            freshness.record_event(instance_id=self._instance_id, slug=slug)
            ts = event.received_at
            if ts and (self._last_event_at is None or ts > self._last_event_at):
                self._last_event_at = ts
            if self._publish is not None:
                self._publish(slug, event)
        return int(event_id) if isinstance(event_id, int) else None

    def _ingest_block(
        self, st: ProfileState, line: dict[str, Any], lc: classification.LineClass,
        line_id: str, bucket: store.Bucket,
    ) -> Optional[int]:
        return self._ingest(st.slug, self._payload_block(st, line, lc, line_id, bucket))

    # ----- tasks: hourly roll-up + protection health -----

    def _hourly(
        self, st: ProfileState, report: CycleReport, *, yield_to_security: bool = True,
    ) -> None:
        # Its NextDNS history first (once), so the very first hours are
        # judged against the site's week. A 403 on that call is the history
        # call's alone: only it waits (its own backoff, its own streak — or,
        # refused again and again, a failed read); the roll-ups go on. A
        # key-wide throttle shows on the roll-up reads that follow.
        try:
            self._ensure_seed(st, report)
        except NextDNSThrottledError as exc:
            if exc.status != 403:
                raise
            self._vendor_answered()
            self._profile_denied(st, exc, EP_SERIES, HOURLY_PATH)
        self._ep = None
        for hour_start in self._closed_hours(st, self._now()):
            if self._abort.is_set() or (yield_to_security and self._any_security_due()):
                return
            if not self._still_mapped(st):
                return
            hour_end = hour_start + timedelta(hours=1)
            key = hour_key(hour_start)
            self._reading_hour = key
            status = self._client.analytics_status(
                st.pid, from_=hour_start, to=hour_end, priority=PRIORITY_HEALTH,
            )
            self._contact_ok()
            queries = sum(status.values())
            blocked = status.get("blocked", 0)
            reasons: dict[str, tuple[str, int]] = {}
            if blocked > 0:
                reasons = self._client.analytics_reasons(
                    st.pid, from_=hour_start, to=hour_end, priority=PRIORITY_HEALTH,
                )
            report.contacted = True
            # Class counts are per REASON: NextDNS counts a multi-reason
            # block under each of its reasons, so they may add up to more
            # than `blocked`.
            counts = classification.class_counts(reasons)
            try:
                store.upsert_hourly(st.slug, store.HourlyRow(
                    hour=key, profile_id=st.pid, queries=queries,
                    default_queries=status.get("default", 0), blocked=blocked,
                    allowed=status.get("allowed", 0),
                    signal_high=counts[classification.HIGH],
                    signal_medium=counts[classification.MEDIUM],
                    signal_low=counts[classification.LOW],
                    policy_blocked=counts["policy"],
                    signal_reasons=classification.signal_reason_counts(reasons),
                ), arrived=format_utc_ms(self._now()))
            except (sqlite3.Error, OSError, ValueError) as exc:
                raise _StoreError(
                    f"The hourly row for {key[:13]}h could not be stored in the tenant's "
                    f"telemetry store ({type(exc).__name__}) — a local fault in Athena, "
                    "not NextDNS."
                ) from None
            report.hourly_rows += 1
            st.hour_done = key
            self._reading_hour = None
            if st.first_hour is None:
                st.first_hour = self._first_hour(st) or key
            self._protection_step(st, hour_start, queries)
            # The card's "queries in 24 h": the last 24 hourly rows once
            # there are 24 (before that, the 24-hour read that classified it).
            since = hour_key(hour_end - timedelta(hours=24))
            total, rows = store.queries_since(st.slug, st.pid, since)
            if rows >= 24 or st.q24 is None:
                st.q24, st.q24_at = total, format_utc_ms(self._now())
            if total >= ACTIVE_THRESHOLD:
                st.ever_active = True

    def _first_hour(self, st: ProfileState) -> Optional[str]:
        if st.first_hour is None:
            try:
                st.first_hour = store.first_hour(st.slug, st.pid)
            except (sqlite3.Error, OSError):
                return None
        return st.first_hour

    # ----- the baseline: local roll-ups, seeded from NextDNS history -----

    def _seed_view(self, st: ProfileState) -> Optional[tuple[str, str, Any, Any]]:
        """(from, to, busy hours, hours with queries) of the profile's seed —
        the lists as (newest hour, bitmask) — None without a usable one."""
        seed = st.seed
        if not seed or not seed.get("from") or not seed.get("to"):
            return None
        ident = (str(seed.get("at")), str(seed.get("to")))
        cached = self._seed_views.get(st.pid)
        if cached is not None and cached[0] == ident:
            return cached[1]
        view = (seed["from"], seed["to"], packed_bits(seed.get("busy")),
                packed_bits(seed.get("seen")))
        self._seed_views[st.pid] = (ident, view)
        return view

    def _observations(self, st: ProfileState, keys: list[str]) -> dict[str, tuple[bool, bool]]:
        """{hour: (busy, any query)} for those of `keys` the baseline knows:
        the profile's own roll-up row when there is one (local observations
        replace the seed as they accumulate), else its NextDNS history seed
        when the hour is inside it. An hour inside one of the profile's
        lapses (an outage, a closure — `dark_hours`) is UNKNOWN: it is never
        the site's normal week."""
        dark = packed_bits(st.dark_hours)
        if dark is not None:
            keys = [k for k in keys if not has_hour(dark, k, SEED_SPAN_HOURS)]
            if not keys:
                return {}
        try:
            local = store.hour_history(st.slug, st.pid, keys)
        except (sqlite3.Error, OSError):
            local = {}
        out = {k: (q >= BASELINE_BUSY_QUERIES, q > 0) for k, q in local.items()}
        view = self._seed_view(st)
        if view is not None:
            frm, to, busy, seen = view
            for k in keys:
                if k not in out and frm <= k <= to:
                    out[k] = (has_hour(busy, k, SEED_SPAN_HOURS),
                              has_hour(seen, k, SEED_SPAN_HOURS))
        return out

    def _baseline_start(self, st: ProfileState) -> Optional[str]:
        """Where the profile's baseline starts: its oldest roll-up row, or
        its NextDNS history (the seed) when that reaches further back."""
        view = self._seed_view(st)
        starts = [h for h in (self._first_hour(st), view[0] if view else None) if h]
        return min(starts) if starts else None

    def _expected_busy(self, st: ProfileState, key: str) -> bool:
        """True when this hour is normally busy at the site: the same hour
        of the week on the previous BASELINE_WEEKS weeks the baseline knows
        (own roll-ups, else the NextDNS history seed), at least half with
        BASELINE_BUSY_QUERIES. False with less than BASELINE_MIN of baseline
        (seeded: from the first day) or without history."""
        cached = self._busy_cache.get((st.pid, key))
        if cached is not None:
            return cached
        start = _hour_start(key)
        base = self._baseline_start(st)
        busy = False
        if base is not None and start - _hour_start(base) >= BASELINE_MIN:
            keys = [hour_key(start - timedelta(days=7 * w)) for w in range(1, BASELINE_WEEKS + 1)]
            history = self._observations(st, keys)
            if history:
                hits = sum(1 for b, _seen in history.values() if b)
                busy = hits * 2 >= len(history)
        self._busy_cache[(st.pid, key)] = busy
        return busy

    def _normally_trafficked(self, st: ProfileState, hours: list[str]) -> Optional[list[str]]:
        """Those of `hours` (a 24-hour window) the site NORMALLY has queries
        in: the same hour of the week had any query on at least half of the
        previous BASELINE_WEEKS weeks the baseline knows. None when the
        baseline cannot judge the window: less than BASELINE_MIN of it, or
        fewer than half of the window's hours known."""
        known, normal = self._trafficked(st, hours)
        if not hours or known * 2 < len(hours):
            return None
        return normal

    def _trafficked(self, st: ProfileState, hours: list[str]) -> tuple[int, list[str]]:
        """(how many of `hours` the baseline knows, those of them the site
        NORMALLY has queries in — see `_normally_trafficked`); (0, []) with
        less than BASELINE_MIN of baseline."""
        if not hours:
            return 0, []
        base = self._baseline_start(st)
        if base is None or _hour_start(hours[-1]) - _hour_start(base) < BASELINE_MIN:
            return 0, []
        weeks = {h: [hour_key(_hour_start(h) - timedelta(days=7 * w))
                     for w in range(1, BASELINE_WEEKS + 1)] for h in hours}
        seen = self._observations(st, [k for keys in weeks.values() for k in keys])
        known, normal = 0, []
        for h in hours:
            flags = [seen[k][1] for k in weeks[h] if k in seen]
            if not flags:
                continue
            known += 1
            if sum(flags) * 2 >= len(flags):
                normal.append(h)
        return known, normal

    def _day_window(self, last: str) -> list[str]:
        """The SILENT_DAY_HOURS hour keys up to `last`, oldest first."""
        end = _hour_start(last)
        return [hour_key(end - timedelta(hours=SILENT_DAY_HOURS - 1 - i))
                for i in range(SILENT_DAY_HOURS)]

    def _backstop_since(self, st: ProfileState, key: str) -> Optional[str]:
        """The whole-day backstop at hour `key`: 0 queries in the trailing
        24 h AND the site normally has queries in at least LAPSE_ZERO_HOURS
        of them (the same hours of the previous weeks) — a weekend-closed or
        part-week site always silent then is not lapsed for it. Returns the
        lapse's since (the first of those hours), or None. Without a
        baseline for the day: any silent day, since the run's first zero
        hour (the plain rule). The floor: SILENT_WEEK_HOURS rolled-up zero
        hours in a row lapse it whatever its baseline (since the run's first
        zero hour) — a baseline that learnt the silence can never hide a
        site that stopped for good."""
        if not self._silent_day(st, key):
            return None
        window = self._day_window(key)
        normal = self._normally_trafficked(st, window)
        if normal is None:
            return st.zero_since or window[0]
        if len(normal) >= LAPSE_ZERO_HOURS:
            return normal[0]
        start = hour_key(_hour_start(key) - timedelta(hours=SILENT_WEEK_HOURS - 1))
        try:
            total, rows = store.queries_between(st.slug, st.pid, start, key)
        except (sqlite3.Error, OSError):
            return None
        if rows >= SILENT_WEEK_HOURS and total == 0:
            return min(st.zero_since or start, start)
        return None

    def _dark_when_mapped(self, st: ProfileState, report: CycleReport) -> Optional[bool]:
        """A profile with no queries in 24 h (and ≥ 100 in 7 days) at
        mapping: is that silence one it NORMALLY has at this time of the
        week? Its NextDNS history is read first (once). True: dark while it
        normally has queries (≥ LAPSE_ZERO_HOURS such hours in the silent 24
        h) — 'before Athena watched'. False: normally silent now (a weekend,
        a closed day). None: no history to tell (the 7-day rule decides)."""
        self._ensure_seed(st, report)
        last = hour_key(_hour_floor(self._now()) - timedelta(hours=1))
        normal = self._normally_trafficked(st, self._day_window(last))
        if normal is None:
            return None
        return len(normal) >= LAPSE_ZERO_HOURS

    def _peak24(self, st: ProfileState) -> int:
        """The busiest 24 hours in a row of the profile's last 7 days — from
        its NextDNS history seed, else from its own roll-ups."""
        seed = st.seed or {}
        if seed.get("from"):
            return int(seed.get("peak24") or 0)
        end = _hour_floor(self._now()) - timedelta(hours=1)
        keys = [hour_key(end - timedelta(hours=back)) for back in range(7 * 24 + 23 - 1, -1, -1)]
        try:
            rows = store.hour_history(st.slug, st.pid, keys)
        except (sqlite3.Error, OSError):
            return 0
        hourly = [rows.get(k, 0) for k in keys]
        return max(sum(hourly[i:i + 24]) for i in range(len(hourly) - 23))

    def _seed_needed(self, st: ProfileState, now: datetime) -> bool:
        """Does the baseline want the profile's NextDNS history: no seed
        that reaches its own roll-ups (one no lookup can reach any more is
        dropped; one that stops short of them — the profile was re-mapped to
        another tenant since — is read again once it is a day old) and
        fewer than SEED_LOCAL_FULL_ROWS own roll-ups in the trailing 3
        weeks?"""
        seed = st.seed
        if seed is not None:
            at = _dt(seed.get("at"))
            if at is not None and now - at < SEED_KEEP:
                if now - at < SEED_EVERY or self._seed_reaches(st, seed, now):
                    return False
            else:
                st.seed = None
                self._seed_views.pop(st.pid, None)
        full = self._local_full.get(st.pid)
        if full is not None and now - full < SEED_EVERY:
            return False
        since = hour_key(now - timedelta(days=7 * BASELINE_WEEKS))
        try:
            _total, rows = store.queries_since(st.slug, st.pid, since)
        except (sqlite3.Error, OSError):
            rows = 0
        if rows >= SEED_LOCAL_FULL_ROWS:
            self._local_full[st.pid] = now
            return False
        return True

    def _seed_reaches(self, st: ProfileState, seed: dict[str, Any], now: datetime) -> bool:
        """Does the seed reach the profile's own roll-ups in this tenant
        (their oldest row — or now, before the first — at most a day after
        the seed's last hour)? Otherwise the hours between are known to
        neither, and with a gap of a week or more the baseline loses whole
        weeks (a re-mapped profile's new tenant has no roll-ups before the
        re-mapping)."""
        end = seed.get("to") or (hour_key(_dt(seed.get("at")) or now))
        first = self._first_hour(st)
        try:
            reach = _hour_start(first) if first else _hour_floor(now)
            return reach - _hour_start(end) <= HOURLY_LOOKBACK
        except ValueError:
            return True

    def _ensure_seed(self, st: ProfileState, report: CycleReport) -> None:
        """Read the profile's NextDNS history into its baseline seed when it
        is needed — ONE call, health priority, at most once per profile id
        per SEED_EVERY (a failed attempt counts; the mark outlives an
        unmapping). A failure is not the profile's problem: its baseline is
        then learnt from Athena's own roll-ups (the first-week rules) and
        the history is asked again a day later. A throttle (or a stop) is
        no answer at all: the attempt does not count — it is asked again
        once the key's / the call's backoff is over (`_seed_retry`). It is
        raised with the call's endpoint class (EP_SERIES) to the caller: a
        roll-up goes on without it (`_hourly`); a classification ends (the
        profile stays as it was: a NEW one is classified, its 'before
        Athena watched' judged, only with its history or after a real
        failure — a 403 repeated on this call alone is one, see
        `_profile_denied`)."""
        now = self._now()
        tried = _dt(self._seed_calls.get(st.pid))
        if tried is not None and now - tried < SEED_EVERY:
            return
        wait = self._seed_retry.get(st.pid)
        if wait is not None and now < wait:
            return
        if not self._seed_needed(st, now):
            return
        # The attempt is marked BEFORE the call (a crash counts too).
        before = self._seed_calls.get(st.pid)
        self._seed_calls[st.pid] = format_utc_ms(now)
        self._ep = EP_SERIES
        try:
            points = self._client.analytics_status_series(
                st.pid, from_=SEED_FROM, interval=SEED_INTERVAL_SEC, priority=PRIORITY_HEALTH,
            )
        except (NextDNSThrottledError, NextDNSAborted):
            if before is None:
                self._seed_calls.pop(st.pid, None)
            else:
                self._seed_calls[st.pid] = before
            raise
        except NextDNSClientError as exc:
            self._ep = None
            if isinstance(exc, NextDNSNotFoundError):
                self._vendor_answered()
            else:
                self._vendor_failed(exc)
            logger.warning(
                "[nextdns-poller] profile %s: its NextDNS history was not read (%s) — its "
                "baseline is learnt from Athena's own roll-ups; asked again in %d h",
                st.pid, exc, int(SEED_EVERY.total_seconds() // 3600))
            return
        self._ep = None
        self._seed_retry.pop(st.pid, None)
        if st.refused_series:
            st.refused_series = 0
            self._refusal_mark.pop((st.pid, EP_SERIES), None)
        self._contact_ok()
        report.contacted = True
        report.health_checks += 1
        st.seed = make_seed(points, self._now())
        self._seed_views.pop(st.pid, None)
        self._busy_cache = {k: v for k, v in self._busy_cache.items() if k[0] != st.pid}
        logger.info("[nextdns-poller] profile %s: baseline seeded from its NextDNS history "
                    "(%s → %s)", st.pid, st.seed.get("from") or "no queries",
                    st.seed.get("to") or "-")

    def _silent_day(self, st: ProfileState, key: str) -> bool:
        """0 queries in each of the SILENT_DAY_HOURS hours up to `key`."""
        frm = hour_key(_hour_start(key) - timedelta(hours=SILENT_DAY_HOURS - 1))
        try:
            total, rows = store.queries_between(st.slug, st.pid, frm, key)
        except (sqlite3.Error, OSError):
            return False
        return rows >= SILENT_DAY_HOURS and total == 0

    def _protection_step(self, st: ProfileState, hour_start: datetime, queries: int) -> None:
        """One closed hour of the PENDING → ACTIVE → LAPSED machine. A
        candidate lapse is decided after the cycle's roll-ups
        (`_resolve_lapses`: vendor gaps, the fleet)."""
        key = hour_key(hour_start)
        cutoff = hour_key(hour_start - timedelta(hours=RECENT_HOURS))
        st.recent_zero = [h for h in st.recent_zero if cutoff < h != key]
        st.error_hours = [h for h in st.error_hours if h > cutoff]
        dark = packed_bits(st.dark_hours)
        if dark is not None and hour_start - dark[0] >= timedelta(hours=SEED_SPAN_HOURS):
            st.dark_hours = None            # no lookup reaches its hours any more
        if queries <= 0:
            st.recent_zero.append(key)
        else:
            self._logging_seen(st)
        if st.state == ACTIVE:
            if queries > 0:
                st.zero_hours, st.zero_since, st.busy_since, st.zero_list = 0, None, None, []
                if not (st.lapse_pending or {}).get("decided"):
                    st.lapse_pending = None
                return
            st.zero_since = st.zero_since or key
            if self._expected_busy(st, key):
                st.busy_since = st.busy_since or key
                st.zero_list = (st.zero_list + [key])[-RECENT_HOURS:]
            elif st.zero_list and not st.lapse_pending:
                # A zero hour the site is NOT normally busy in (a closed
                # night) between two busy zero hours: they do not follow
                # each other — only consecutive busy silences count.
                st.zero_list = []
            day_since = self._backstop_since(st, key) if st.ever_active else None
            hourly = len(st.zero_list) >= LAPSE_ZERO_HOURS
            if day_since or hourly:
                cand = st.lapse_pending or {"first": format_utc_ms(self._now())}
                # Since: for the hourly rule the run's first normally-busy
                # zero hour (an office quiet overnight went dark when it
                # should have woken up — or at its last busy hour before the
                # night); for the backstop the first hour of the silent day
                # the site normally has queries in (the run's first zero
                # hour without a baseline). Never later than decided before.
                sinces = [s for s in (cand.get("since"), day_since,
                                      (st.busy_since or st.zero_list[0]) if hourly else None)
                          if s]
                cand.update({"hour": key, "since": min(sinces),
                             "at": format_utc_ms(hour_start + timedelta(hours=1)),
                             "backstop": bool(day_since) or bool(cand.get("backstop"))})
                st.lapse_pending = cand
            return
        if st.state == LAPSED:
            lapse = st.lapse or {}
            if lapse.get("cause") in VISIBILITY_CAUSES and \
                    hour_start < (_dt(lapse.get("at")) or hour_start):
                # An hour before the key lost sight of the profile (read
                # late, once it is visible again): says nothing about the
                # lapse — a restore is never dated before it.
                return
            inside = lapse.get("cause") not in VISIBILITY_CAUSES
            if queries <= 0:
                st.zero_hours += 1        # no repeats while lapsed
                st.restore_streak = 0
                if inside:
                    self._mark_dark(st, key, key)
                return
            st.restore_streak += 1
            if queries < RESTORE_MIN_QUERIES and st.restore_streak < RESTORE_HOURS:
                if inside:
                    self._mark_dark(st, key, key)     # a lone wake-up, still lapsed
                return
            self._restore(st, key, hour_start, queries)

    def _mark_dark(self, st: ProfileState, first: str, last: str) -> None:
        """Hours `first`..`last` are inside a lapse of the profile: those of
        them it NORMALLY has queries in (its baseline then) are UNKNOWN to
        the baseline from now on (`_observations`) — the outage or the
        closure is never learnt as the site's normal week. Its normally
        silent hours stay known (silent is what they are: a weekend inside
        a closure is still a weekend), and so does every hour of a lapse
        decided without a baseline (the plain rule's silent day may be a
        normal closed day — marking it would leave the next one unjudged).
        Kept for SEED_SPAN_HOURS (as far back as any lookup reaches)."""
        try:
            a, b = _hour_start(first), _hour_start(last)
        except ValueError:
            return
        a = max(a, b - timedelta(hours=SEED_SPAN_HOURS - 1))
        hours = [hour_key(a + timedelta(hours=i))
                 for i in range(int((b - a).total_seconds() // 3600) + 1)]
        _known, normal = self._trafficked(st, hours)
        if not normal:
            return
        for h in normal:
            st.dark_hours = mark_span(st.dark_hours, h, h, SEED_SPAN_HOURS)
        self._busy_cache = {k: v for k, v in self._busy_cache.items() if k[0] != st.pid}

    def _lapse_span_start(self, st: ProfileState, cand: dict[str, Any]) -> Optional[str]:
        """Where a lapse's dark span starts: its `since`; for one decided
        without it ('before Athena watched') the hour after the last query
        its NextDNS history saw, else the silent 24 hours that decided it."""
        since = cand.get("since")
        if since:
            return since
        hour = cand.get("hour")
        if not hour:
            return None
        try:
            end = _hour_start(hour)
        except ValueError:
            return None
        seen = packed_bits((st.seed or {}).get("seen"))
        start = end - timedelta(hours=SILENT_DAY_HOURS)
        if seen is not None and seen[0] < start:
            start = seen[0] + timedelta(hours=1)
        return hour_key(max(start, end - timedelta(hours=SEED_SPAN_HOURS - 1)))

    # ----- lapse decisions (after the cycle's roll-ups) -----

    def _resolve_lapses(self) -> None:
        """Turn lapse candidates into lapses. A whole silent day (one the
        site normally has queries in) always lapses. Otherwise the counted
        zero hours must not be a NextDNS-side
        gap (bounded to VENDOR_GAP_MAX_HOURS in a row) — and a candidate
        waits a little for the other profiles to read its hours. Then the
        fleet check: at least half the sites dark at once is ONE incident."""
        now = self._now()
        candidates = [st for st in sorted(self._profiles.values(), key=lambda s: s.pid)
                      if st.state == ACTIVE and st.lapse_pending
                      and (not st.missing or st.lapse_pending.get("decided"))]

        def may_wait(st: ProfileState) -> bool:
            first = _dt((st.lapse_pending or {}).get("first")) or now
            return now - first < VENDOR_GAP_WAIT

        # Settle the hours oldest first: declaring or expiring a gap is
        # decided once, whoever asks.
        for hour in sorted({h for st in candidates for h in st.zero_list
                            if not st.lapse_pending.get("decided")}):
            self._gap_verdict(hour, any(may_wait(st) for st in candidates
                                        if hour in st.zero_list))
        # A profile the key lost sight of waits (at most two intervals) while
        # another watched profile has a 404 / 403 still being checked: when
        # many are lost at once they are decided — and grouped — together.
        in_flight = any(p.state == ACTIVE and not p.missing and (p.not_found or p.denied_at)
                        for p in self._profiles.values())
        visibility_wait = timedelta(seconds=2 * self._interval)
        decided: list[ProfileState] = []
        for st in candidates:
            pending = st.lapse_pending or {}
            if pending.get("decided"):
                first = _dt(pending.get("first")) or now
                if not (in_flight and now - first < visibility_wait):
                    decided.append(st)
                continue
            if pending.get("backstop"):
                decided.append(st)
                continue
            verdicts = [self._gap_verdict(h, may_wait(st)) for h in st.zero_list]
            if "wait" in verdicts:
                continue
            if verdicts.count("count") >= LAPSE_ZERO_HOURS:
                decided.append(st)
        fleet = self._fleet_step(decided, now)
        for st in decided:
            if st.pid in self._profiles and st.lapse_pending and self._still_mapped(st):
                self._raise_lapse(st, st.lapse_pending, fleet=fleet)

    def _gap_shape(self, hour: str) -> tuple[bool, bool]:
        """(ready, shared) for one hour: have enough ACTIVE profiles read
        it; is its zero shared as a vendor-side gap (see the module doc)?"""
        cached = self._shape_cache.get(hour)
        if cached is not None:
            return cached
        # A profile NextDNS refuses (403) reads no hour: it never holds the
        # others' verdict back.
        population = [p for p in self._profiles.values()
                      if p.state == ACTIVE and not p.missing and p.ever_active
                      and p.problem_kind != "refused" and not p.refused
                      and not p.refused_hourly]
        if len(population) < VENDOR_GAP_MIN_PROFILES:
            out = (True, False)
        else:
            observed = [p for p in population if p.hour_done and p.hour_done >= hour]
            ready = len(observed) >= math.ceil(VENDOR_GAP_READY_SHARE * len(population))
            expected = [p for p in observed if self._expected_busy(p, hour)]
            zero = [p for p in expected if hour in p.recent_zero]
            # Vendor evidence: a read for the hour FAILED (and was answered
            # 0 later). An empty answer is normal silence, not evidence.
            evidence = [p for p in zero if hour in p.error_hours]
            shared = False
            if len(zero) >= VENDOR_GAP_MIN_PROFILES and expected:
                share = len(zero) / len(expected)
                shared = ((len(evidence) >= VENDOR_GAP_MIN_PROFILES and share >= VENDOR_GAP_SHARE)
                          or share >= VENDOR_GAP_SHARE_NO_EVIDENCE)
            out = (ready, shared)
        self._shape_cache[hour] = out
        return out

    def _gap_verdict(self, hour: str, may_wait: bool) -> str:
        """'gap' (excused), 'count' (counts toward a lapse) or 'wait'."""
        if hour in self._gap_expired:
            return "count"
        if hour in self._gap_hours:
            return "gap"
        ready, shared = self._gap_shape(hour)
        if not ready and may_wait:
            return "wait"
        if not shared:
            return "count"
        prev = hour_key(_hour_start(hour) - timedelta(hours=1))
        if prev in self._gap_expired or self._gap_run_before(hour) >= VENDOR_GAP_MAX_HOURS:
            self._expire_gap(hour)
            return "count"
        self._declare_gap(hour)
        return "gap"

    def _gap_run_before(self, hour: str) -> int:
        run = 0
        h = _hour_start(hour) - timedelta(hours=1)
        while hour_key(h) in self._gap_hours:
            run += 1
            h -= timedelta(hours=1)
        return run

    def _trim_gaps(self) -> None:
        cutoff = hour_key(self._now() - timedelta(hours=RECENT_HOURS))
        self._gap_hours = sorted(h for h in set(self._gap_hours) if h > cutoff)[-RECENT_HOURS:]
        self._gap_expired = sorted(h for h in set(self._gap_expired) if h > cutoff)[-RECENT_HOURS:]

    def _declare_gap(self, hour: str) -> None:
        zeros = sum(1 for p in self._profiles.values() if hour in p.recent_zero)
        self._gap_hours.append(hour)
        self._trim_gaps()
        logger.warning(
            "[nextdns-poller] NextDNS analytics reported no queries for %d active profiles "
            "in the hour from %s — read as a NextDNS-side gap (at most %d hours in a row): "
            "no lapse alerts for it", zeros, _hour_text(hour), VENDOR_GAP_MAX_HOURS,
        )

    def _expire_gap(self, hour: str) -> None:
        """The shared silence outlasted the bound: not a vendor gap after
        all — its hours count toward the sites' lapses."""
        h = _hour_start(hour) - timedelta(hours=1)
        run = []
        while hour_key(h) in self._gap_hours:
            run.append(hour_key(h))
            h -= timedelta(hours=1)
        if run:
            logger.warning(
                "[nextdns-poller] the shared silence since %s lasted more than %d hours: no "
                "longer read as a NextDNS-side gap — the sites' lapses proceed",
                _hour_text(run[-1]), VENDOR_GAP_MAX_HOURS,
            )
        self._gap_hours = [g for g in self._gap_hours if g not in run]
        self._gap_expired.extend([*run, hour])
        self._trim_gaps()
        self._shape_cache.clear()

    def _still_dark(self, st: ProfileState) -> bool:
        """A lapsed site is still dark: still unseen (a visibility lapse), or
        its last rolled-up hour had no queries (silent, logging off)."""
        if (st.lapse or {}).get("cause") in VISIBILITY_CAUSES:
            return st.missing
        return bool(st.hour_done) and st.hour_done in st.recent_zero

    def _fleet_step(self, decided: list[ProfileState], now: datetime) -> Optional[dict[str, Any]]:
        """ONE fleet-wide incident when at least half of the watched sites
        (and ≥ VENDOR_GAP_MIN_PROFILES) are dark at once. Returns the open
        incident (the lapses decided now carry it), else None."""
        fleet = self._fleet
        # Dark at once: lapsing now, or lapsed within the window — for an
        # open incident, since the window before it opened — for a cause
        # that leaves it dark (no queries, logging off, unseen by the key)
        # and still so.
        start = now - FLEET_WINDOW
        opened = _dt((fleet or {}).get("opened_at")) if (fleet or {}).get("open") else None
        if opened is not None:
            start = min(start, opened - FLEET_WINDOW)
        window = format_utc_ms(start)
        decided_pids = {st.pid for st in decided}
        dark: dict[str, ProfileState] = {st.pid: st for st in decided}
        for p in self._profiles.values():
            lapse = p.lapse or {}
            if (p.ever_active and p.state == LAPSED and lapse.get("cause") in DARK_CAUSES
                    and str(lapse.get("at") or "") >= window and self._still_dark(p)):
                dark[p.pid] = p
        # The watched sites: every ever-active ACTIVE / LAPSED profile the
        # key sees, and the dark ones it lost sight of.
        population = {p.pid for p in self._profiles.values()
                      if p.ever_active and not p.missing and p.state in (ACTIVE, LAPSED)}
        population |= set(dark)
        sites, watched = len(dark), len(population)
        outage = sites >= VENDOR_GAP_MIN_PROFILES and sites * 2 >= watched
        if fleet is not None and fleet.get("open"):
            if outage:
                fleet["sites_now"] = sites
                fleet["sites"] = max(int(fleet.get("sites") or 0), sites)
                fleet["watched"] = watched
                fleet["pids"] = sorted({*(fleet.get("pids") or []), *dark})
                return fleet
            fleet["open"] = False
            fleet["closed_at"] = format_utc_ms(now)
            self._fleet_note(fleet, f"closed:{fleet['closed_at']}",
                             self._fleet_close_text(fleet, dark))
            logger.info("[nextdns-poller] the fleet-wide NextDNS outage is over")
            return None
        if not outage:
            return None
        closed = _dt((fleet or {}).get("closed_at"))
        if fleet is not None and closed is not None and now - closed < FLEET_RELAPSE_WINDOW:
            fleet.update({"open": True, "sites": sites, "sites_now": sites,
                          "watched": watched, "closed_at": None,
                          "pids": sorted({*(fleet.get("pids") or []), *dark})})
            self._fleet_note(fleet, f"again:{format_utc_ms(now)}",
                             f"{sites} of {watched} sites stopped reporting to NextDNS again "
                             f"— the same incident, so no new alert.")
            return fleet
        since = min((p.zero_since or (p.lapse or {}).get("since") or hour_key(now))
                    for p in dark.values())
        vid = f"fleet:{self._instance_id}:{since}"
        slug = self._internal_tenant()
        listed = sorted(dark.values(), key=lambda p: (p.label or p.pid).lower())
        self._fleet = {"open": True, "vid": vid, "since": since, "opened_at": format_utc_ms(now),
                       "sites": sites, "sites_now": sites, "watched": watched, "slug": slug,
                       "event_id": None, "closed_at": None, "pids": sorted(dark)}
        logger.warning(
            "[nextdns-poller] %d of %d watched sites stopped reporting to NextDNS at once "
            "(since %s): ONE fleet-wide incident%s", sites, watched, _hour_text(since),
            f" in tenant {slug}" if slug else
            " — no ACTIVE tenant of kind 'internal' to raise it in (shown on the card)",
        )
        if slug is not None:
            self._queue(None, {"op": "event", "kind": "fleet", "slug": slug, "vid": vid,
                               "payload": {
                "vendor_event_id": vid,
                "kind": "fleet_dns_outage",
                "sites": sites,
                "watched": watched,
                "tenants": len({p.slug for p in dark.values()}),
                "since": since,
                "detected_at": format_utc_ms(now),
                "profiles": [{"profile_id": p.pid, "profile_name": p.label}
                             for p in listed[:FLEET_LIST_MAX]],
            }})
        # Sites that lapsed earlier in this episode, before it was fleet-wide.
        link = {"sites": sites, "watched": watched, "since": since}
        for p in dark.values():
            lapse = p.lapse or {}
            if p.pid in decided_pids or not lapse:
                continue
            lapse["fleet"] = True
            self._queue(p, {
                "op": "note", "slug": lapse.get("slug") or p.slug,
                "event_id": lapse.get("event_id"), "event_vid": lapse.get("vid"),
                "text": self._fleet_text(link),
                "marker": f"fleet:{vid}:{p.pid}", "query_kind": NOTE_KIND_VENDOR,
            })
        return self._fleet

    def _fleet_close_text(self, fleet: dict[str, Any], dark: dict[str, ProfileState]) -> str:
        """The closing note: how many of the incident's sites REALLY report
        again (ACTIVE after a restore), how many are still silent, and how
        many left it otherwise (unmapped, re-mapped)."""
        pids = [p for p in (fleet.get("pids") or []) if isinstance(p, str)]
        total = len(pids) or int(fleet.get("sites") or 0)
        still = sum(1 for pid in pids if pid in dark)
        restored = sum(1 for pid in pids if pid not in dark and pid in self._profiles
                       and self._profiles[pid].state == ACTIVE
                       and not self._profiles[pid].missing)
        other = max(0, total - still - restored)
        return (f"{restored} of the {total} sites are reporting again ({still} still silent"
                + (f", {other} not confirmed yet or no longer watched" if other else "")
                + ") — fewer than half of the watched sites are dark now, so the fleet-wide "
                "incident is over.")

    @staticmethod
    def _fleet_text(link: dict[str, Any]) -> str:
        return (f"Part of a fleet-wide outage: {link['sites']} of {link['watched']} sites "
                f"stopped reporting to NextDNS at the same time (since "
                f"{_hour_text(link.get('since'))}) — likely one shared cause (NextDNS itself, "
                "or a DNS template pushed to many sites), tracked as ONE incident.")

    def _fleet_note(self, fleet: dict[str, Any], tag: str, text: str) -> None:
        slug = fleet.get("slug")
        if not slug:
            return
        self._queue(None, {"op": "note", "slug": slug, "event_id": fleet.get("event_id"),
                           "event_vid": fleet.get("vid"), "text": text,
                           "marker": f"{fleet.get('vid')}:{tag}",
                           "query_kind": NOTE_KIND_VENDOR})

    def _raise_lapse(self, st: ProfileState, cand: dict[str, Any],
                     fleet: Optional[dict[str, Any]] = None) -> None:
        """ACTIVE → LAPSED with ONE signal (queued) — or, within
        RELAPSE_WINDOW of the profile's last restore, a note on the earlier
        lapse alert (the same episode; no new alert)."""
        cause = cand.get("cause") or "no_queries"
        since = cand.get("since")
        detected = cand.get("at") or format_utc_ms(self._now())
        if cause == "no_queries":
            cause = self._logs_cause(st) or cause
        run = _hours_between(since, cand.get("hour")) if since else 0
        lr = st.last_restore or {}
        restored_at = _dt(lr.get("at"))
        detected_dt = _dt(detected) or self._now()
        earlier = lr.get("lapse_event_id")
        episode = bool(
            restored_at is not None and lr.get("slug") == st.slug
            and isinstance(earlier, int) and detected_dt - restored_at < RELAPSE_WINDOW
        )
        vid = f"lapsed:{st.pid}:{since or detected}"
        link = ({"sites": int(fleet.get("sites_now") or fleet.get("sites") or 0),
                 "watched": int(fleet.get("watched") or 0), "since": fleet.get("since")}
                if fleet else None)
        if episode:
            text = (f"Stopped reporting again from {_hour_text(since or hour_key(detected_dt))} "
                    f"({run or LAPSE_ZERO_HOURS} hours without queries), after resuming at "
                    f"{_hour_text(lr.get('at'))} — the same episode, so no new alert.")
            if link:
                text += " " + self._fleet_text(link)
            self._queue(st, {"op": "note", "slug": st.slug, "event_id": earlier,
                             "text": text, "marker": f"relapse:{st.pid}:{since or detected}",
                             "query_kind": NOTE_KIND_VENDOR})
            event_id: Optional[int] = earlier
        else:
            payload: dict[str, Any] = {
                "vendor_event_id": vid,
                "kind": "protection_lapsed",
                "profile_id": st.pid,
                "profile_name": st.label,
                "cause": cause,
                "since": since,
                "zero_hours": run or None,
                "detected_at": detected,
            }
            if cand.get("queries_7d") is not None:
                payload["queries_7d"] = int(cand["queries_7d"])
            if link:
                payload["fleet"] = link
            self._queue(st, {"op": "event", "kind": "lapse", "slug": st.slug,
                             "vid": vid, "payload": payload})
            event_id = None
        st.state, st.state_since = LAPSED, detected
        st.lapse = {"event_id": event_id, "vid": vid, "slug": st.slug, "since": since,
                    "at": detected, "cause": cause, "episode": episode,
                    "fleet": bool(link)}
        if cause not in VISIBILITY_CAUSES:
            start = self._lapse_span_start(st, cand)
            if start and cand.get("hour"):
                self._mark_dark(st, start, cand["hour"])
        st.lapse_pending = None
        st.restore_streak = 0
        logger.warning("[nextdns-poller] profile %s stopped reporting (%s%s)", st.pid, cause,
                       f", since {since}" if since else "")

    def _logs_cause(self, st: ProfileState) -> Optional[str]:
        """At a lapse: was logging turned off at NextDNS? (one read; any
        failure keeps the default wording)."""
        try:
            self._read_settings(st, force=True)
        except (NextDNSClientError, NextDNSAuthError):
            return None
        return "logs_off" if st.logs_enabled is False else None

    def _below_active(self, st: ProfileState, key: str) -> bool:
        """Fewer than the ACTIVE threshold in the 24 roll-up hours up to `key`."""
        frm = hour_key(_hour_start(key) - timedelta(hours=23))
        try:
            total, _rows = store.queries_between(st.slug, st.pid, frm, key)
        except (sqlite3.Error, OSError):
            return False
        return total < self._active_threshold(st)

    def _back_to_pending(self, st: ProfileState, key: str) -> None:
        """A profile lapsed as 'dark before Athena watched' (0 in 24 h, ≥ 100
        in 7 days) that wakes up with fewer than 100 queries in 24 h is a
        1–99-a-day profile: PENDING again (never promoted to ACTIVE, so no
        weekly backstop lapses) — a note on its lapse alert, no restore
        alert."""
        lapse = st.lapse or {}
        now = format_utc_ms(self._now())
        if lapse.get("slug") == st.slug:
            self._queue(st, {
                "op": "note", "slug": st.slug, "event_id": lapse.get("event_id"),
                "event_vid": lapse.get("vid"),
                "text": (f"NextDNS is reporting queries again from {_hour_text(key)} — fewer "
                         f"than {self._active_threshold(st)} in 24 hours, so this profile is "
                         "watched as pending (a low-volume profile), not as a restored site: "
                         "no restore alert."),
                "marker": f"pending-again:{st.pid}:{key}", "query_kind": NOTE_KIND_VENDOR,
            })
        st.state, st.state_since, st.ever_active, st.health_at = PENDING, now, False, now
        st.zero_hours, st.zero_since, st.busy_since, st.zero_list = 0, None, None, []
        st.lapse = st.lapse_pending = None
        st.restore_streak = 0
        logger.info("[nextdns-poller] profile %s reports again at a low volume: pending", st.pid)

    def _restore(self, st: ProfileState, key: str, hour_start: datetime, queries: int) -> None:
        lapse = st.lapse or {}
        if lapse.get("cause") == "before_watch" and self._below_active(st, key):
            self._back_to_pending(st, key)
            return
        restored_at = hour_start + timedelta(hours=1)
        if lapse.get("cause") in VISIBILITY_CAUSES:
            # Seen again only now: the restore is detected now, never before
            # the lapse it resolves.
            restored_at = max(restored_at, self._now())
        same_tenant = lapse.get("slug") == st.slug
        lapse_event = (lapse.get("event_id")
                       if same_tenant and isinstance(lapse.get("event_id"), int) else None)
        lapse_vid = lapse.get("vid") if same_tenant and lapse_event is None else None
        lr = st.last_restore or {}
        earlier_restored = lr.get("restored_event_id")
        vid = f"restored:{st.pid}:{key}"
        if (lapse.get("episode") and lr.get("slug") == st.slug
                and isinstance(earlier_restored, int)):
            self._queue(st, {
                "op": "note", "slug": st.slug, "event_id": earlier_restored,
                "text": (f"Reporting again from {_hour_text(key)} ({int(queries)} queries in "
                         f"the hour) after stopping again from {_hour_text(lapse.get('since'))} "
                         "— the same episode, so no new alert."),
                "marker": f"re-restored:{st.pid}:{key}", "query_kind": NOTE_KIND_VENDOR,
            })
            event_id: Optional[int] = earlier_restored
            restored_vid = lr.get("restored_vid")
        else:
            self._queue(st, {
                "op": "event", "kind": "restore", "slug": st.slug, "vid": vid,
                "lapse_vid": lapse_vid, "restored_hour": key,
                "lapse": {"since": lapse.get("since"), "slug": lapse.get("slug")},
                "payload": {
                    "vendor_event_id": vid,
                    "kind": "protection_restored",
                    "profile_id": st.pid,
                    "profile_name": st.label,
                    "lapse_event_id": lapse_event,
                    "lapsed_since": lapse.get("since") or st.zero_since,
                    "restored_hour": key,
                    "queries": int(queries),
                    "detected_at": format_utc_ms(restored_at),
                },
            })
            event_id, restored_vid = None, vid
        st.last_restore = {"at": format_utc_ms(restored_at), "slug": st.slug,
                           "lapse_event_id": lapse_event if lapse_event is not None
                           else lr.get("lapse_event_id") if lapse.get("episode") else None,
                           "lapse_vid": lapse_vid,
                           "restored_event_id": event_id, "restored_vid": restored_vid}
        st.state, st.state_since = ACTIVE, format_utc_ms(restored_at)
        st.zero_hours, st.zero_since, st.busy_since, st.zero_list = 0, None, None, []
        st.lapse = None
        st.restore_streak = 0
        logger.info("[nextdns-poller] profile %s is reporting queries again", st.pid)

    def _restoration_notes(
        self, slug: str, profile: str, event_id: int, lapse_event: Optional[int],
        lapse: dict[str, Any], restored_hour: str,
    ) -> None:
        """The deterministic L1 note on the RESTORED alert (below the triage
        worker's floor, so written here, with the engine's own words), and a
        vendor-update note on the LAPSED alert pointing forward — both in
        the profile's own tenant (a lapse of another tenant is never
        referenced)."""
        from apps.octo.agent.heuristic_l1 import DnsFilterEvent, TriageFeatures, triage

        decision = triage(TriageFeatures(
            severity="low", has_indicator=False,
            dns_filter=DnsFilterEvent(
                kind="restored", level="low", profile=profile,
                lapse_event_id=lapse_event, lapsed_since=lapse.get("since"),
                restored_hour=restored_hour,
            ),
        ))
        write_note(
            slug, event_id, decision.note_text(), marker=f"restored:{event_id}",
            query_kind=NOTE_KIND_TRIAGE, disposition=decision.disposition,
            confidence=decision.confidence,
        )
        if lapse_event is not None and lapse.get("slug") == slug:
            write_note(
                slug, lapse_event,
                f"NextDNS is reporting queries again from {_hour_text(restored_hour)} — "
                f"recorded as event #{event_id}.",
                marker=f"restored-by:{event_id}", query_kind=NOTE_KIND_VENDOR,
            )

    # ----- local: bucket close notes -----

    def _read_mark(self, st: ProfileState) -> Optional[datetime]:
        """The oldest line time the security path may still count for a
        watched profile: its pending log pull's resume point, else its last
        check minus the overlap (the next window's start). None: not watched
        (nothing more will be read for it)."""
        if st.missing or st.state not in (ACTIVE, LAPSED):
            return None
        if st.logs:
            return _dt(st.logs.get("resume") or st.logs.get("from"))
        checked = _dt(st.checked_to)
        return checked - self._overlap if checked is not None else None

    # ----- the entity feed (feed.py): per PROFILE, never per device -----

    def _entity_feed(self, report: CycleReport) -> None:
        """Per mapped profile whose tenant wants it: device-hour reads for
        EVERY profile first, then the 14-day seed, then the daily per-IP
        read — within ENTITY_CALLS_PER_CYCLE, yielding to security checks,
        starting at a profile that rotates every cycle."""
        consumer = feed.current()
        wants: dict[str, bool] = {}
        now = self._now()
        latest = _hour_floor(now - timedelta(seconds=HOURLY_DELAY_SEC)) - timedelta(hours=1)
        hours = [hour_key(latest - timedelta(hours=i)) for i in range(ENTITY_HOURS_BACK)][::-1]
        day = (now - timedelta(days=1)).strftime("%Y-%m-%d")
        seed_days = [(now - timedelta(days=i)).strftime("%Y-%m-%d")
                     for i in range(1, ENTITY_SEED_DAYS + 1)]
        ordered = sorted(self._profiles.values(), key=lambda x: x.pid)
        if ordered:
            turn = self._entity_turn % len(ordered)
            ordered = ordered[turn:] + ordered[:turn]
            self._entity_turn += 1
        eligible: list[ProfileState] = []
        for st in ordered:
            if st.missing or st.state == NEW or self._blocked(st, HEALTH_PATH, now):
                continue
            if st.slug not in wants:
                wants[st.slug] = bool(feed.call(consumer, "wants", st.slug, default=False))
            if wants[st.slug] and self._still_mapped(st):
                eligible.append(st)
        calls = 0

        def room() -> bool:
            if self._abort.is_set() or calls >= ENTITY_CALLS_PER_CYCLE:
                return False
            return not (calls >= ENTITY_MIN_CALLS_BEFORE_YIELD and self._any_security_due())

        # 1. device presence — every profile before any other entity read
        for st in eligible:
            if not room():
                break
            if self._entity_held(st.pid, "devices", now):
                continue
            need = feed.call(consumer, "hours_needed", st.slug, st.pid, hours, default=[]) or []
            for h in [h for h in hours if h in need][-ENTITY_HOURS_PER_PROFILE:]:
                if not room():
                    break
                calls += 1
                if not self._device_hour(st, h, consumer, report):
                    break
        # 2. the seed (once per profile and day, analytics only — and only for
        #    a profile whose analytics/devices answers)
        for st in eligible:
            if not room():
                break
            if self._entity_held(st.pid, "devices", now) or self._entity_held(st.pid, "seed", now) \
                    or st.pid in self._devices_refused or self._devices_sampled(st.pid, now):
                continue
            need = feed.call(consumer, "seed_days_needed", st.slug, st.pid, seed_days,
                             default=[]) or []
            for d in [d for d in seed_days if d in need][:ENTITY_SEED_DAYS_PER_CYCLE]:
                if not room():
                    break
                calls += 1
                if not self._device_day(st, d, consumer, report):
                    break
        # 3. per-IP volume (yesterday), once a day per profile
        if now.hour >= 1:
            for st in eligible:
                if not room():
                    break
                if self._ips_refused_day.get(st.pid) == day or \
                        self._entity_held(st.pid, "ips", now):
                    continue
                if feed.call(consumer, "day_needed", st.slug, st.pid, day, default=False):
                    calls += 1
                    self._ip_day(st, day, consumer, report)
        for slug in sorted(s for s, w in wants.items() if w):
            for item in feed.call(consumer, "pending_signals", slug, default=[]) or []:
                if not isinstance(item, dict) or not isinstance(item.get("key"), str):
                    continue
                payload = self._payload_device_signal(slug, item)
                if payload is None:
                    continue
                event_id = self._ingest(slug, payload)
                if event_id is not None:
                    feed.call(consumer, "signal_stored", slug, item["key"], event_id)
                    report.signals += 1

    # ----- entity reads: each one's failure is that profile's alone -----

    def _entity_held(self, pid: str, read: str, now: datetime) -> bool:
        hold = self._entity_hold.get((pid, read))
        return hold is not None and now < hold[0]

    def _entity_failed(self, pid: str, read: str, why: str) -> None:
        _until, n = self._entity_hold.get((pid, read), (self._now(), 0))
        delay = min(ENTITY_HOLD_CEILING, ENTITY_HOLD_BASE * (2 ** min(n, 16)))
        self._entity_hold[(pid, read)] = (self._now() + delay, n + 1)
        log = logger.warning if n == 0 else logger.debug
        log("[nextdns-poller] profile %s: entity read %s %s; asked again in %d min (the other "
            "reads and profiles go on)", pid, read, why, int(delay.total_seconds() // 60))

    def _entity_ok(self, pid: str, read: str) -> None:
        self._entity_hold.pop((pid, read), None)

    def _devices_sampled(self, pid: str, now: datetime) -> bool:
        """This profile samples its log instead of analytics/devices (it was
        refused ENTITY_DEVICES_REFUSALS times in a row) until the re-probe."""
        until = self._devices_fallback_until.get(pid)
        if until is None:
            return False
        if now >= until:
            del self._devices_fallback_until[pid]       # ask analytics/devices again
            self._devices_refused[pid] = ENTITY_DEVICES_REFUSALS - 1
            return False
        return True

    def _entity_read(self, fn: Callable[[], Any]) -> Any:
        """One entity-feed read. A rejected key / stop / a key-wide throttle
        (429) ends the cycle like any read; a 403 is raised for the caller to
        hold that profile's read (NextDNS refusing ONE read class of one
        profile is that profile's problem, not the key's); any other failure
        is that hour's (or day's) alone — it stays unread (never "silent")."""
        try:
            out = fn()
        except (NextDNSAborted, NextDNSAuthError, NextDNSThrottledError):
            raise
        except NextDNSClientError as exc:
            logger.info("[nextdns-poller] entity feed read failed (%s)", type(exc).__name__)
            return None
        self._contact_ok()
        return out

    def _device_hour(self, st: ProfileState, hour: str, consumer: Any,
                     report: CycleReport) -> bool:
        """One profile-hour of device presence. False when that profile's
        device reads should stop for this cycle."""
        start = _hour_start(hour)
        end = start + timedelta(hours=1)
        method, complete, devices, total = "analytics", True, None, None
        if not self._devices_sampled(st.pid, self._now()):
            try:
                devices = self._client.analytics_devices(st.pid, from_=start, to=end,
                                                         priority=PRIORITY_HEALTH)
                self._contact_ok()
                self._devices_refused.pop(st.pid, None)
                self._entity_ok(st.pid, "devices")
            except (NextDNSAborted, NextDNSAuthError):
                raise
            except NextDNSThrottledError as exc:
                if exc.status != 403:
                    raise                       # 429: the key is throttled — the cycle ends
                self._entity_failed(st.pid, "devices", "refused (HTTP 403)")
                return False
            except NextDNSClientError as exc:
                if isinstance(exc, NextDNSNotFoundError) or "HTTP 400" in str(exc):
                    n = self._devices_refused.get(st.pid, 0) + 1
                    self._devices_refused[st.pid] = n
                    if n < ENTITY_DEVICES_REFUSALS:
                        logger.info("[nextdns-poller] profile %s: analytics/devices refused "
                                    "(%s, %d in a row); asked again next cycle", st.pid,
                                    type(exc).__name__, n)
                        return False
                    self._devices_fallback_until[st.pid] = self._now() + ENTITY_DEVICES_REPROBE
                    logger.warning(
                        "[nextdns-poller] profile %s: analytics/devices refused %d times in a "
                        "row (%s); its device presence samples one log page per hour, and "
                        "analytics/devices is asked again in %d h", st.pid, n,
                        type(exc).__name__, int(ENTITY_DEVICES_REPROBE.total_seconds() // 3600))
                else:
                    logger.info("[nextdns-poller] analytics/devices failed (%s)",
                                type(exc).__name__)
                    self._entity_failed(st.pid, "devices", f"failed ({type(exc).__name__})")
                    return False
        if devices is None:
            try:
                page = self._entity_read(lambda: self._client.logs(
                    st.pid, from_=start, to=end, status=None, limit=LOG_PAGE_SIZE, sort="desc",
                    priority=PRIORITY_HEALTH))
            except NextDNSThrottledError as exc:
                if exc.status != 403:
                    raise
                self._entity_failed(st.pid, "devices", "log sample refused (HTTP 403)")
                return False
            if page is None:
                return False
            method, complete = "logs", page.cursor is None
            agg: dict[str, dict[str, Any]] = {}
            for line in page.lines:
                dev = line.get("device") if isinstance(line.get("device"), dict) else {}
                did = _text(dev.get("id"), 64) or None
                name = _text(dev.get("name"), 120) or None
                key = did or (f"name:{name}" if name else None)
                if key is None:
                    continue
                entry = agg.setdefault(key, {"id": did or key, "name": name,
                                             "model": _text(dev.get("model"), 80) or None,
                                             "local_ip": None, "queries": 0,
                                             "client": _text(line.get("client"), 32) or None})
                entry["queries"] += 1
            devices = list(agg.values())
            total = len(page.lines)
        report.contacted = True
        feed.call(consumer, "on_device_hour", st.slug, st.pid, {
            "hour": hour, "complete": complete, "method": method, "devices": devices,
            "total": total, "read_at": format_utc_ms(self._now()), "profile_name": st.label,
        })
        return True

    def _device_day(self, st: ProfileState, day: str, consumer: Any,
                    report: CycleReport) -> bool:
        """One day of the 14-day seed (analytics/devices for the UTC day)."""
        start = datetime.strptime(day, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        try:
            devices = self._entity_read(lambda: self._client.analytics_devices(
                st.pid, from_=start, to=start + timedelta(days=1), priority=PRIORITY_HEALTH))
        except NextDNSThrottledError as exc:
            if exc.status != 403:
                raise
            self._entity_failed(st.pid, "devices", "seed refused (HTTP 403)")
            return False
        if devices is None:
            self._entity_failed(st.pid, "seed", "failed")
            return False
        report.contacted = True
        feed.call(consumer, "on_device_day", st.slug, st.pid, {
            "day": day, "devices": devices, "read_at": format_utc_ms(self._now())})
        return True

    def _ip_day(self, st: ProfileState, day: str, consumer: Any, report: CycleReport) -> None:
        start = datetime.strptime(day, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        try:
            ips = self._client.analytics_ips(st.pid, from_=start, to=start + timedelta(days=1),
                                             priority=PRIORITY_HEALTH)
            self._contact_ok()
        except (NextDNSAborted, NextDNSAuthError):
            raise
        except NextDNSThrottledError as exc:
            if exc.status != 403:
                raise                           # 429: the key is throttled — the cycle ends
            self._ips_refused_day[st.pid] = day
            logger.warning("[nextdns-poller] profile %s: analytics/ips refused (HTTP 403); not "
                           "asked again for %s", st.pid, day)
            return
        except NextDNSClientError as exc:
            if isinstance(exc, NextDNSNotFoundError) or "HTTP 400" in str(exc):
                self._ips_refused_day[st.pid] = day
                logger.warning("[nextdns-poller] profile %s: analytics/ips refused (%s); not "
                               "asked again for %s", st.pid, type(exc).__name__, day)
            else:
                self._entity_failed(st.pid, "ips", f"failed ({type(exc).__name__})")
            return
        self._entity_ok(st.pid, "ips")
        report.contacted = True
        feed.call(consumer, "on_ip_day", st.slug, st.pid, {
            "day": day, "total": sum(q for _ip, q in ips), "ips": [[ip, q] for ip, q in ips],
            "read_at": format_utc_ms(self._now())})

    def _payload_device_signal(self, slug: str, item: dict[str, Any]) -> Optional[dict[str, Any]]:
        """The stored payload of a device-silence finding — built HERE, at the
        adapter boundary, with its OCSF mapping."""
        kind = item.get("kind")
        if kind not in ("device_silent", "device_restored"):
            return None
        pid = valid_profile_id(item.get("profile_id"))
        detected = normalize_timestamp(item.get("detected_at"), naive_is_utc=True)
        if pid is None or not detected:
            return None
        st = self._profiles.get(pid)
        device = item.get("device") if isinstance(item.get("device"), dict) else {}
        datto = item.get("datto") if isinstance(item.get("datto"), dict) else {}
        hostname = _text(datto.get("hostname"), 64) or None
        dname = _text(device.get("name"), 120) or None
        level = "medium" if kind == "device_silent" else "low"
        title = (f"NextDNS stopped reporting from {hostname or dname or 'a computer'} — "
                 "Datto shows it online") if kind == "device_silent" else \
            f"NextDNS reporting again from {hostname or dname or 'a computer'}"
        eid = f"{kind}:{pid}:{_text(device.get('id'), 64)}:{_text(item.get('silent_since'), 32)}"
        payload: dict[str, Any] = {
            "vendor_event_id": eid[:128],
            "kind": kind,
            "profile_id": pid,
            "profile_name": (st.label if st else "") or _text(item.get("profile_name"), 80),
            "detected_at": detected,
            "device": {k: v for k, v in {"id": _text(device.get("id"), 64) or None,
                                         "name": dname,
                                         "model": _text(device.get("model"), 80) or None}.items()
                       if v},
            "datto": {k: v for k, v in {
                "hostname": hostname, "device_uid": _text(datto.get("device_uid"), 64) or None,
                "os": _text(datto.get("os"), 80) or None,
                "online_since": _text(datto.get("online_since"), 32) or None,
                "last_seen": _text(datto.get("last_seen"), 32) or None}.items() if v},
            "silent_since": _text(item.get("silent_since"), 32) or None,
            "silent_hours": item.get("silent_hours") if isinstance(item.get("silent_hours"), int)
            else None,
            # When the device LAST reported (an hour, or a day of the seed):
            # the silence is usually much longer than the verified run.
            "last_report": _text(item.get("last_report"), 32) or None,
            "last_report_precision": item.get("last_report_precision")
            if item.get("last_report_precision") in ("hour", "day") else None,
            "profile_silent_too": bool(item.get("profile_silent_too")),
            "link": {"state": _text(item.get("link_state"), 16) or None,
                     "rule": _text(item.get("link_rule"), 24) or None},
            "signal": {"level": level},
        }
        if kind == "device_restored":
            payload["restored_hour"] = _text(item.get("restored_hour"), 32) or None
            if isinstance(item.get("silent_event_id"), int):
                payload["silent_event_id"] = item["silent_event_id"]
        payload["ocsf"] = ocsf.project_device_finding(
            kind, time_ms=int(_dt(detected).timestamp() * 1000) if _dt(detected) else 0,
            severity=level, event_uid=eid[:128], profile_id=pid, title=title,
            hostname=hostname, device_name=dname,
            nextdns_device_id=_text(device.get("id"), 64) or None,
            datto_uid=_text(datto.get("device_uid"), 64) or None, original_time=detected,
            last_report=payload.get("last_report"), silent_since=payload.get("silent_since"))
        return {k: v for k, v in payload.items() if v is not None}

    def _close_buckets(self) -> None:
        """A bucket whose span is over (+ one interval and the overlap, so a
        late re-read cannot still count into it) and that had more than one
        hit gets ONE note on its alert: how many lookups — and, for a bucket
        without the domain in its key, how many distinct domains (masked
        samples)."""
        cutoff = self._now() - timedelta(seconds=self._interval) - self._overlap
        before = hour_key(cutoff)
        before_day = before[:11] + "00:00:00Z"
        # A profile whose lines are not read up to the cutoff yet (a log
        # backlog after downtime, a throttle, its own backoff across the
        # span's end) holds its spans open: the note counts every line.
        held: dict[str, dict[str, str]] = {}
        for st in self._profiles.values():
            mark = self._read_mark(st)
            if mark is not None and mark < cutoff:
                held.setdefault(st.slug, {})[st.pid] = hour_key(mark)
        for slug in sorted({st.slug for st in self._profiles.values()}):
            try:
                closed = store.closed_unnoted(slug, before_hour=before, before_day=before_day,
                                              held=held.get(slug))
            except (sqlite3.Error, OSError, ValueError):
                continue
            for b in closed:
                ok = True
                if b.hits > 1:
                    when = (f"on {b.hour[:10]} (UTC)" if b.span == store.SPAN_DAY
                            else f"in the hour from {_hour_text(b.hour)}")
                    what = f"Seen {b.hits} times {when}"
                    if b.distinct_roots > 1:
                        at_least = "at least " if b.distinct_roots >= store.MAX_ROOTS else ""
                        samples = ", ".join(masked_samples(b.sample_roots))
                        what = (f"{b.hits} lookups across {at_least}{b.distinct_roots} different "
                                f"domains {when}" + (f" (e.g. {samples})" if samples else ""))
                    elif b.distinct_roots == 1:
                        what += ", all for the same domain"
                    ok = write_note(
                        slug, b.event_id,
                        f"{what} — first {b.first_seen[11:19]}, last {b.last_seen[11:19]} UTC: "
                        "NextDNS blocked every one; only the first raised this alert.",
                        marker=f"bucket:{b.key}", query_kind=NOTE_KIND_VENDOR,
                    )
                if ok:
                    try:
                        store.mark_noted(slug, b.key)
                    except (sqlite3.Error, OSError):
                        pass

    # ----- discovery -----

    def _maybe_discover(
        self, now: datetime, report: CycleReport, *, force: bool = False,
        priority: int = PRIORITY_DISCOVERY, swallow: bool = True,
    ) -> None:
        """The profile list, when due (or `force`). `swallow`: a transport
        error is logged and retried next interval instead of ending the
        cycle (the list is not the only contact while profiles are polled).
        A throttle or a rejected key always propagates."""
        if not force and self._discovery_due is not None and now < self._discovery_due:
            return
        if self._abort.is_set():
            return
        try:
            profiles = self._client.list_profiles(priority=priority)
        except NextDNSNotFoundError:
            self._vendor_answered()
            return
        except NextDNSThrottledError:
            raise
        except NextDNSClientError as exc:
            if isinstance(exc, NextDNSAborted):
                raise
            self._vendor_failed(exc)
            if not swallow:
                raise
            logger.warning("[nextdns-poller] profile list not read (%s); asked again next "
                           "interval", exc)
            self._discovery_due = now + timedelta(seconds=self._interval)
            return
        self._contact_ok()
        report.contacted = True
        report.discovery = True
        self._known = {p.id: p.name for p in profiles}
        self._known_at = self._now()
        # Every 6 h — or every interval while no profile is watched (nothing
        # mapped yet, or only pending ones): then the list IS the contact
        # that tells source health the integration works (6 calls an hour),
        # and a profile added while the operator maps shows up promptly.
        watched = any(st.state in (ACTIVE, LAPSED) for st in self._profiles.values())
        every = DISCOVERY_EVERY_SEC if watched else self._interval
        self._discovery_due = now + timedelta(seconds=every)
        self._share_discovery(profiles)
        for st in self._profiles.values():
            if st.pid in self._known and self._known[st.pid] and not st.label:
                st.label = _text(self._known[st.pid], 120)
            if st.missing and st.pid in self._known:
                st.probe_due = True             # listed again: re-check now

    def _share_discovery(self, profiles: list[Any]) -> None:
        """Hand the listing to the platform's discovery cache (the mapping
        panel and the card read it without asking NextDNS again). Best
        effort — keyed by the instance's cred_ref like every listing."""
        if self._instance_id is None:
            return
        try:
            from shared_adapter_contract.types import VendorTenant, VendorTenantListing

            from apps.octo.instances import vendor_tenants
            from apps.octo.instances.manager import get_instance

            record = get_instance(self._instance_id)
            if record is None or record.disabled_at is not None:
                return
            vendor_tenants.store(self._instance_id, record.cred_ref, VendorTenantListing(
                tenants=[VendorTenant(id=p.id, label=p.name or f"Profile {p.id}")
                         for p in profiles],
            ))
        except Exception as exc:  # noqa: BLE001
            logger.debug("[nextdns-poller] discovery not shared (%s)", type(exc).__name__)

    def known_profiles(self) -> Optional[dict[str, str]]:
        return dict(self._known) if self._known is not None else None

    # ----- snapshot for the card / source health -----

    def _update_snapshot(self) -> None:
        counts = {s: 0 for s in (*STATES, NEW)}
        missing = problems = 0
        states: dict[str, dict[str, Any]] = {}
        for st in self._profiles.values():
            counts[st.state] = counts.get(st.state, 0) + 1
            missing += 1 if st.missing else 0
            problems += 1 if st.problem else 0
            states[st.pid] = {
                "profile_id": st.pid, "name": st.label, "tenant_slug": st.slug,
                "state": st.state, "since": st.state_since, "queries_24h": st.q24,
                "queries_24h_at": st.q24_at, "last_check_at": st.checked_to,
                # The last status / probe read (classification, the pending
                # check, a missing profile's re-probe) — what a PENDING / NEW
                # / missing profile's freshness is judged by (Fleet v2).
                "health_at": st.health_at,
                "missing": st.missing, "backlog": bool(st.logs),
                "problem": st.problem, "problem_kind": st.problem_kind,
                "problem_at": st.problem_at, "logs_enabled": st.logs_enabled,
                "lapse_cause": (st.lapse or {}).get("cause") if st.state == LAPSED else None,
                "baseline_seeded": bool(st.seed and st.seed.get("from")),
            }
        budget = self.planned_calls_per_hour()
        now = self._now()
        cutoff = hour_key(now - timedelta(hours=24))
        fleet = self._fleet if self._fleet and self._fleet.get("open") else None
        down = self._unreachable_since(now)
        snap = {
            "mapped": len(self._profiles),
            "counts": counts,
            "missing": missing,
            "problems": problems,
            "states": states,
            "known": len(self._known) if self._known is not None else None,
            "known_ids": sorted(self._known) if self._known is not None else None,
            "known_at": format_utc_ms(self._known_at) if self._known_at else None,
            "stretched": self._stretched,
            # No call has succeeded for UNREACHABLE_AFTER_INTERVALS intervals
            # since calls started failing: when they started (else None).
            "unreachable_since": format_utc_ms(down) if down is not None else None,
            "rollup_lag_hours": self._rollup_lag_hours(now),
            "analytics_gaps": [h for h in self._gap_hours if h >= cutoff],
            "fleet_outage": ({
                "sites": int(fleet.get("sites_now") or fleet.get("sites") or 0),
                "watched": int(fleet.get("watched") or 0),
                "since": fleet.get("since"), "tenant": fleet.get("slug"),
                "event_id": fleet.get("event_id"),
            } if fleet else None),
            "calls_per_hour_planned": round(budget["total"], 1),
            "spacing_sec": self._client.limiter.min_spacing_sec,
            "interval_sec": self._interval,
            # How often a watched profile is ACTUALLY checked: the interval,
            # or longer while the cycle stretches (Fleet v2 ages security
            # checks against this, never against the bare interval).
            "security_round_sec": self._security_round_sec(budget["total"]),
            "pending_check_sec": self._pending_every.total_seconds(),
            # Profiles whose device presence samples one log page per hour
            # (analytics/devices refused there) until the re-probe — shown,
            # never silent: a sampled busy hour is not "read whole".
            "device_presence_sampled": sorted(self._devices_fallback_until),
        }
        with self._snap_lock:
            self._snapshot = snap


def masked_samples(roots: Any, limit: int = store.SAMPLE_ROOTS) -> list[str]:
    """Up to `limit` DISTINCT masked forms of `roots`, in order. Masking
    keeps two letters and the TLD, so many roots mask alike: each form is
    shown once, drawing on more of the roots."""
    from apps.octo.api.indicator_mask import mask_indicator

    out: list[str] = []
    for root in roots or ():
        if not isinstance(root, str) or not root:
            continue
        masked = mask_indicator(root, "domain")
        if masked not in out:
            out.append(masked)
            if len(out) >= limit:
                break
    return out


def write_note(
    slug: str, event_id: int, text: str, *, marker: str, query_kind: str,
    disposition: Optional[str] = None, confidence: float = 1.0,
) -> bool:
    """ONE agent note (agent 'octo') on stored alert `event_id` per marker —
    an existing one is found, not duplicated. The alert row itself is never
    touched. True when the note exists afterwards; never raises."""
    from apps.octo.agent import notes as agent_notes

    db = paths.client_dir(slug) / "events.db"
    request_id = f"nextdns-{hashlib.sha256(marker.encode()).hexdigest()[:24]}"
    try:
        conn = sqlite3.connect(db, timeout=10.0)
        try:
            agent_notes.ensure_agent_schema(conn)
            with conn:
                if conn.execute("SELECT 1 FROM events WHERE id = ?", (event_id,)).fetchone() is None:
                    return False
                if conn.execute(
                    "SELECT 1 FROM agent_notes WHERE ref_kind = 'event' AND ref_id = ? "
                    "AND audit_request_id = ?", (event_id, request_id),
                ).fetchone() is None:
                    agent_notes.insert_agent_note_row(
                        conn, ref_kind="event", ref_id=event_id, agent_id="octo",
                        note_text=text, confidence=confidence, request_id=request_id,
                        query_kind=query_kind, disposition=disposition,
                    )
        finally:
            conn.close()
    except (sqlite3.Error, OSError) as exc:
        logger.warning("[nextdns-poller] note on %s #%s not written (%s)", slug, event_id,
                       type(exc).__name__)
        return False
    return True


__all__ = [
    "ACTIVE", "ACTIVE_THRESHOLD", "EVENT_BLOCK", "EVENT_FLEET", "EVENT_LAPSED",
    "EVENT_RESTORED", "LAPSED", "NEW", "PENDING", "PROFILE_KEY_PREFIX", "STATE_KEY",
    "NextDNSPoller", "ProfileState", "hour_key", "line_identity", "masked_samples",
    "pack_hours", "profile_state_key", "unpack_hours", "write_note",
]
