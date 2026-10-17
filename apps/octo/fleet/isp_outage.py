"""ISP-outage correlation — several sites on ONE provider losing their
internet at once are ONE incident, not N site alerts.

Run by the UniFi poller after every fleet poll (`evaluate`, 5 min), over the
MAPPED sites of that poll only (an unmapped / ignored console is nobody's
site and is never named anywhere). Local state only: no vendor call.

PER SITE, per ASN ("trouble"):
  * the console is unreachable (`/v1/hosts` state not connected) → the site's
    PRIMARY ASN (statistics.ispInfo, else its first WAN's);
  * a WAN port is down (`portUp` false) → THAT WAN's ASN (a dual-WAN site
    whose backup ISP fails is that ISP's, not its primary's);
  * NEW internet / WAN issues since the previous poll (entries whose stable
    key was not there before — the lists may be histories) → the ASN.
The ONSET of a trouble is only ever OBSERVED: the site was seen without it
in the previous fresh poll (at most two fleet intervals old) and with it now.
A site already in trouble when first seen (a start, a gap in the polls, a
new mapping) has an UNKNOWN onset and never forms an incident — so a restart
can never correlate the backlog of every site that happened to be down.

FAILURE POINTS, not sites: each trouble carries the UNIT that failed — a
console that is unreachable is ONE unit however many sites it carries (a
multi-site / hosted console rebooting is one console, not "N sites"); a WAN
trouble is its public address's unit (sites behind one shared address are
one), else — no address known — the console's when it carries several
observed sites, else the site's own. Counting is over units; every site of a
counted unit is listed.

OPEN: >= `min_sites` (3; OCTO_FLEET_ISP_OUTAGE_MIN_SITES, 2..50) failure
points of the same ASN whose observed onsets fall within `window` (10 min;
OCTO_FLEET_ISP_OUTAGE_WINDOW_MIN, 5..60) of each other, the newest of them
within `window` of NOW (an old cluster never opens late) → ONE
`fleet.isp_outage` signal (HIGH, OCSF Incident Finding 2005 — mapped at the
UniFi adapter boundary, `ocsf.project_isp_outage`) in the operator's
INTERNAL tenant (the oldest active tenant of kind 'internal'; none → the
incident is tracked and shown, never written): "ISP outage: <ISP> — N
sites". One site (or one console) never correlates; mixed ASNs never add
up (sites are grouped by ASN); a FLEET-WIDE wave (>= half of the observed
sites, across >= 3 ASNs, within the window — the UniFi cloud itself, not an
ISP) opens nothing and is shown as suppressed — and STAYS suppressed: its
(ASN, site, onset) troubles are remembered in the stored state while they
last, so the wave can never turn into per-ASN incidents once it is older
than the window.
WHILE OPEN: a later site of that ASN joins (one note on the incident when
the count grows); each member site's own WAN alerts (`unifi.wan_down` /
`unifi.wan_failover` in ITS tenant, from the window before the onset) get a
note linking them to the incident — the client's note names only its own
provider: no count, no ASN, no time, never another client (the size of an
outage across clients is the operator's, not a client's) — and the incident
(internal tenant) gets one note listing what was grouped.
CLOSE: fewer than `min_sites` failure points still down AND at least half of the
members still observed seen back → a closing note ("N of M sites are back"); the same ASN failing
again within 30 minutes reopens THE SAME incident with a note.

IDEMPOTENT ACROSS RESTARTS: the state (per-site keys and onsets, the
incidents, an OUTBOX of the signal and notes) is in the registry
(`adapter_poller_state`, key 'isp_outage' under the UniFi instance), saved
BEFORE anything is written; the signal's payload is fixed when it is queued
(its id `isp:<instance>:<asn>:<onset>`, its time the opening), so the sink's
identity guard answers a re-delivery with the stored row; every note has a
marker (one note per marker). A registry that cannot be read decides
nothing that cycle.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
from datetime import datetime, timedelta
from typing import Any, Callable, Mapping, Optional

from apps.octo import paths
from apps.octo.db import connect
from apps.octo.fleet.state import primary_wan
from apps.octo.ingest.timestamps import format_utc_ms, normalize_timestamp

logger = logging.getLogger(__name__)

KIND = "isp_outage"
EVENT_TYPE = "fleet.isp_outage"
STATE_KEY = "isp_outage"
STATE_VERSION = 1
DEFAULT_MIN_SITES = 3
DEFAULT_WINDOW_MIN = 10
MIN_SITES_ENV = "OCTO_FLEET_ISP_OUTAGE_MIN_SITES"
WINDOW_ENV = "OCTO_FLEET_ISP_OUTAGE_WINDOW_MIN"
RELAPSE_WINDOW = timedelta(minutes=30)
# A previous observation older than this many fleet intervals (+ slack) says
# nothing about a transition ("feed older than 2 polls" = unknown).
STALE_INTERVALS = 2
STALE_SLACK = timedelta(seconds=60)
PLATFORM_SHARE = 0.5
PLATFORM_MIN_ASNS = 3
MAX_LISTED = 50
MAX_GROUPED = 200
MAX_KEYS = 50
MAX_CLOSED_KEPT = 20
MAX_OUTBOX = 500
MAX_SUPPRESSED = 2000
NOTE_KIND = "vendor_update"
WAN_ALERT_TYPES = ("unifi.wan_down", "unifi.wan_failover")
GROUP_SCAN_LIMIT = 50


def _clamp_env(env: Optional[Mapping[str, str]], name: str, default: int, low: int,
               high: int) -> int:
    raw = (os.environ if env is None else env).get(name)
    try:
        value = int(str(raw).strip()) if raw not in (None, "") else default
    except ValueError:
        value = default
    return max(low, min(high, value))


def min_sites(env: Optional[Mapping[str, str]] = None) -> int:
    """How many sites of one ASN make an ISP outage (default 3, 2..50)."""
    return _clamp_env(env, MIN_SITES_ENV, DEFAULT_MIN_SITES, 2, 50)


def window(env: Optional[Mapping[str, str]] = None) -> timedelta:
    """How close together their onsets must be (default 10 min, 5..60)."""
    return timedelta(minutes=_clamp_env(env, WINDOW_ENV, DEFAULT_WINDOW_MIN, 5, 60))


def _iso(dt: datetime) -> str:
    return format_utc_ms(dt)


def _dt(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    ts = normalize_timestamp(value, naive_is_utc=True)
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def _hhmm(value: Any) -> str:
    dt = _dt(value)
    return dt.strftime("%Y-%m-%d %H:%M UTC") if dt else "an unknown time"


def internal_tenant() -> Optional[str]:
    """The operator's own tenant — the ACTIVE client of kind 'internal' (the
    oldest when there are several) — where fleet-wide signals go."""
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


# ---------------------------------------------------------------------------
# One site's troubles
# ---------------------------------------------------------------------------

def _int(value: Any) -> Optional[int]:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def primary_isp(site: Mapping[str, Any]) -> tuple[Optional[int], str]:
    """(ASN, ISP name) the site reaches the internet through: the site's
    statistics.ispInfo, else its first IPv4 WAN that names one."""
    stats = site.get("stats") if isinstance(site.get("stats"), dict) else {}
    asn, name = _int(stats.get("isp_asn")), str(stats.get("isp_name") or "")
    if asn is not None:
        return asn, name
    for w in site.get("wans") or []:
        if not isinstance(w, dict) or str(w.get("wan") or "").endswith(("/v6", "/pd")):
            continue
        if _int(w.get("asn")) is not None:
            return _int(w.get("asn")), str(w.get("isp") or name)
    return None, name


def site_troubles(
    site: Mapping[str, Any],
    prev_keys: Optional[set[str]],
    prev_wan_keys: Optional[dict[str, set[str]]],
) -> dict[int, tuple[str, str]]:
    """{ASN: (ISP name, why)} for what is wrong with the site NOW. `prev_*`
    None = no fresh previous poll (new issue entries cannot be told)."""
    out: dict[int, tuple[str, str]] = {}
    asn, isp = primary_isp(site)
    connected = site.get("host_connected")
    if connected is False and asn is not None:
        out[asn] = (isp, "console unreachable")
    primary = primary_wan(site.get("wans") or [])
    for w in site.get("wans") or []:
        if not isinstance(w, dict) or str(w.get("wan") or "").endswith(("/v6", "/pd")):
            continue
        if primary is not None and str(w.get("wan")) != primary:
            continue                    # a backup line is nice-to-have, never an outage
        wasn = _int(w.get("asn"))
        if w.get("port_up") is False and wasn is not None:
            out.setdefault(wasn, (str(w.get("isp") or isp), f"{w.get('wan') or 'WAN'} down"))
    if connected is False:
        return out
    stats = site.get("stats") if isinstance(site.get("stats"), dict) else {}
    keys = [k for k in (stats.get("internet_issue_keys") or []) if isinstance(k, str)]
    if prev_keys is not None and asn is not None and any(k not in prev_keys for k in keys):
        out.setdefault(asn, (isp, "internet issues"))
    wan_keys = stats.get("wan_issue_keys") if isinstance(stats.get("wan_issue_keys"), dict) else {}
    if prev_wan_keys is not None:
        by_wan = {str(w.get("wan")): w for w in site.get("wans") or [] if isinstance(w, dict)}
        for wan, wkeys in wan_keys.items():
            if primary is not None and str(wan) != primary:
                continue                # backup-line issues never make an ISP outage
            before = prev_wan_keys.get(wan, set())
            if not any(isinstance(k, str) and k not in before for k in (wkeys or [])):
                continue
            w = by_wan.get(wan) or {}
            wasn = _int(w.get("asn")) if w else None
            wasn = wasn if wasn is not None else asn
            if wasn is not None:
                out.setdefault(wasn, (str(w.get("isp") or isp), f"{wan} issues"))
    return out


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def failure_unit(site: Mapping[str, Any], asn: int, why: str, *,
                 console_sites: int = 1) -> str:
    """WHAT failed for this trouble — the correlation counts these, not
    sites. An unreachable console is its console (`h:`); a WAN trouble is
    the public address of a WAN on that ASN (`ip:`, digested — sites behind
    one shared address are one); with no address known, the console when it
    carries several observed sites (never counted twice), else the site."""
    scope = str(site.get("scope") or "")
    host = str(site.get("host_id") or scope.split("/")[0] or scope)
    if why == "console unreachable":
        return f"h:{_digest(host)}"
    wans = [w for w in site.get("wans") or [] if isinstance(w, dict) and w.get("external_ip")
            and not str(w.get("wan") or "").endswith(("/v6", "/pd"))]
    ips = sorted(str(w["external_ip"]) for w in wans if _int(w.get("asn")) == asn)
    if not ips and primary_isp(site)[0] == asn:
        ips = sorted(str(w["external_ip"]) for w in wans if _int(w.get("asn")) is None)
    if ips:
        return f"ip:{_digest(ips[0])}"
    if console_sites > 1:
        return f"h:{_digest(host)}"
    return f"s:{_digest(scope)}"


def cluster(onsets: list[tuple[str, datetime]], span: timedelta) -> list[tuple[str, datetime]]:
    """The largest group of (scope, onset) whose onsets lie within `span` of
    each other (the most recent such group on a tie)."""
    items = sorted(onsets, key=lambda x: (x[1], x[0]))
    best: list[tuple[str, datetime]] = []
    lo = 0
    for hi in range(len(items)):
        while items[hi][1] - items[lo][1] > span:
            lo += 1
        if hi - lo + 1 >= len(best):
            best = items[lo:hi + 1]
    return best


# ---------------------------------------------------------------------------
# Notes
# ---------------------------------------------------------------------------

def write_note(slug: str, event_id: int, text: str, *, marker: str) -> bool:
    """ONE agent note (agent 'octo') on stored alert `event_id` per marker —
    found, never duplicated. True when the note exists afterwards. Raises
    sqlite3 / OS errors (the caller retries next cycle)."""
    from apps.octo.agent import notes as agent_notes

    db = paths.client_dir(slug) / "events.db"
    if not db.exists():
        raise FileNotFoundError(f"tenant {slug!r} has no event store")
    request_id = f"fleet-{hashlib.sha256(marker.encode()).hexdigest()[:24]}"
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
                    note_text=text[:2000], confidence=1.0, request_id=request_id,
                    query_kind=NOTE_KIND,
                )
    finally:
        conn.close()
    return True


def wan_alerts(slug: str, scope: str, since: datetime, limit: int = GROUP_SCAN_LIMIT) -> list[int]:
    """Ids of the site's own WAN alerts (`unifi.wan_down` / `wan_failover`)
    in ITS tenant from `since` on (the received_at index; read-only)."""
    db = paths.client_dir(slug) / "events.db"
    if not db.exists():
        return []
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=10.0)
    try:
        marks = ",".join("?" * len(WAN_ALERT_TYPES))
        rows = conn.execute(
            f"SELECT id FROM events WHERE received_at >= ? AND source = 'unifi' "
            f"AND event_type IN ({marks}) AND json_extract(payload, '$.scope') = ? "
            f"ORDER BY id LIMIT ?",
            (_iso(since), *WAN_ALERT_TYPES, scope, int(limit)),
        ).fetchall()
    finally:
        conn.close()
    return [int(r[0]) for r in rows]


def client_note(isp: str) -> str:
    """The note on a member site's own WAN alert, in ITS client's tenant."""
    provider = " ".join(str(isp or "").split())[:80] or "the internet provider"
    return (f"Linked to a provider-wide internet outage on {provider}, tracked as one "
            "incident. Nothing to do on this site unless it stays down after the provider "
            "recovers.")


# ---------------------------------------------------------------------------
# The correlator
# ---------------------------------------------------------------------------

Ingest = Callable[[str, dict[str, Any]], Optional[int]]


class IspOutageCorrelator:
    """One per UniFi poller (instance). Not thread-safe: the poller calls
    `evaluate` from its own loop; `snapshot` is safe from API threads."""

    def __init__(
        self,
        *,
        instance_id: int,
        ingest: Ingest,
        build_payload: Callable[[dict[str, Any]], dict[str, Any]],
        min_sites_n: Optional[int] = None,
        window_td: Optional[timedelta] = None,
        tenant: Callable[[], Optional[str]] = internal_tenant,
    ) -> None:
        self._instance_id = int(instance_id)
        self._ingest = ingest
        self._build_payload = build_payload
        self._min = min_sites_n if min_sites_n is not None else min_sites()
        self._window = window_td if window_td is not None else window()
        self._tenant = tenant
        self._state: Optional[dict[str, Any]] = None
        self._saved_text: Optional[str] = None
        self._snapshot: list[dict[str, Any]] = []
        self._suppressed: Optional[dict[str, Any]] = None

    # ----- state -----

    def _load(self) -> bool:
        if self._state is not None:
            return True
        try:
            conn = sqlite3.connect(f"file:{paths.registry_db_path()}?mode=ro", uri=True,
                                   timeout=5.0)
            try:
                row = conn.execute(
                    "SELECT value_json FROM adapter_poller_state WHERE instance_id = ? "
                    "AND key = ?", (self._instance_id, STATE_KEY)).fetchone()
            finally:
                conn.close()
        except sqlite3.Error as exc:
            logger.warning("[isp-outage] state not readable (%s); nothing decided this cycle",
                           type(exc).__name__)
            return False
        value: Any = None
        if row is not None:
            try:
                value = json.loads(row[0])
            except ValueError:
                value = None
        if not isinstance(value, dict) or value.get("v") != STATE_VERSION:
            value = {"v": STATE_VERSION, "seen_at": None, "sites": {}, "incidents": {},
                     "outbox": [], "suppressed": []}
        for key, empty in (("sites", {}), ("incidents", {}), ("outbox", []),
                           ("suppressed", [])):
            if not isinstance(value.get(key), type(empty)):
                value[key] = empty
        self._state = value
        self._saved_text = row[0] if row is not None else None
        self._refresh_snapshot()
        return True

    def _save(self) -> bool:
        from apps.octo.instances import poller_state

        assert self._state is not None
        text = poller_state.dumps(self._state)
        if text == self._saved_text:
            return True
        if poller_state.save(self._instance_id, STATE_KEY, self._state):
            self._saved_text = text
            return True
        return False

    # ----- the cycle -----

    def evaluate(self, sites: list[dict[str, Any]], now: datetime,
                 interval: timedelta) -> None:
        """One fresh fleet poll's MAPPED sites: each `{scope, slug, name,
        host_connected, wans[], stats{}}`. Never raises."""
        try:
            self._evaluate(sites, now, interval)
        except Exception:  # noqa: BLE001 — never stop the poller
            logger.exception("[isp-outage] evaluation failed; retried next fleet poll")

    def _evaluate(self, sites: list[dict[str, Any]], now: datetime,
                  interval: timedelta) -> None:
        if not self._load():
            return
        st = self._state
        assert st is not None
        prev_at = _dt(st.get("seen_at"))
        fresh_prior = prev_at is not None and \
            timedelta(0) <= now - prev_at <= interval * STALE_INTERVALS + STALE_SLACK
        prev_sites: dict[str, Any] = st.get("sites") or {}
        observed: dict[str, Any] = {}
        per_host: dict[str, int] = {}
        for site in sites:
            if isinstance(site.get("scope"), str):
                host = str(site.get("host_id") or site["scope"].split("/")[0])
                per_host[host] = per_host.get(host, 0) + 1
        for site in sites:
            scope, slug = site.get("scope"), site.get("slug")
            if not isinstance(scope, str) or not isinstance(slug, str):
                continue
            prior = prev_sites.get(scope) if isinstance(prev_sites.get(scope), dict) else None
            same = prior is not None and prior.get("slug") == slug
            last = prior if (same and fresh_prior) else None
            prev_keys = set(last.get("keys") or []) if last is not None else None
            prev_wan = ({w: set(k or []) for w, k in (last.get("wan_keys") or {}).items()}
                        if last is not None else None)
            troubles = site_troubles(site, prev_keys, prev_wan)
            prior_trouble = (prior.get("trouble") or {}) if same else {}
            host = str(site.get("host_id") or scope.split("/")[0])
            cur: dict[str, Any] = {}
            for asn, (isp, why) in sorted(troubles.items()):
                p = prior_trouble.get(str(asn))
                if isinstance(p, dict):
                    since = p.get("since")
                elif last is not None:
                    since = _iso(now)            # seen without it last poll: an OBSERVED onset
                else:
                    since = None                 # first seen already down: onset unknown
                entry: dict[str, Any] = {"since": since, "why": why, "isp": isp[:80],
                                         "unit": failure_unit(site, asn, why,
                                                              console_sites=per_host.get(host, 1))}
                # Issue-only trouble (new internet/WAN issue ENTRIES, no hard
                # failure) is PENDING on its first poll and counts only if new
                # entries appear again on the next one — a single latency blip
                # at three sites must not page as a HIGH "ISP outage" that
                # closes five minutes later. Its onset stays the first poll.
                # A console unreachable or a WAN port down counts at once.
                if why.endswith("issues") and not isinstance(p, dict):
                    entry["pending"] = True
                cur[str(asn)] = entry
            stats = site.get("stats") if isinstance(site.get("stats"), dict) else {}
            observed[scope] = {
                "slug": slug, "name": str(site.get("name") or scope)[:120],
                "keys": [k for k in (stats.get("internet_issue_keys") or [])
                         if isinstance(k, str)][-MAX_KEYS:],
                "wan_keys": {str(w): [k for k in (ks or []) if isinstance(k, str)][-MAX_KEYS:]
                             for w, ks in (stats.get("wan_issue_keys") or {}).items()},
                "trouble": cur,
            }
        st["sites"] = observed
        st["seen_at"] = _iso(now)
        self._decide(now, observed)
        if not self._save():
            # Nothing is written that the stored state does not know about.
            self._refresh_snapshot()
            return
        if self._deliver():
            self._save()
        self._refresh_snapshot()

    # ----- decisions -----

    def _decide(self, now: datetime, observed: dict[str, Any]) -> None:
        st = self._state
        assert st is not None
        incidents: dict[str, Any] = st["incidents"]
        by_asn: dict[str, list[tuple[str, dict[str, Any]]]] = {}
        for scope, s in observed.items():
            for asn, t in (s.get("trouble") or {}).items():
                if t.get("pending"):
                    continue            # issue-only, first poll: not yet a failure
                by_asn.setdefault(asn, []).append((scope, t))
        for asn, inc in list(incidents.items()):
            if inc.get("open"):
                self._update_open(inc, by_asn.get(asn, []), observed, now)
        recent = {(asn, scope) for asn, lst in by_asn.items() for scope, t in lst
                  if (_dt(t.get("since")) is not None
                      and now - _dt(t.get("since")) <= self._window)}  # type: ignore[operator]
        wave_asns = {a for a, _ in recent}
        wave_sites = {s for _, s in recent}
        platform = (len(wave_asns) >= PLATFORM_MIN_ASNS
                    and len(wave_sites) >= PLATFORM_SHARE * max(1, len(observed)))
        # A closed incident keeps collecting its sites' WAN alerts for a while:
        # a console that comes back reports its WAN_FAILED / RESTORED lines
        # AFTER the fleet poll that saw it back (the system log is read later
        # in the same cycle).
        for inc in incidents.values():
            closed = _dt(inc.get("closed_at"))
            if not inc.get("open") and closed is not None and now - closed <= RELAPSE_WINDOW:
                self._group_alerts(inc, now)
        # A suppressed wave STAYS suppressed: its (ASN, site, onset) troubles
        # are remembered while they last (a trouble that ended, or started
        # again with another onset, drops out) — once the wave is older than
        # the window it can never split into per-ASN incidents.
        alive = {(asn, scope, str(t.get("since"))) for asn, lst in by_asn.items()
                 for scope, t in lst if t.get("since")}
        held = {tuple(x) for x in (st.get("suppressed") or [])
                if isinstance(x, list) and len(x) == 3 and tuple(x) in alive}
        self._suppressed = None
        if platform:
            fresh_wave = {(asn, scope, str(t.get("since"))) for asn, lst in by_asn.items()
                          for scope, t in lst if (asn, scope) in recent}
            if fresh_wave - held:
                logger.warning(
                    "[isp-outage] %d of %d sites across %d ISPs went down within %s: a "
                    "fleet-wide wave, not one ISP — no ISP-outage incident opened",
                    len(wave_sites), len(observed), len(wave_asns), self._window)
            held |= fresh_wave
            self._suppressed = {"at": _iso(now), "sites": len(wave_sites),
                                "asns": len(wave_asns), "observed": len(observed)}
        st["suppressed"] = [list(x) for x in sorted(held)][:MAX_SUPPRESSED]
        for asn, lst in sorted(by_asn.items()):
            inc = incidents.get(asn)
            if inc is not None and inc.get("open"):
                continue
            group = self._group(asn, lst, held)
            if not group:
                continue
            if now - max(d for _, d in group) > self._window:
                continue                         # an old cluster never opens late
            closed = _dt((inc or {}).get("closed_at"))
            if inc is not None and closed is not None and now - closed < RELAPSE_WINDOW:
                self._reopen(inc, group, observed, now)
            else:
                self._open(asn, group, observed, now)
        self._prune(now)

    def _group(self, asn: str, troubled: list[tuple[str, dict[str, Any]]],
               held: set[tuple[Any, ...]]) -> list[tuple[str, datetime]]:
        """The sites of the largest cluster of FAILURE POINTS of this ASN
        whose onsets lie within the window (each unit at its earliest
        onset), when it holds at least `min_sites` units — else []. Onsets
        unknown or part of a suppressed wave never count."""
        units: dict[str, datetime] = {}
        sites: list[tuple[str, str, datetime]] = []
        for scope, t in troubled:
            onset = _dt(t.get("since"))
            if onset is None or (asn, scope, str(t.get("since"))) in held:
                continue
            unit = str(t.get("unit") or f"s:{_digest(scope)}")
            sites.append((scope, unit, onset))
            units[unit] = min(units.get(unit, onset), onset)
        chosen = cluster(list(units.items()), self._window)
        if len(chosen) < self._min:
            return []
        keep = {u for u, _ in chosen}
        return [(scope, onset) for scope, unit, onset in sites if unit in keep]

    def _member(self, scope: str, observed: dict[str, Any], asn: str) -> dict[str, Any]:
        s = observed.get(scope) or {}
        t = (s.get("trouble") or {}).get(asn) or {}
        return {"slug": s.get("slug"), "name": s.get("name") or scope,
                "since": t.get("since"), "why": t.get("why") or "down",
                "unit": t.get("unit"), "recovered_at": None}

    def _open(self, asn: str, group: list[tuple[str, datetime]], observed: dict[str, Any],
              now: datetime) -> None:
        st = self._state
        assert st is not None
        since = min(d for _, d in group)
        isp = ""
        for scope, _ in group:
            isp = isp or str(((observed.get(scope) or {}).get("trouble") or {})
                             .get(asn, {}).get("isp") or "")
        vid = f"isp:{self._instance_id}:{asn}:{_iso(since)}"
        slug = self._tenant()
        inc: dict[str, Any] = {
            "open": True, "vid": vid, "asn": int(asn), "isp": isp or f"AS{asn}",
            "since": _iso(since), "opened_at": _iso(now), "closed_at": None,
            "slug": slug, "event_id": None,
            "members": {scope: self._member(scope, observed, asn) for scope, _ in group},
            "grouped": [], "noted_sites": len(group), "reopened": 0,
        }
        st["incidents"][asn] = inc
        logger.warning(
            "[isp-outage] ISP outage: %s (AS%s) — %d sites since %s: ONE incident%s",
            inc["isp"], asn, len(group), inc["since"],
            f" in tenant {slug}" if slug else
            " — no ACTIVE tenant of kind 'internal' to raise it in (shown on the Fleet tab)")
        if slug is not None:
            self._queue({"op": "event", "vid": vid, "slug": slug,
                         "payload": self._build_payload(self._payload_view(inc))})
        self._group_alerts(inc, now)

    def _reopen(self, inc: dict[str, Any], group: list[tuple[str, datetime]],
                observed: dict[str, Any], now: datetime) -> None:
        asn = str(inc["asn"])
        inc["open"] = True
        inc["closed_at"] = None
        inc["reopened"] = int(inc.get("reopened") or 0) + 1
        for scope, _ in group:
            m = inc["members"].get(scope)
            if m is None:
                inc["members"][scope] = self._member(scope, observed, asn)
            else:
                m["recovered_at"] = None
        n = len(group)
        self._note_incident(inc, f"again:{_iso(now)}", (
            f"{n} sites on {inc['isp']} (AS{asn}) lost their connection again within "
            f"{int(self._window.total_seconds() // 60)} minutes ({_hhmm(_iso(now))}) — the same "
            "outage, so no new alert."))
        inc["noted_sites"] = max(int(inc.get("noted_sites") or 0), len(inc["members"]))
        self._group_alerts(inc, now)

    def _update_open(self, inc: dict[str, Any], troubled: list[tuple[str, dict[str, Any]]],
                     observed: dict[str, Any], now: datetime) -> None:
        asn = str(inc["asn"])
        members: dict[str, Any] = inc["members"]
        down = {scope for scope, _t in troubled}
        start = _dt(inc.get("since")) or now
        for scope, t in troubled:
            onset = _dt(t.get("since"))
            if scope not in members and onset is not None and onset >= start - self._window \
                    and len(members) < MAX_GROUPED:
                members[scope] = self._member(scope, observed, asn)
        for scope, m in members.items():
            if scope in down:
                m["recovered_at"] = None
            elif scope in observed and (observed[scope].get("slug") == m.get("slug")):
                m["recovered_at"] = m.get("recovered_at") or _iso(now)
        if len(members) > int(inc.get("noted_sites") or 0):
            inc["noted_sites"] = len(members)
            self._note_incident(inc, f"sites:{len(members)}", (
                f"Now {len(members)} sites on {inc['isp']} (AS{asn}) — "
                + ", ".join(self._site_label(m) for m in list(members.values())[-5:])
                + (" …" if len(members) > 5 else "") + " joined the same outage."))
        still = [s for s in members if s in down]
        # Failure points still down (one console with several sites is one).
        units = {scope: str(t.get("unit") or f"s:{_digest(scope)}") for scope, t in troubled}
        still_units = {units[s] for s in still}
        back = [s for s, m in members.items() if m.get("recovered_at")]
        # A member no longer observed (unmapped, its tenant offboarded, gone
        # from UniFi's list) is neither down nor back: the half rule counts
        # the members still seen, so it can never hold the incident open.
        seen = [s for s in members if s in observed]
        self._group_alerts(inc, now)
        if len(still_units) < self._min and len(back) * 2 >= len(seen):
            inc["open"] = False
            inc["closed_at"] = _iso(now)
            names = ", ".join(self._site_label(members[s]) for s in still[:5])
            self._note_incident(inc, f"closed:{inc['closed_at']}", (
                f"{len(back)} of the {len(members)} sites on {inc['isp']} (AS{asn}) are back "
                f"online ({len(still)} still down{': ' + names if names else ''}) — the ISP "
                "outage is over. A site still down now is its own problem: check its modem / "
                "circuit."))
            logger.info("[isp-outage] the %s (AS%s) outage is over", inc["isp"], asn)

    @staticmethod
    def _site_label(m: dict[str, Any]) -> str:
        return f"{m.get('name')} ({m.get('slug')})"

    def _group_alerts(self, inc: dict[str, Any], now: datetime) -> None:
        """Link each member site's own WAN alerts to the incident (a note on
        the alert in ITS tenant; one note on the incident per batch)."""
        grouped: list[str] = inc.setdefault("grouped", [])
        if len(grouped) >= MAX_GROUPED:
            return
        start = (_dt(inc.get("since")) or now) - self._window
        fresh: list[tuple[str, str, int]] = []
        for scope, m in inc["members"].items():
            slug = m.get("slug")
            if not isinstance(slug, str):
                continue
            try:
                ids = wan_alerts(slug, scope, start)
            except (sqlite3.Error, OSError) as exc:
                logger.warning("[isp-outage] WAN alerts of one site not read (%s)",
                               type(exc).__name__)
                continue
            for eid in ids:
                tag = f"{slug}#{eid}"
                if tag in grouped or len(grouped) + len(fresh) >= MAX_GROUPED:
                    continue
                fresh.append((slug, str(m.get("name") or scope), eid))
        if not fresh:
            return
        for slug, _name, eid in fresh:
            grouped.append(f"{slug}#{eid}")
            # The note sits in the CLIENT's tenant (its users read it): its
            # own provider only — no count, no ASN, no time, no other site.
            self._queue({"op": "note", "slug": slug, "event_id": eid, "marker":
                         f"{inc['vid']}:grouped:{slug}:{eid}", "text": client_note(inc['isp'])})
        listing = "; ".join(f"{name} ({slug}) alert #{eid}" for slug, name, eid in fresh[:20])
        digest = hashlib.sha256("|".join(f"{s}#{e}" for s, _n, e in fresh).encode()) \
            .hexdigest()[:16]
        self._note_incident(inc, f"grouped:{digest}", (
            f"Grouped under this outage ({len(fresh)} site WAN alert"
            f"{'s' if len(fresh) != 1 else ''}): {listing}"
            + (" …" if len(fresh) > 20 else "") + "."))

    def _note_incident(self, inc: dict[str, Any], tag: str, text: str) -> None:
        if not inc.get("slug"):
            return
        self._queue({"op": "note", "slug": inc["slug"], "event_id": inc.get("event_id"),
                     "event_vid": inc["vid"], "marker": f"{inc['vid']}:{tag}", "text": text})

    def _queue(self, item: dict[str, Any]) -> None:
        st = self._state
        assert st is not None
        box: list[dict[str, Any]] = st["outbox"]
        if len(box) >= MAX_OUTBOX:
            logger.warning("[isp-outage] outbox full; an item was dropped")
            return
        box.append(item)

    def _prune(self, now: datetime) -> None:
        st = self._state
        assert st is not None
        incidents: dict[str, Any] = st["incidents"]
        closed = sorted(((a, i) for a, i in incidents.items() if not i.get("open")),
                        key=lambda x: str(x[1].get("closed_at") or ""))
        for n, (asn, inc) in enumerate(closed):
            when = _dt(inc.get("closed_at"))
            old = when is None or now - when > RELAPSE_WINDOW * 4
            pending = any(i.get("event_vid") == inc.get("vid") or i.get("vid") == inc.get("vid")
                          for i in st["outbox"])
            if (old or n < len(closed) - MAX_CLOSED_KEPT) and not pending:
                incidents.pop(asn, None)

    # ----- delivery -----

    def _deliver(self) -> bool:
        """Write the queued signal / notes in order. An item a local fault
        cannot write stays (next cycle). True when anything changed."""
        st = self._state
        assert st is not None
        box: list[dict[str, Any]] = st["outbox"]
        changed = False
        while box:
            item = box[0]
            try:
                done = self._deliver_item(item)
            except FileNotFoundError:
                logger.warning("[isp-outage] tenant %s has no event store; item dropped",
                               item.get("slug"))
                done = True
            except (sqlite3.Error, OSError) as exc:
                logger.warning("[isp-outage] a queued %s was not written (%s); retried next "
                               "cycle", item.get("op"), type(exc).__name__)
                break
            if not done:
                break
            box.pop(0)
            changed = True
        return changed

    def _deliver_item(self, item: dict[str, Any]) -> bool:
        slug = item.get("slug")
        if not isinstance(slug, str):
            return True
        if item.get("op") == "event":
            payload = item.get("payload")
            if not isinstance(payload, dict):
                return True
            event_id = self._ingest(slug, payload)
            if event_id is None:
                return False
            for inc in (self._state or {}).get("incidents", {}).values():
                if inc.get("vid") == item.get("vid"):
                    inc["event_id"] = event_id
            for later in (self._state or {}).get("outbox", [])[1:]:
                if later.get("event_vid") == item.get("vid"):
                    later["event_id"] = event_id
            return True
        event_id = item.get("event_id")
        if not isinstance(event_id, int):
            vid = item.get("event_vid")
            known = [inc.get("event_id") for inc in (self._state or {}).get("incidents", {})
                     .values() if inc.get("vid") == vid]
            event_id = known[0] if known and isinstance(known[0], int) else None
        if not isinstance(event_id, int):
            return True                          # nothing to note on (never written)
        write_note(slug, event_id, str(item.get("text") or ""),
                   marker=str(item.get("marker") or ""))
        return True

    # ----- read side -----

    def _payload_view(self, inc: dict[str, Any]) -> dict[str, Any]:
        members = list(inc["members"].items())
        return {
            "vid": inc["vid"], "asn": inc["asn"], "isp": inc["isp"], "since": inc["since"],
            "opened_at": inc["opened_at"], "min_sites": self._min,
            "window_min": int(self._window.total_seconds() // 60),
            "sites": len(members),
            "affected": [{"scope": scope, "site_name": m.get("name"), "tenant": m.get("slug"),
                          "since": m.get("since"), "why": m.get("why")}
                         for scope, m in members[:MAX_LISTED]],
        }

    def _refresh_snapshot(self) -> None:
        st = self._state or {}
        out = []
        for inc in (st.get("incidents") or {}).values():
            members = inc.get("members") or {}
            down = [s for s, m in members.items() if not m.get("recovered_at")]
            out.append({
                "vid": inc.get("vid"), "open": bool(inc.get("open")), "asn": inc.get("asn"),
                "isp": inc.get("isp"), "since": inc.get("since"),
                "opened_at": inc.get("opened_at"), "closed_at": inc.get("closed_at"),
                "tenant": inc.get("slug"), "event_id": inc.get("event_id"),
                "sites": len(members), "sites_down": len(down),
                "members": [{"scope": s, "tenant": m.get("slug"), "name": m.get("name"),
                             "since": m.get("since"), "why": m.get("why"),
                             "recovered_at": m.get("recovered_at")}
                            for s, m in list(members.items())[:MAX_LISTED]],
            })
        out.sort(key=lambda i: (not i["open"], str(i.get("opened_at") or "")), reverse=False)
        if self._suppressed:
            out.append({"vid": None, "open": False, "suppressed": dict(self._suppressed)})
        self._snapshot = out

    def snapshot(self) -> list[dict[str, Any]]:
        return json.loads(json.dumps(self._snapshot))


def mapped_site_rows(fleet: Mapping[str, Any], mapped: Mapping[str, str]) -> list[dict[str, Any]]:
    """The correlator's input from a fleet view (scope → SiteInfo) and the
    mapping (scope → tenant slug): mapped sites only."""
    out: list[dict[str, Any]] = []
    for scope, slug in sorted(mapped.items()):
        info = fleet.get(scope)
        if info is None:
            continue
        out.append({"scope": scope, "slug": slug, "name": getattr(info, "name", scope),
                    "host_id": getattr(info, "host_id", None) or scope.split("/")[0],
                    "host_connected": getattr(info, "host_connected", None),
                    "wans": [dict(w) for w in getattr(info, "wans", [])],
                    "stats": dict(getattr(info, "stats", {}) or {})})
    return out


__all__ = [
    "EVENT_TYPE", "IspOutageCorrelator", "KIND", "STATE_KEY", "client_note", "cluster",
    "failure_unit", "internal_tenant", "mapped_site_rows", "min_sites", "primary_isp",
    "site_troubles", "wan_alerts", "window", "write_note",
]
