"""The resolver — one event → "where and who at that moment, how sure, why"
(design sections 3 and 4, with the adversarial fixes).

`Resolver.for_tenant(slug)` is built for ONE tenant and reads only that
tenant's files (its entities.db; its events.db for the LAN witness). It never
takes a second slug and refuses any path outside `clients/<slug>/`.

WHERE (site rules)
  S1 policy     the event's vendor scope (NextDNS profile, UniFi site) has
                auto / confirmed refs — CONFIRMED ONLY when any exist (G8) — one
                site: that site (the ref's score: confirmed 95, auto 90); several
                (a shared profile): a set S2 must narrow
  S2 located    the public IP is a site egress of THIS tenant at T: direct
                (UniFi) 85, operator-asserted 95, CGNAT / unknown NAT 60,
                double NAT 80 once stable 7 days and not shared, else 60;
                -20 inside a margin. Several sites: a set
  S-AGREE       S1 and S2 name the same site: 99, basis `both` — only when the
                egress row may corroborate (direct / stable double NAT /
                operator, never `shared_external`, CGNAT or unknown — G4);
                otherwise basis `policy`, flagged `location_unverified`
  S-NARROW      S1 gives a set, S2 picks one inside it: max(S2, 90); and the
                mirror: S2 gives a set (one egress shared by several sites of
                the tenant), S1 names exactly one site inside it: that site,
                max(S1, 90) (basis `both` when the egress may corroborate,
                else `policy`), flagged `shared_in_tenant`
  not_located   S1 holds but the IP is no egress of this tenant at T: the policy
                site, basis `not_located` — NO candidate set; the reason says
                `egress_unstable` when the site's egress is CGNAT / unknown /
                shared (G4: the old "off site" asserted a place)
  S-CONFLICT    S1 and S2 name different single sites, both >= 70: tier
                `conflict`, a Conflicts card + notice, no pick
  S3 subnet     a LAN IP inside exactly one site's subnet (no scope): 60
WHO (device rules)
  D5 NextDNS    the line carries the NextDNS app's device: at most 80 (medium)
                — a client-asserted name never reaches strong (G3)
  D4 witness    a buoy's Pi-hole saw the same domain within ±5 s (sensor time)
                from exactly one LAN client: 88 for an upstream block (status
                6/7/8/18), else 80 → that LAN IP goes to D3
  D3 lease      a LAN IP at the site at T in exactly one lease: 85 with an exact
                start, 80 sampled, -20 inside a margin; two rows, a conflict,
                a MAC anomaly, a reconnect hole or a ghost join (a join of
                that address no lease covers, in [T - one poll, T + 20 s]) →
                candidates, never a pick
  D7 connected  every lease open at the site at T (and joins logged up to 20 s
                AFTER T — the join is logged after DHCP, the lookup can come
                first), filtered (networks whose DHCP DNS provably bypasses
                NextDNS; NextDNS-app devices that reported directly in T's OWN
                hour — matched by name, never by a LAN address seen anywhere —
                for a gateway-sourced line; until T's hour is read the answer
                waits for it and excludes nothing), ranked: F1 LAN-witness
                hit within 60 s,
                F2 present at the bucket's first and last hit (not for clients
                connected over 24 h), F3 earlier rule-resolved hits on the same
                root (never an operator's one-off — G8), FJ joined within ±20 s.
                Score min(50, 100 / n) + 10 per feature, capped at 69: a set
                never reaches medium
  N-DEV         names only ever "also consistent" (never a score)
SCORING  a chain is as strong as its weakest hop; rules stop at 99; only an
         operator's confirmation is 100 ("exact"). Tiers: exact 100, strong
         90-99, medium 70-89, weak 40-69, candidate below or a set.
TIME     the event's own clock. Every watermark an answer needs (the site's
         fleet report for S2; its client list AND system log for D3 / D7) must
         be past T + slack (and, for a gateway-sourced NextDNS line, T's
         device-presence hour read), else the answer is `provisional` and
         redone; after 30 minutes — or, while it waits for T's presence hour,
         once that hour is due to be read (~65 min after it starts) + slack —
         it is finalised with `lookup_stale` (and `data_gap` when T is in a
         UniFi hole). A watermark dependency
         re-queues it for 7 days (G7) — once every wait has reached what it
         NEEDED (stored with the answer); a re-run that would store the same
         answer writes nothing.

The answer is stored (`resolution`) with its chain and the rows it relied on
(`resolution_dep`). It NEVER contains a device name (G11): candidates hold
lease row ids and tokens; names are read from the leases while they exist.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

from apps.octo import paths
from apps.octo.entity import ids
from apps.octo.entity import intervals as iv
from apps.octo.entity import normalize as nz
from apps.octo.entity import sites as st
from apps.octo.entity import tokens as tk
from apps.octo.entity.db import TenantDB

# Versions move when a rule's logic changes (replays diff on RESOLVER_VERSION):
# S-NARROW 2 (its mirror), D3 2 (time-bounded conflicts, ghosts of the subject
# address before T), D7 2 (T's own presence hour, by name; positive-evidence
# DNS bypass), M1 2 (late log lines, uplink flapping, time-bounded findings),
# S2 2 (IPv6: the WAN /128 or a delegated prefix; an IPv6 address the site's
# known IPv6 space cannot place is location UNKNOWN).
RULES: dict[str, int] = {
    "S1": 1, "S2": 2, "S-AGREE": 1, "S-NARROW": 2, "S-NOTLOC": 1, "S-CONFLICT": 1, "S3": 1,
    "D3": 2, "D4": 1, "D5": 1, "D7": 2, "N-DEV": 1, "M1": 2,
}
RESOLVER_VERSION = "rv_" + hashlib.sha256(
    json.dumps(sorted(RULES.items())).encode()).hexdigest()[:12]

FINALISE_AFTER = timedelta(minutes=30)
# NextDNS device presence for hour H is read once H + 1 h + the NextDNS
# poller's HOURLY_DELAY_SEC (5 min) has passed (a test pins the two together):
# an answer waiting for T's presence hour stays provisional — no stale pill —
# until then + slack, never finalised `lookup_stale` at T + 30 min while
# every feed is healthy.
PRESENCE_READ_AFTER = timedelta(minutes=65)
PRESENCE_SLACK = timedelta(minutes=20)
BACKFILL_WINDOW = timedelta(days=7)
LEASE_LOOKBACK_S = 26 * 3600
# No interval margin is wider than this (a sampled edge is half a poll gap,
# a reconnect hole at most the 3-poll gap rule): rows that ended earlier
# cannot hold at T.
MAX_SLACK_S = 2 * 3600
JOIN_AHEAD_S = 20
WITNESS_S = 5
F1_WINDOW_S = 60
ALWAYS_ON_S = 24 * 3600
VENDOR_SKEW_S = {"nextdns": 2, "unifi": 5}
MAX_CANDIDATES = 25
STABLE_DOUBLE_NAT = timedelta(days=7)
UPSTREAM_BLOCK_STATUSES = frozenset({6, 7, 8, 18})
GATEWAY_CLIENTS = frozenset({"", "dnscrypt", "dns", "dot", "doh", "unifi"})
# A backfill that would store exactly these again writes nothing.
NOOP_FIELDS = ("site_id", "site_basis", "site_score", "site_tier", "device_ref", "tier", "score",
               "n_candidates", "chain", "candidates", "flags", "status", "lookup_watermark")
TIER_RANK = {"none": 0, "candidate": 1, "suggest": 1, "weak": 2, "medium": 3, "strong": 4,
             "exact": 5, "conflict": 0}


def tier_of(score: int) -> str:
    if score >= 100:
        return "exact"
    if score >= 90:
        return "strong"
    if score >= 70:
        return "medium"
    if score >= 40:
        return "weak"
    return "candidate"


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# The subject of an event (one extractor per source; the payload is never
# changed)
# ---------------------------------------------------------------------------

@dataclass
class Subject:
    event_id: Optional[int]
    source: str                   # 'nextdns' | 'unifi'
    kind: str                     # 'nextdns_block' | 'unifi_ips'
    at: str
    time_quality: str
    vendor: str
    scope_id: str
    ip: Optional[str] = None
    mac: Optional[str] = None
    device_id: Optional[str] = None
    device_name: Optional[str] = None
    client: str = ""
    domain: Optional[str] = None
    root: Optional[str] = None
    bucket: Optional[dict[str, Any]] = None

    @property
    def subject_type(self) -> str:
        if self.ip and nz.is_public(self.ip):
            return "public_ip"
        if self.ip:
            return "lan_ip"
        return "nextdns_device" if self.device_id or self.device_name else "none"

    @property
    def gateway_sourced(self) -> bool:
        return self.source == "nextdns" and not (self.device_id or self.device_name) \
            and self.client.lower() in GATEWAY_CLIENTS


def _m(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def subject_of(event_id: Optional[int], source: str, event_type: str,
               payload: dict[str, Any]) -> Optional[Subject]:
    if source == "nextdns" and event_type == "nextdns.security_block":
        log = _m(payload.get("log"))
        at = nz.ts(log.get("timestamp"))
        pid = payload.get("profile_id")
        if not at or not isinstance(pid, str):
            return None
        device = _m(log.get("device"))
        domain = str(log.get("domain") or "").lower().rstrip(".") or None
        root = str(log.get("root") or "").lower().rstrip(".") or domain
        return Subject(
            event_id=event_id, source="nextdns", kind="nextdns_block", at=at,
            time_quality="vendor", vendor="nextdns", scope_id=pid,
            ip=nz.ip(log.get("clientIp")),
            device_id=str(device.get("id"))[:64] if device.get("id") else None,
            device_name=str(device.get("name"))[:120] if device.get("name") else None,
            client=str(log.get("client") or "")[:32], domain=domain, root=root)
    if source == "unifi" and event_type == "unifi.ips_threat":
        ev = _m(payload.get("event"))
        ips = _m(payload.get("ips"))
        at = nz.ts(ev.get("timestamp"))
        scope = payload.get("scope")
        if not at or not isinstance(scope, str):
            return None
        client = _m(ips.get("client"))
        return Subject(
            event_id=event_id, source="unifi", kind="unifi_ips", at=at, time_quality="vendor",
            vendor="unifi", scope_id=scope, ip=nz.ip(ips.get("local_ip") or client.get("ip")),
            mac=nz.mac(client.get("mac")))
    return None


# ---------------------------------------------------------------------------
# The answer
# ---------------------------------------------------------------------------

@dataclass
class Answer:
    site_id: Optional[str] = None
    site_basis: str = "none"
    site_score: int = 0
    site_tier: str = "none"
    sites: list[str] = field(default_factory=list)
    device_ref: Optional[str] = None
    tier: str = "none"
    score: int = 0
    n_candidates: int = 0
    candidates: list[dict[str, Any]] = field(default_factory=list)
    chain: list[dict[str, Any]] = field(default_factory=list)
    flags: set[str] = field(default_factory=set)
    deps: set[tuple[str, str]] = field(default_factory=set)
    waits: list[dict[str, Any]] = field(default_factory=list)
    gap: bool = False
    conflict: Optional[dict[str, Any]] = None

    def hop(self, rule: str, *, inp: dict[str, Any], out: dict[str, Any], score: Optional[int],
            lookup: Optional[list[dict[str, Any]]] = None, adjust: Optional[list[str]] = None,
            note: Optional[str] = None) -> None:
        h: dict[str, Any] = {"hop": len(self.chain) + 1, "rule": rule,
                             "rule_version": RULES.get(rule, 1), "in": inp, "out": out,
                             "lookup": lookup or [], "adjust": adjust or [], "score": score}
        if note:
            h["note"] = note
        self.chain.append(h)


def _row_match(row: sqlite3.Row, t: str, watermark: Optional[str]) -> Optional[str]:
    """'in_core' | 'in_slack' | None for one interval row at T. Canonical
    timestamps compare as strings; dates are parsed only near an edge."""
    start = row["valid_from"]
    end = row["valid_to"] or watermark
    if end is None:
        return None
    if start <= t <= end:
        return "in_core"
    from_slack = int(row["from_slack_s"] or 0)
    to_slack = int(row["to_slack_s"] or 0)
    if t < start:
        return "in_slack" if from_slack and nz.shift(start, -from_slack) <= t else None
    return "in_slack" if to_slack and t <= nz.shift(end, to_slack) else None


class Resolver:
    """Built for ONE tenant (`for_tenant`)."""

    def __init__(self, slug: str, tdb: TenantDB, now: Callable[[], datetime]) -> None:
        self.slug = slug
        self.tdb = tdb
        self._now = now

    @classmethod
    def for_tenant(cls, slug: str, *, now: Callable[[], datetime] = _now_utc) -> "Resolver":
        return cls(slug, TenantDB.for_tenant(slug), now)

    def guard(self, path: Any) -> None:
        """Refuse any entities path that is not this tenant's (AT7)."""
        from pathlib import Path

        TenantDB.guard(self.slug, Path(path))

    # ----- tokens (this tenant's key) -----

    def tok(self, kind: str, value: Optional[str], scope: str = "") -> Optional[str]:
        return tk.token(self.slug, kind, value, scope) if value else None

    # ----- public entry points -----

    def resolve_event(self, event_id: int, *, mode: str = "sweep",
                      created_by: str = "rule:sweep") -> Optional[dict[str, Any]]:
        """Resolve one stored event of this tenant (its events.db) and store
        the answer. None when the event is not a kind slice 1 resolves."""
        row = self._event(event_id)
        if row is None:
            return None
        try:
            payload = json.loads(row["payload"])
        except (TypeError, ValueError):
            return None
        subject = subject_of(int(row["id"]), row["source"], row["event_type"], _m(payload))
        if subject is None:
            return None
        if subject.source == "nextdns":
            subject.bucket = self._nextdns_bucket(int(row["id"]))
        elif subject.source == "unifi":
            subject.bucket = self._unifi_bucket(int(row["id"]))
        with self.tdb.write() as conn:
            answer = self.compute(conn, subject)
            return self._store(conn, subject, answer, mode=mode, created_by=created_by)

    def compute(self, conn: sqlite3.Connection, subject: Subject) -> Answer:
        """The answer for `subject` — deterministic: the same lookups in any
        insertion order give the same chain and candidates."""
        self._wm_cache: dict[tuple[str, str], Optional[str]] = {}
        self._subnet_cache: dict[str, list[tuple[Any, sqlite3.Row]]] = {}
        a = Answer()
        self._where(conn, subject, a)
        if a.site_basis != "none" and a.tier != "conflict":
            self._who(conn, subject, a)
        return a

    # ----- events.db (this tenant's, read only) -----

    def _events_conn(self) -> Optional[sqlite3.Connection]:
        path = paths.client_dir(self.slug) / "events.db"
        if not path.exists():
            return None
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _event(self, event_id: int) -> Optional[sqlite3.Row]:
        conn = self._events_conn()
        if conn is None:
            return None
        try:
            return conn.execute("SELECT id, source, event_type, received_at, payload FROM events "
                                "WHERE id = ?", (int(event_id),)).fetchone()
        except sqlite3.Error:
            return None
        finally:
            conn.close()

    def _telemetry_conn(self) -> Optional[sqlite3.Connection]:
        path = paths.client_dir(self.slug) / "telemetry.db"
        if not path.exists():
            return None
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _nextdns_bucket(self, event_id: int) -> Optional[dict[str, Any]]:
        conn = self._telemetry_conn()
        if conn is None:
            return None
        try:
            r = conn.execute("SELECT hour, span, hits, first_seen, last_seen FROM "
                             "nextdns_signal_buckets WHERE event_id = ?", (event_id,)).fetchone()
        except sqlite3.Error:
            return None
        finally:
            conn.close()
        return dict(r) if r else None

    def _unifi_bucket(self, event_id: int) -> Optional[dict[str, Any]]:
        conn = self._telemetry_conn()
        if conn is None:
            return None
        try:
            r = conn.execute("SELECT hour, hits, first_seen, last_seen FROM unifi_signal_buckets "
                             "WHERE event_id = ?", (event_id,)).fetchone()
        except sqlite3.Error:
            return None
        finally:
            conn.close()
        return dict(r) if r else None

    # ----- WHERE -----

    def _s1(self, conn: sqlite3.Connection, s: Subject, a: Answer) -> list[st.Ref]:
        rows = st.refs(conn, s.vendor, s.scope_id, at=s.at, states=("auto", "confirmed"))
        confirmed = [r for r in rows if r.state == "confirmed"]
        use = confirmed or rows              # G8: confirmed only, when any exist
        for r in use:
            a.deps.add(("ref", str(r.id)))
        return sorted(use, key=lambda r: (r.site_id, r.id))

    def _egress_rows(self, conn: sqlite3.Connection, ip: str, t: str) -> list[sqlite3.Row]:
        if ":" not in ip:
            return conn.execute(
                "SELECT e.* FROM lk_site_egress e JOIN site s ON s.site_id = e.site_id "
                "WHERE e.addr = ? AND s.status = 'active' AND e.valid_from <= ? "
                "ORDER BY e.site_id, e.id", (ip, nz.shift(t, 3600))).fetchall()
        # IPv6: the gateway's WAN address (/128) or a delegated LAN prefix
        # holding the address (a device asking NextDNS directly over IPv6).
        return [r for r in conn.execute(
            "SELECT e.* FROM lk_site_egress e JOIN site s ON s.site_id = e.site_id "
            "WHERE e.addr LIKE '%:%' AND s.status = 'active' AND e.valid_from <= ? "
            "ORDER BY e.site_id, e.id", (nz.shift(t, 3600),)).fetchall()
            if iv.egress_contains(r, ip)]

    def _s2(self, conn: sqlite3.Connection, s: Subject,
            a: Answer) -> tuple[dict[str, tuple[int, bool, list[dict[str, Any]]]], bool]:
        """{site: (score, may_corroborate, lookups)}, any_row_for_ip."""
        out: dict[str, tuple[int, bool, list[dict[str, Any]]]] = {}
        rows = self._egress_rows(conn, s.ip, s.at) if s.ip else []
        for r in rows:
            wm_row = iv.watermark(conn, "unifi.sites", r["vendor_scope_id"]) \
                if r["source"] == "unifi.sites" else None
            wm = wm_row["last_ok_at"] if wm_row is not None else None
            if r["source"] == "operator":
                wm = r["valid_to"] or nz.iso(self._now())
            match = _row_match(r, s.at, wm)
            if match is None:
                if r["valid_to"] is None and r["source"] == "unifi.sites" and \
                        (wm is None or wm < s.at) and r["valid_from"] <= s.at:
                    # T is after the site's last fresh report: not known YET.
                    a.waits.append({"source": "unifi.sites", "scope": r["vendor_scope_id"],
                                    "need": s.at, "have": wm})
                continue
            flags = set(json.loads(r["flags"] or "[]"))
            nat = r["nat_kind"]
            if r["source"] == "operator":
                score, corroborates = 95, True
            elif r["source"] == "datto.extIp":
                score, corroborates = 50, False
            elif nat == "direct":
                score, corroborates = 85, True
            elif nat == "double_nat":
                stable = (nz.seconds_between(r["valid_from"], s.at)
                          >= STABLE_DOUBLE_NAT.total_seconds())
                score, corroborates = (80, True) if stable and "shared_external" not in flags \
                    else (60, False)
            else:
                score, corroborates = 60, False     # cgnat / unknown (G4, AT-R5)
            if "shared_external" in flags:
                corroborates = False
                a.flags.add("location_unverified")
            adjust = []
            if match == "in_slack":
                score -= 20
                adjust.append("in_slack:-20")
            look = {"table": "lk_site_egress", "id": int(r["id"]), "source": r["source"],
                    "valid_from": r["valid_from"], "valid_to": r["valid_to"], "watermark": wm,
                    "match": match, "nat_kind": nat, "flags": sorted(flags), "adjust": adjust}
            if int(r["prefix_len"]) not in (32, 128):
                look["prefix_len"] = int(r["prefix_len"])     # an IPv6 delegated prefix
            a.deps.add(("egress", str(r["id"])))
            prior = out.get(r["site_id"])
            if prior is None or score > prior[0]:
                out[r["site_id"]] = (score, corroborates, [look])
            # wait for the site's fleet watermark to pass T (provisional)
            if r["source"] == "unifi.sites" and (wm is None or wm < s.at):
                a.waits.append({"source": "unifi.sites", "scope": r["vendor_scope_id"],
                                "need": s.at, "have": wm})
        return out, bool(rows)

    def _where(self, conn: sqlite3.Connection, s: Subject, a: Answer) -> None:
        ip_tok = self.tok("public_ip" if s.ip and nz.is_public(s.ip) else "lan_ip", s.ip)
        s1 = self._s1(conn, s, a)
        s1_sites = sorted({r.site_id for r in s1})
        if s1:
            best = {sid: max(r.score for r in s1 if r.site_id == sid) for sid in s1_sites}
            a.hop("S1", inp={"type": "vendor_scope", "vendor": s.vendor, "at": s.at,
                             "time_quality": s.time_quality},
                  out={"sites": s1_sites, "basis": "policy"},
                  score=max(best.values()),
                  lookup=[{"table": "site_vendor_ref", "id": r.id, "state": r.state,
                           "rule": r.rule_id, "site_id": r.site_id, "score": r.score}
                          for r in s1])
        if s.source == "unifi":
            # The IPS event's site IS its UniFi scope's site (S1); a LAN IP.
            if len(s1_sites) == 1:
                a.site_id, a.site_basis = s1_sites[0], "policy"
                a.site_score = max(r.score for r in s1)
            return self._finish_site(a)
        if not s.ip:
            if len(s1_sites) == 1:
                a.site_id, a.site_basis, a.site_score = s1_sites[0], "policy", \
                    max(r.score for r in s1)
            elif s1_sites:
                a.sites = s1_sites
                a.site_basis = "policy"
                a.site_score = max(r.score for r in s1)
            return self._finish_site(a)
        if not nz.is_public(s.ip):
            # A LAN IP on a NextDNS line (a buoy forwarding with its client's
            # address, or a profile used inside a VPN): S3 when no single S1.
            if len(s1_sites) == 1:
                a.site_id, a.site_basis, a.site_score = s1_sites[0], "policy", \
                    max(r.score for r in s1)
            else:
                hits = [r for r in st.active_sites(conn)
                        if iv.subnet_of(conn, r["site_id"], s.ip, s.at) is not None]
                if len(hits) == 1:
                    a.site_id, a.site_basis, a.site_score = hits[0]["site_id"], "located", 60
                    a.hop("S3", inp={"type": "lan_ip", "tok": ip_tok, "at": s.at},
                          out={"site_id": a.site_id, "basis": "located"}, score=60)
            return self._finish_site(a)
        s2, any_rows = self._s2(conn, s, a)
        s2_sites = sorted(s2)
        if s2:
            if len(s2_sites) > 1:
                a.flags.add("shared_in_tenant")
            a.hop("S2", inp={"type": "public_ip", "tok": ip_tok, "at": s.at,
                             "time_quality": s.time_quality},
                  out={"sites": s2_sites, "basis": "located"},
                  score=max(v[0] for v in s2.values()),
                  lookup=[look for sid in s2_sites for look in s2[sid][2]])
        if len(s1_sites) == 1 and len(s2_sites) == 1:
            p_site, l_site = s1_sites[0], s2_sites[0]
            p_score = max(r.score for r in s1)
            l_score, corroborates, _ = s2[l_site]
            if p_site == l_site:
                if corroborates and l_score >= 60:
                    a.site_id, a.site_basis, a.site_score = p_site, "both", 99
                    a.hop("S-AGREE", inp={"policy": p_score, "located": l_score},
                          out={"site_id": p_site, "basis": "both"}, score=99)
                else:
                    a.site_id, a.site_basis, a.site_score = p_site, "policy", p_score
                    a.flags.add("location_unverified")
                    a.hop("S-AGREE", inp={"policy": p_score, "located": l_score},
                          out={"site_id": p_site, "basis": "policy"}, score=p_score,
                          note="the address is CGNAT, unknown or shared with another network: "
                               "it does not corroborate the profile's site")
            elif p_score >= 70 and l_score >= 70:
                a.tier, a.site_basis = "conflict", "none"
                a.sites = [p_site, l_site]
                a.conflict = {"policy_site": p_site, "located_site": l_site}
                a.hop("S-CONFLICT", inp={"policy": p_site, "located": l_site},
                      out={"tier": "conflict"}, score=None)
            else:
                pick = (p_site, p_score, "policy") if p_score >= l_score else \
                    (l_site, l_score, "located")
                a.site_id, a.site_score, a.site_basis = pick
            return self._finish_site(a)
        if len(s1_sites) == 1 and len(s2_sites) > 1 and s1_sites[0] in s2:
            # The mirror of S-NARROW: one egress shared by several sites of
            # this tenant (shared_in_tenant), a policy ref naming ONE of them
            # (design 3.8: "a confirmed profile-to-site ref narrows it").
            p_site = s1_sites[0]
            p_score = max(r.score for r in s1)
            l_score, corroborates, _ = s2[p_site]
            score = max(p_score, 90)
            if corroborates and l_score >= 60:
                a.site_id, a.site_basis, a.site_score = p_site, "both", score
            else:
                a.site_id, a.site_basis, a.site_score = p_site, "policy", p_score
                a.flags.add("location_unverified")
            a.hop("S-NARROW", inp={"sites": s2_sites, "policy": p_site},
                  out={"site_id": p_site, "basis": a.site_basis}, score=a.site_score,
                  note="the address is the internet connection of several of this client's "
                       "sites; the profile's own site narrows it")
            return self._finish_site(a)
        if len(s1_sites) > 1 and s2_sites:
            inside = [x for x in s2_sites if x in s1_sites]
            if len(inside) == 1:
                score = max(s2[inside[0]][0], 90)
                a.site_id, a.site_basis, a.site_score = inside[0], "both", score
                a.hop("S-NARROW", inp={"sites": s1_sites}, out={"site_id": inside[0]},
                      score=score)
                return self._finish_site(a)
        if s1_sites and not s2_sites:
            known = self._egress_state(conn, s1_sites, s.at, a, ipv6=":" in s.ip)
            if known == "unknown_v6":
                # An IPv6 address, and the site's IPv6 address space at T is
                # not known (UniFi reported its IPv4 address only): it can be
                # neither placed nor ruled out — never "not this client's
                # connection".
                if len(s1_sites) == 1:
                    a.site_id, a.site_basis = s1_sites[0], "policy"
                else:
                    a.sites, a.site_basis = s1_sites, "policy"
                a.site_score = max(r.score for r in s1)
                a.flags.update({"location_unknown", "ipv6_unknown"})
                a.hop("S2", inp={"type": "public_ip", "tok": ip_tok, "at": s.at, "family": 6},
                      out={"sites": [], "basis": "unknown", "why": "ipv6_unknown"}, score=None,
                      note="the address is IPv6 and the site's IPv6 internet addresses at that "
                           "moment are not known (UniFi reported its IPv4 address only): the "
                           "location is unknown — not ruled out")
                return self._finish_site(a)
            if known != "covered":
                # The site's own internet address at T is not known (T is
                # after its last fresh report, or in a hole): never "elsewhere".
                if known == "gap":
                    a.flags.add("data_gap")
                    a.gap = True
                if len(s1_sites) == 1:
                    a.site_id, a.site_basis = s1_sites[0], "policy"
                    a.site_score = max(r.score for r in s1)
                else:
                    a.sites, a.site_basis = s1_sites, "policy"
                    a.site_score = max(r.score for r in s1)
                a.flags.add("location_unknown")
                a.hop("S2", inp={"type": "public_ip", "tok": ip_tok, "at": s.at},
                      out={"sites": [], "basis": "unknown", "why": known}, score=None,
                      note="the site's own internet address at that moment is not known yet"
                           if known == "pending" else
                           "the UniFi feed has a hole at that moment: the site's address is "
                           "unknown")
                return self._finish_site(a)
            if len(s1_sites) == 1:
                a.site_id, a.site_basis = s1_sites[0], "not_located"
                a.site_score = max(r.score for r in s1)
                reason = "egress_unstable" if self._egress_unstable(conn, s1_sites[0], s.at) \
                    else "ip_not_an_egress"
                a.flags.add(reason)
                a.hop("S-NOTLOC", inp={"type": "public_ip", "tok": ip_tok, "at": s.at},
                      out={"site_id": a.site_id, "basis": "not_located", "reason": reason},
                      score=a.site_score,
                      note="the address is not this tenant's internet connection at that time: "
                           "the profile's site holds, but no device list is given")
            else:
                a.sites, a.site_basis = s1_sites, "not_located"
                a.site_score = max(r.score for r in s1)
            return self._finish_site(a)
        if not s1_sites and len(s2_sites) == 1:
            a.site_id, a.site_basis, a.site_score = s2_sites[0], "located", s2[s2_sites[0]][0]
        elif not s1_sites and s2_sites:
            a.sites, a.site_basis = s2_sites, "located"
            a.site_score = max(v[0] for v in s2.values())
        elif s1_sites and s2_sites:
            a.sites, a.site_basis = sorted(set(s1_sites) | set(s2_sites)), "policy"
            a.site_score = max(r.score for r in s1)
        self._finish_site(a)

    def _finish_site(self, a: Answer) -> None:
        if a.tier == "conflict":
            a.site_tier = "conflict"
        elif a.site_id is None and not a.sites:
            a.site_basis, a.site_tier, a.site_score = "none", "none", 0
        elif a.site_id is None:
            a.site_tier = "candidate"
        else:
            a.site_tier = tier_of(min(99, a.site_score))

    def _unifi_scopes(self, conn: sqlite3.Connection, site_id: str) -> list[str]:
        return sorted({r["vendor_scope_id"] for r in conn.execute(
            "SELECT vendor_scope_id FROM site_vendor_ref WHERE site_id = ? AND vendor = 'unifi' "
            "AND state IN ('auto','confirmed')", (site_id,)).fetchall()})

    def _egress_state(self, conn: sqlite3.Connection, site_ids: list[str], t: str,
                      a: Answer, *, ipv6: bool = False) -> str:
        """'covered' — an egress row of these sites vouches for T (so an
        address that matched none is really elsewhere); 'pending' — T is
        after the sites' last fresh report (wait for it); 'gap' — no
        observation covers T (an outage, or before the first report).
        For an IPv6 address only a delegated PREFIX of the sites can vouch
        (a device's own IPv6 address is anywhere in it; the gateway's WAN
        /128 alone proves nothing about the rest): with none known at all,
        'unknown_v6'."""
        marks = ",".join("?" * len(site_ids))
        rows = conn.execute(
            f"SELECT * FROM lk_site_egress WHERE site_id IN ({marks}) AND valid_from <= ? "
            f"ORDER BY id", (*site_ids, nz.shift(t, 3600))).fetchall()
        if ipv6:
            rows = [r for r in rows if ":" in r["addr"] and int(r["prefix_len"]) <= 64]
            if not rows:
                return "unknown_v6"
        else:
            rows = [r for r in rows if ":" not in r["addr"]]
        pending = False
        for r in rows:
            wm_row = iv.watermark(conn, "unifi.sites", r["vendor_scope_id"]) \
                if r["source"] == "unifi.sites" else None
            wm = wm_row["last_ok_at"] if wm_row is not None else (
                r["valid_to"] or nz.iso(self._now()))
            if _row_match(r, t, wm) is not None:
                return "covered"
            if r["valid_to"] is None and (wm is None or wm < t) and r["valid_from"] <= t:
                pending = True
                a.waits.append({"source": "unifi.sites", "scope": r["vendor_scope_id"],
                                "need": t, "have": wm})
        return "pending" if pending else "gap"

    def _egress_unstable(self, conn: sqlite3.Connection, site_id: str, t: str) -> bool:
        rows = conn.execute(
            "SELECT nat_kind, flags FROM lk_site_egress WHERE site_id = ? AND valid_from <= ? "
            "AND (valid_to IS NULL OR valid_to >= ?)", (site_id, t, t)).fetchall()
        return any(r["nat_kind"] in ("cgnat", "unknown") or "shared_external" in (r["flags"] or "")
                   for r in rows)

    # ----- WHO -----

    def _who(self, conn: sqlite3.Connection, s: Subject, a: Answer) -> None:
        if s.source == "nextdns" and (s.device_id or s.device_name):
            self._d5(conn, s, a)
            return
        if a.site_id is None:
            return
        if a.site_basis == "not_located" or "location_unknown" in a.flags:
            return                              # no device list for an unlocated IP
        if s.source == "unifi":
            if s.ip and nz.is_lan(s.ip):
                self._d3(conn, s, a, s.ip, base=min(99, a.site_score), via=None)
            return
        if s.ip and nz.is_lan(s.ip):
            self._d3(conn, s, a, s.ip, base=min(99, a.site_score), via=None)
            return
        witness = self._d4(conn, s, a)
        if witness is not None and len(witness["ips"]) == 1:
            self._d3(conn, s, a, witness["ips"][0], base=min(a.site_score, witness["score"]),
                     via="D4")
            return
        self._d7(conn, s, a, restrict_ips=witness["ips"] if witness else None,
                 witness=witness)

    def _wait_clients(self, conn: sqlite3.Connection, s: Subject, a: Answer,
                      site_id: str) -> list[str]:
        scopes = self._unifi_scopes(conn, site_id)
        skew = VENDOR_SKEW_S.get(s.vendor, 5)
        need = nz.shift(s.at, skew + JOIN_AHEAD_S)
        for scope in scopes:
            for source in ("unifi.clients", "unifi.syslog"):
                have = self._wm(conn, source, scope)
                a.deps.add(("watermark", f"{source}:{scope}"))
                if have is None or have < need:
                    a.waits.append({"source": source, "scope": scope, "need": need,
                                    "have": have})
        return scopes

    def _lease_rows(self, conn: sqlite3.Connection, site_id: str, t: str,
                    ip: Optional[str] = None) -> list[sqlite3.Row]:
        """Lease rows that MAY hold at T: a bounded scan (day-chunked rows
        start at most ~26 h before T), and rows that ended more than
        MAX_SLACK before T are left in SQLite (no margin is that wide)."""
        lo = nz.shift(t, -LEASE_LOOKBACK_S)
        hi = nz.shift(t, JOIN_AHEAD_S + MAX_SLACK_S)
        ended = nz.shift(t, -MAX_SLACK_S)
        if ip is not None:
            return conn.execute(
                "SELECT * FROM lk_ip_lease WHERE site_id = ? AND ip = ? AND valid_from "
                "BETWEEN ? AND ? AND (valid_to IS NULL OR valid_to >= ?) ORDER BY id",
                (site_id, ip, lo, hi, ended)).fetchall()
        return conn.execute(
            "SELECT * FROM lk_ip_lease WHERE site_id = ? AND valid_from BETWEEN ? AND ? "
            "AND (valid_to IS NULL OR valid_to >= ?) ORDER BY id",
            (site_id, lo, hi, ended)).fetchall()

    def _wm(self, conn: sqlite3.Connection, source: str, scope: str) -> Optional[str]:
        cache = getattr(self, "_wm_cache", None)
        if cache is not None and (source, scope) in cache:
            return cache[(source, scope)]
        wm = iv.watermark(conn, source, scope)
        value = wm["last_ok_at"] if wm is not None else None
        if cache is not None:
            cache[(source, scope)] = value
        return value

    def _lease_wm(self, conn: sqlite3.Connection, row: sqlite3.Row) -> Optional[str]:
        return self._wm(conn, "unifi.clients", row["vendor_scope_id"])

    def _subnet(self, conn: sqlite3.Connection, site_id: str, ip: Optional[str],
                at: str) -> Optional[sqlite3.Row]:
        """The most specific subnet of the site holding `ip` (valid at T, or
        the earliest configuration known after it) — loaded once per answer."""
        import ipaddress

        cache = getattr(self, "_subnet_cache", None)
        if cache is None:
            return iv.subnet_of(conn, site_id, ip, at)
        if site_id not in cache:
            nets = []
            for r in conn.execute("SELECT * FROM lk_site_subnet WHERE site_id = ? AND "
                                  "(valid_to IS NULL OR valid_to > ?) ORDER BY id",
                                  (site_id, at)).fetchall():
                try:
                    nets.append((ipaddress.ip_network(r["cidr"]), r))
                except ValueError:
                    continue
            cache[site_id] = nets
        if not ip:
            return None
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        best = None
        for net, r in cache[site_id]:
            if addr.version == net.version and addr in net and \
                    (best is None or net.prefixlen > best[0].prefixlen):
                best = (net, r)
        return best[1] if best else None

    def _ghost_near(self, conn: sqlite3.Connection, site_id: str, t: str,
                    ip: Optional[str]) -> list[sqlite3.Row]:
        """Joins of THAT address (or of an unknown one) whose MAC no lease
        covers at the join time — a device that came and went between polls
        (G10). The ghost window is [join, next poll]: only joins up to one
        poll BEFORE T count (plus JOIN_AHEAD_S after it — the join is logged
        after DHCP, the device's first lookup can precede it); a phone joining
        the guest network minutes AFTER the alert is no ghost of it."""
        lo, hi = nz.shift(t, -iv.DEFAULT_POLL_S), nz.shift(t, JOIN_AHEAD_S)
        out = []
        for j in conn.execute(
                "SELECT * FROM lk_join WHERE site_id = ? AND at BETWEEN ? AND ? AND mac IS NOT NULL "
                "AND (ip IS NULL OR ip = ?) "
                "AND event IN ('CLIENT_CONNECTED_WIRED','CLIENT_CONNECTED_WIRELESS',"
                "'HOTSPOT_GUEST_AUTHORIZED','TELEPORT_CLIENT_CONNECTED') ORDER BY at, id",
                (site_id, lo, hi, ip)).fetchall():
            covered = conn.execute(
                "SELECT 1 FROM lk_ip_lease WHERE site_id = ? AND mac = ? AND "
                "valid_from <= ? AND (valid_to IS NULL OR valid_to >= ?) LIMIT 1",
                (site_id, j["mac"], nz.shift(j["at"], iv.DEFAULT_POLL_S),
                 nz.shift(j["at"], -iv.DEFAULT_POLL_S))).fetchone()
            if covered is None:
                out.append(j)
        return out

    def _ip_conflict(self, conn: sqlite3.Connection, site_id: str, ip: str, t: str) -> bool:
        """A CLIENT_IP_CONFLICT for this address within ±10 minutes of T (a
        time-bounded fact — never the whole lease)."""
        return conn.execute(
            "SELECT 1 FROM lk_ip_conflict WHERE site_id = ? AND ip = ? AND at BETWEEN ? AND ? "
            "LIMIT 1", (site_id, ip, nz.shift(t, -iv.CONFLICT_WINDOW_S),
                        nz.shift(t, iv.CONFLICT_WINDOW_S))).fetchone() is not None

    def _anomalous(self, conn: sqlite3.Connection, site_id: str, mac: Optional[str],
                   t: str) -> bool:
        if not mac:
            return False
        return conn.execute(
            "SELECT 1 FROM lk_mac_anomaly WHERE site_id = ? AND mac = ? AND from_ts <= ? "
            "AND to_ts >= ? LIMIT 1", (site_id, mac, nz.shift(t, 3600),
                                        nz.shift(t, -3600))).fetchone() is not None

    def _cand(self, row: sqlite3.Row, match: str, score: int,
              features: list[str]) -> dict[str, Any]:
        # NEVER a name (G11): the lease row id + tokens; names are read from
        # the lease while it exists.
        return {"lease_id": int(row["id"]), "mac_tok": row["mac_tok"],
                "name_tok": row["name_tok"], "mac_kind": row["mac_kind"],
                "conn": row["conn"], "net_id": row["net_id"], "is_guest": int(row["is_guest"]),
                "match": match, "score": int(score), "features": sorted(features),
                "managed": False}

    def _d3(self, conn: sqlite3.Connection, s: Subject, a: Answer, ip: str, *, base: int,
            via: Optional[str]) -> None:
        site_id = a.site_id
        assert site_id is not None
        self._wait_clients(conn, s, a, site_id)
        matches = []
        for r in self._lease_rows(conn, site_id, s.at, ip):
            m = _row_match(r, s.at, self._lease_wm(conn, r))
            if m is not None:
                matches.append((r, m))
                a.deps.add(("lease", str(r["id"])))
        ip_tok = self.tok("lan_ip", ip)
        look = [{"table": "lk_ip_lease", "id": int(r["id"]), "source": r["source"],
                 "valid_from": r["valid_from"], "valid_to": r["valid_to"], "match": m,
                 "from_exact": int(r["from_exact"]), "conflict": int(r["conflict"]),
                 "close_reason": r["close_reason"]} for r, m in matches]
        ghosts = self._ghost_near(conn, site_id, s.at, ip)
        if len(matches) == 1:
            r, m = matches[0]
            hole = m == "in_slack" and r["close_reason"] == "reconnect" and \
                r["valid_to"] is not None and s.at > r["valid_to"]
            anomaly = self._anomalous(conn, site_id, r["mac"], s.at)
            mismatch = bool(s.mac and r["mac"] and s.mac != r["mac"])
            conflicted = bool(r["conflict"]) or self._ip_conflict(conn, site_id, ip, s.at)
            if not (conflicted or hole or anomaly or ghosts or mismatch):
                score = 85 if r["from_exact"] else 80
                adjust = []
                if m == "in_slack":
                    score -= 20
                    adjust.append("in_slack:-20")
                if r["mac_kind"] == "random":
                    score = min(score, 70)
                    adjust.append("random_mac:cap70")
                final = min(base, score)
                a.hop("D3", inp={"type": "lan_ip", "tok": ip_tok, "at": s.at, "via": via},
                      out={"device_ref": f"unifi_client:{r['mac_tok'] or r['vendor_client_id']}",
                           "lease_id": int(r["id"])},
                      score=score, lookup=look, adjust=adjust)
                a.device_ref = f"unifi_client:{r['mac_tok'] or r['vendor_client_id']}"
                a.score = final
                a.tier = tier_of(final)
                a.candidates = [self._cand(r, m, final, [])]
                a.n_candidates = 1
                if r["conn"] in ("vpn", "teleport"):
                    a.flags.add("via_vpn")
                self._also_consistent(conn, s, a, r)
                return
            why = ("conflict" if conflicted else "reconnect_hole" if hole
                   else "mac_anomaly" if anomaly else "mac_mismatch" if mismatch
                   else "ghost_join")
            a.flags.add(why)
            a.hop("D3", inp={"type": "lan_ip", "tok": ip_tok, "at": s.at, "via": via},
                  out={"candidates": 1 + len(ghosts)}, score=None, lookup=look,
                  note=f"no pick: {why.replace('_', ' ')}")
            cands = [self._cand(r, m, min(50, base), [why])]
            cands += [{"join_id": int(j["id"]), "mac_tok": self.tok("mac", j["mac"]),
                       "match": "ghost", "score": min(50, base), "features": ["ghost_join"],
                       "managed": False} for j in ghosts]
            self._set_candidates(a, cands)
            return
        if not matches:
            a.hop("D3", inp={"type": "lan_ip", "tok": ip_tok, "at": s.at, "via": via},
                  out={"device_ref": None}, score=None,
                  note="no UniFi lease held that address at that time")
            if not a.waits:
                a.flags.add("no_lease")
            return
        a.flags.add("lease_overlap")
        n = len(matches)
        each = min(50, 100 // n)
        cands = [self._cand(r, m, min(base, each), []) for r, m in matches]
        a.hop("D3", inp={"type": "lan_ip", "tok": ip_tok, "at": s.at, "via": via},
              out={"candidates": n}, score=None, lookup=look,
              note="the address changed hands around that time: both holders are listed")
        self._set_candidates(a, cands)

    def _set_candidates(self, a: Answer, cands: list[dict[str, Any]]) -> None:
        cands.sort(key=lambda c: (-int(c["score"]), 0 if c.get("match") == "in_core" else 1,
                                  int(c.get("lease_id") or 0), int(c.get("join_id") or 0)))
        a.n_candidates = len(cands)
        a.candidates = cands[:MAX_CANDIDATES]
        a.score = int(cands[0]["score"]) if cands else 0
        a.tier = "candidate"
        a.device_ref = None

    def _also_consistent(self, conn: sqlite3.Connection, s: Subject, a: Answer,
                         lease: sqlite3.Row) -> None:
        """N-DEV: a NextDNS device / Datto hostname with the same name — shown
        as "also consistent", never a score."""
        key = nz.name_key(lease["name_obs"])
        if not key:
            return
        dattos = conn.execute("SELECT device_uid FROM inv_device WHERE hostname_key = ? "
                              "AND missing_since IS NULL ORDER BY device_uid",
                              (nz.name_key(nz.hostname(lease["name_obs"])),)).fetchall()
        if dattos:
            a.hop("N-DEV", inp={"type": "name", "tok": lease["name_tok"]},
                  out={"also_consistent": [f"datto_device:{self.tok('datto_device', d['device_uid'])}"
                                           for d in dattos[:3]]},
                  score=None, note="the same computer name in Datto — names never decide")

    def _d5(self, conn: sqlite3.Connection, s: Subject, a: Answer) -> None:
        """The NextDNS app named the device. Client-asserted: at most 80 (G3)."""
        key = s.device_id or s.device_name or ""
        ref = f"nextdns_device:{self.tok('nextdns_device', key, s.scope_id)}"
        score = 80
        # The device hop stands on its own (the app named it wherever it
        # was); a known site caps it like any chain (weakest link).
        final = min(score, a.site_score) if a.site_score else score
        a.hop("D5", inp={"type": "nextdns_device", "tok": ref.split(":", 1)[1], "at": s.at,
                         "client": s.client[:24]},
              out={"device_ref": ref}, score=score, adjust=["client_asserted:cap80"],
              note="NextDNS's own app named the device — a name the device reports itself")
        a.device_ref, a.score, a.tier = ref, final, tier_of(final)
        a.n_candidates = 1
        a.candidates = [{"nextdns_device": ref, "score": final, "features": ["D5"],
                         "managed": False}]
        link = conn.execute(
            "SELECT b_value FROM device_link WHERE a_type = 'nextdns_device' AND a_value = ? "
            "AND state IN ('auto','confirmed') AND valid_to IS NULL ORDER BY id LIMIT 1",
            (f"{s.scope_id}:{s.device_id or s.device_name}",)).fetchone()
        if link is not None:
            a.hop("N-DEV", inp={"type": "nextdns_device"},
                  out={"also_consistent": [f"datto_device:{self.tok('datto_device', link['b_value'].split(':', 1)[-1])}"]},
                  score=None, note="linked to a Datto device of this tenant (same computer name)")

    def _d4(self, conn: sqlite3.Connection, s: Subject, a: Answer) -> Optional[dict[str, Any]]:
        """A buoy's Pi-hole saw the same domain within ±5 s (sensor time)."""
        if not s.domain or a.site_id is None:
            return None
        events = self._events_conn()
        if events is None:
            return None
        t = nz.dt(s.at)
        assert t is not None
        try:
            rows = events.execute(
                "SELECT id, source_host, received_at, payload FROM events "
                "WHERE event_type = 'pihole.query' AND received_at BETWEEN ? AND ? ORDER BY id",
                (nz.iso(t - timedelta(seconds=180)), nz.iso(t + timedelta(seconds=180)))).fetchall()
        except sqlite3.Error:
            rows = []
        finally:
            events.close()
        one_site = len(st.active_sites(conn)) == 1
        hits: list[tuple[str, int, int, str]] = []
        f1: list[str] = []
        for r in rows:
            try:
                p = json.loads(r["payload"])
            except ValueError:
                continue
            raw = _m(_m(p).get("raw_query"))
            dom = str(raw.get("domain") or "").lower().rstrip(".")
            client = nz.ip(str(raw.get("client") or ""))
            when = nz.dt(raw.get("timestamp"))
            status = raw.get("status")
            if not client or when is None or not isinstance(status, int):
                continue
            host = str(r["source_host"] or "")
            if not one_site:
                refs = st.refs(conn, "buoy", host, states=("auto", "confirmed"))
                if not any(x.site_id == a.site_id for x in refs):
                    continue
            delta = abs((when - t).total_seconds())
            if dom == s.domain and delta <= WITNESS_S:
                hits.append((client, int(r["id"]), status, nz.iso(when)))
            elif s.root and (dom == s.root or dom.endswith("." + s.root)) and delta <= F1_WINDOW_S:
                f1.append(client)
        if not hits and not f1:
            a.hop("D4", inp={"type": "lan_witness", "at": s.at}, out={"witness": None},
                  score=None, note="no LAN witness at this site")
            return None
        if not hits:
            return {"ips": None, "score": 0, "f1": sorted(set(f1))}
        ips = sorted({h[0] for h in hits})
        upstream = all(h[2] in UPSTREAM_BLOCK_STATUSES for h in hits)
        score = 88 if upstream else 80
        a.hop("D4", inp={"type": "lan_witness", "at": s.at, "window_s": WITNESS_S},
              out={"lan_ips": [self.tok("lan_ip", ip) for ip in ips]}, score=score,
              lookup=[{"table": "events", "id": h[1], "status": h[2], "sensor_time": h[3]}
                      for h in hits],
              note="a Pi-hole on this site's LAN saw the same lookup"
                   + (" and NextDNS blocked it upstream" if upstream else ""))
        for h in hits:
            a.deps.add(("event", str(h[1])))
        return {"ips": ips, "score": score, "f1": sorted(set(f1) | set(ips))}

    def _app_devices(self, conn: sqlite3.Connection, s: Subject,
                     a: Answer) -> Optional[set[str]]:
        """Name keys of NextDNS-app devices of this profile that reported
        DIRECTLY in T's OWN hour (their lookups never pass the gateway, so a
        gateway-sourced line cannot be theirs). A device whose app died
        minutes before T still has queries in the hour BEFORE — it is NOT
        excluded for that. Matched by NAME only: the app's localIp is the
        latest seen anywhere (at home, at a hotel), never proof of this LAN.
        None while T's hour is not read yet (and the profile has app devices
        at all): the answer waits for it and excludes nothing meanwhile."""
        hour = nz.hour_start(s.at)
        known = conn.execute(
            "SELECT 1 FROM ndns_device WHERE profile_id = ? AND last_seen >= ? LIMIT 1",
            (s.scope_id, nz.shift(hour, -7 * 86400))).fetchone()
        if known is None:
            return set()
        read = conn.execute("SELECT 1 FROM ndns_presence_hour WHERE profile_id = ? AND hour = ?",
                            (s.scope_id, hour)).fetchone()
        if read is None:
            have = conn.execute("SELECT MAX(hour) FROM ndns_presence_hour WHERE profile_id = ?",
                                (s.scope_id,)).fetchone()[0]
            a.waits.append({"source": "nextdns.presence", "scope": s.scope_id, "need": hour,
                            "have": have})
            a.flags.add("app_presence_pending")
            return None
        rows = conn.execute(
            "SELECT d.name_key FROM ndns_device_hour h JOIN ndns_device d "
            "ON d.profile_id = h.profile_id AND d.device_id = h.device_id "
            "WHERE h.profile_id = ? AND h.hour = ? AND h.queries > 0",
            (s.scope_id, hour)).fetchall()
        return {r["name_key"] for r in rows if r["name_key"]}

    def _d7(self, conn: sqlite3.Connection, s: Subject, a: Answer, *,
            restrict_ips: Optional[list[str]], witness: Optional[dict[str, Any]]) -> None:
        site_id = a.site_id
        assert site_id is not None
        self._wait_clients(conn, s, a, site_id)
        excluded: dict[str, int] = {}
        app_names = (self._app_devices(conn, s, a) if s.gateway_sourced else set()) or set()
        joins_near = {}
        for j in conn.execute(
                "SELECT mac, at FROM lk_join WHERE site_id = ? AND at BETWEEN ? AND ? AND mac IS "
                "NOT NULL AND event LIKE '%CONNECTED%' ORDER BY at",
                (site_id, nz.shift(s.at, -JOIN_AHEAD_S), nz.shift(s.at, JOIN_AHEAD_S))).fetchall():
            joins_near.setdefault(j["mac"], j["at"])
        last_hit = None
        if s.bucket and s.bucket.get("last_seen") and int(s.bucket.get("hits") or 1) > 1:
            last_hit = nz.ts(s.bucket["last_seen"])
            if last_hit and last_hit != s.at:
                a.flags.add("bucket_later_hits")
        f3_macs = self._f3(conn, s)
        present_at_last: set[str] = set()
        if last_hit and last_hit != s.at:
            for x in self._lease_rows(conn, site_id, last_hit):
                if _row_match(x, last_hit, self._lease_wm(conn, x)) is not None:
                    present_at_last.add(x["mac"] or f"id:{x['vendor_client_id']}")
        chosen: dict[str, tuple[sqlite3.Row, str, list[str]]] = {}
        for r in self._lease_rows(conn, site_id, s.at):
            m = _row_match(r, s.at, self._lease_wm(conn, r))
            joined_after = False
            if m is None and r["from_exact"] and r["valid_from"] > s.at and \
                    nz.seconds_between(s.at, r["valid_from"]) <= JOIN_AHEAD_S:
                m, joined_after = "joined_after", True
            if m is None:
                continue
            if restrict_ips is not None and r["ip"] not in restrict_ips:
                continue
            if r["mac_kind"] == "virtual":
                excluded["virtual_mac"] = excluded.get("virtual_mac", 0) + 1
                continue
            subnet = self._subnet(conn, site_id, r["ip"], s.at)
            if s.source == "nextdns" and subnet is not None and subnet["dns_path"] in ("other",):
                excluded["dns_bypasses_nextdns"] = excluded.get("dns_bypasses_nextdns", 0) + 1
                continue
            if s.gateway_sourced and app_names and nz.name_key(r["name_obs"]) and \
                    nz.name_key(r["name_obs"]) in app_names:
                excluded["nextdns_app_device"] = excluded.get("nextdns_app_device", 0) + 1
                continue
            features = []
            if joined_after or (r["mac"] and r["mac"] in joins_near):
                features.append("FJ")
            if witness and witness.get("f1") and r["ip"] in witness["f1"]:
                features.append("F1")
            if last_hit and last_hit != s.at:
                same = (r["mac"] or f"id:{r['vendor_client_id']}") in present_at_last
                connected = r["connected_at"]
                always_on = bool(connected and nz.seconds_between(connected, s.at) > ALWAYS_ON_S)
                if same and not always_on:
                    features.append("F2")
            if r["mac_tok"] and r["mac_tok"] in f3_macs:
                features.append("F3")
            key = r["mac"] or f"id:{r['vendor_client_id']}" or str(r["id"])
            prior = chosen.get(key)
            # One candidate per client: the row in core wins, then the lowest id.
            if prior is None or (prior[1] != "in_core" and m == "in_core"):
                chosen[key] = (r, m, features)
            a.deps.add(("lease", str(r["id"])))
        n = len(chosen)
        cands = []
        for key in sorted(chosen):
            r, m, features = chosen[key]
            score = min(69, (min(50, 100 // n) if n else 0) + 10 * len(features))
            cands.append(self._cand(r, m if m != "joined_after" else "joined_after",
                                    min(score, a.site_score), features))
        if s.gateway_sourced:
            a.flags.add("gateway_sourced")
        a.hop("D7", inp={"type": "site", "site_id": site_id, "at": s.at},
              out={"candidates": n, "excluded": dict(sorted(excluded.items()))},
              score=max((c["score"] for c in cands), default=None),
              note=("NextDNS saw only the site's public address: every device connected then "
                    "is a candidate" if n else
                    "every device connected then was set aside (see excluded): none is left "
                    "as a candidate" if excluded else "no device was connected at that time"))
        if "location_unverified" in a.flags:
            a.flags.add("location_unverified")
        if n:
            self._set_candidates(a, cands)
        else:
            a.tier, a.score = "none", 0

    def _f3(self, conn: sqlite3.Connection, s: Subject) -> set[str]:
        """Clients resolved (medium or better, BY A RULE — never an
        operator's one-off, G8) for the same root in the last 7 days."""
        if not s.root:
            return set()
        rows = conn.execute(
            "SELECT device_ref FROM resolution WHERE subject_root = ? AND at >= ? AND at < ? "
            "AND tier IN ('medium','strong','exact') AND status <> 'superseded' "
            "AND created_by LIKE 'rule:%' AND device_ref LIKE 'unifi_client:%'",
            (s.root, nz.shift(s.at, -7 * 86400), s.at)).fetchall()
        return {r["device_ref"].split(":", 1)[1] for r in rows}

    # ----- storing -----

    def _status(self, a: Answer, s: Subject, now: datetime) -> tuple[str, set[str]]:
        flags: set[str] = set()
        if not a.waits:
            return "final", flags
        at = nz.dt(s.at)
        assert at is not None
        if now >= finalise_deadline(at, a.waits):
            flags.add("lookup_stale")
            if a.gap or any(w["have"] is None or w["have"] < s.at for w in a.waits
                            if str(w["source"]).startswith("unifi.")):
                flags.add("data_gap")
            return "final", flags
        return "provisional", flags

    def _store(self, conn: sqlite3.Connection, s: Subject, a: Answer, *, mode: str,
               created_by: str) -> dict[str, Any]:
        now = self._now()
        status, more = self._status(a, s, now)
        flags = sorted(a.flags | more)
        if status == "final" and "lookup_stale" in flags:
            for w in a.waits:
                a.deps.add(("watermark", f"{w['source']}:{w['scope']}"))
        res_id = ids.new("rs")
        subject_kind = s.subject_type
        subject_value = s.ip or s.device_id or s.device_name or ""
        # Each wait keeps what it HAD and what it NEEDS ("have|need"): the
        # worker redoes an answer only once every wait reached its need.
        wm = sorted({f"{w['source']}:{w['scope']}={w['have']}|{w['need']}" for w in a.waits})
        row = {
            "res_id": res_id, "event_id": s.event_id, "event_source": s.source,
            "subject_type": subject_kind,
            "subject_tok": self.tok(subject_kind if subject_kind != "none" else "name",
                                    subject_value) or "",
            "subject_root": s.root, "tok_key_version": tk.key_version(), "at": s.at,
            "time_quality": s.time_quality, "site_id": a.site_id,
            "site_basis": a.site_basis if a.site_basis in
            ("located", "policy", "both", "not_located", "none") else "none",
            "site_score": a.site_score, "site_tier": a.site_tier,
            "device_ref": a.device_ref, "tier": a.tier, "score": int(a.score),
            "n_candidates": a.n_candidates,
            "chain": json.dumps(a.chain, sort_keys=True, separators=(",", ":")),
            "candidates": json.dumps(a.candidates, sort_keys=True, separators=(",", ":")),
            "flags": json.dumps(flags), "resolver_version": RESOLVER_VERSION,
            "lookup_watermark": ";".join(wm) or "complete", "mode": mode,
            "bucket_last_seen": (nz.ts(s.bucket.get("last_seen")) if s.bucket else None),
            "status": status,
            "superseded_by": None, "created_at": nz.iso(now), "created_by": created_by,
        }
        if mode == "backfill" and s.event_id is not None:
            prior = current(conn, s.event_id, s.source)
            if prior is not None and all(prior[k] == row[k] for k in NOOP_FIELDS):
                # The same answer again: nothing is written.
                return {**dict(prior), "noop": True}
        conn.execute(
            f"INSERT INTO resolution ({', '.join(row)}) VALUES ({', '.join('?' * len(row))})",
            list(row.values()))
        for kind, dep in sorted(a.deps):
            conn.execute("INSERT OR IGNORE INTO resolution_dep (dep_kind, dep_id, res_id) "
                         "VALUES (?, ?, ?)", (kind, dep, res_id))
        if s.event_id is not None:
            conn.execute(
                "UPDATE resolution SET status = 'superseded', superseded_by = ? "
                "WHERE event_id = ? AND event_source = ? AND res_id <> ? "
                "AND status <> 'superseded'", (res_id, s.event_id, s.source, res_id))
        if a.conflict is not None:
            st.record_conflict(conn, "site_conflict", f"event:{s.source}:{s.event_id}",
                               {**a.conflict, "at": s.at}, nz.iso(now))
        return row


def current(conn: sqlite3.Connection, event_id: int, source: Optional[str] = None
            ) -> Optional[sqlite3.Row]:
    sql = "SELECT * FROM resolution WHERE event_id = ? AND status <> 'superseded'"
    args: list[Any] = [int(event_id)]
    if source:
        sql += " AND event_source = ?"
        args.append(source)
    return conn.execute(sql + " ORDER BY created_at DESC, res_id DESC LIMIT 1", args).fetchone()


def finalise_deadline(at: datetime, waits: list[Any]) -> datetime:
    """When an answer still waiting is finalised (`lookup_stale`): T + 30
    minutes — or, while it waits for T's NextDNS presence hour, not before
    that hour is due to be read + slack. `waits` are the answer's own
    ({source, need}) or stored ones (`parse_waits`)."""
    deadline = at + FINALISE_AFTER
    for w in waits:
        source, need = (w.get("source"), w.get("need")) if isinstance(w, dict) else (w[0], w[3])
        if source != "nextdns.presence" or not need:
            continue
        hour = nz.dt(need)
        if hour is not None:
            deadline = max(deadline, hour + PRESENCE_READ_AFTER + PRESENCE_SLACK)
    return deadline


def parse_waits(text: Optional[str]) -> list[tuple[str, str, Optional[str], Optional[str]]]:
    """A stored `lookup_watermark` → [(source, scope, have, need)]."""
    out = []
    for w in (text or "").split(";"):
        if "=" not in w:
            continue
        key, value = w.split("=", 1)
        source, _, scope = key.partition(":")
        have, sep, need = value.partition("|")
        out.append((source, scope, None if have == "None" else have,
                    (need or None) if sep else None))
    return out


def wait_state(conn: sqlite3.Connection, source: str, scope: str,
               need: Optional[str]) -> tuple[Optional[str], bool]:
    """(what the feed has now, whether that meets `need`) for one wait."""
    if source == "nextdns.presence":
        have = conn.execute("SELECT MAX(hour) FROM ndns_presence_hour WHERE profile_id = ?",
                            (scope,)).fetchone()[0]
        met = need is not None and conn.execute(
            "SELECT 1 FROM ndns_presence_hour WHERE profile_id = ? AND hour = ?",
            (scope, need)).fetchone() is not None
        return have, met
    row = conn.execute("SELECT last_ok_at FROM lk_watermark WHERE source = ? AND scope = ?",
                       (source, scope)).fetchone()
    have = row["last_ok_at"] if row is not None else None
    return have, bool(have and need and have >= need)
