"""Link rules — structural opinions about what belongs together, run by the
worker (design 3.4, with G5 / G8 / S-11). Only narrow evidence writes `auto`;
names only ever SUGGEST (capped at 45, their own review tab); an operator's
decision is never touched (the triggers); a rule that runs into one becomes a
Conflicts card.

  reconcile_unifi   a UniFi site no longer mapped to this tenant: its refs are
                    retired and its open lookups closed at their last
                    observation ('unmapped'); a site re-mapped elsewhere
                    starts fresh THERE (nothing is copied). A site still
                    mapped to this tenant through ANOTHER adapter instance (a
                    key rotation) keeps its Athena site: only the ref moves,
                    nothing closes. A registry that cannot be read changes
                    NOTHING (every rule below too).
  L-SOLE            a tenant with exactly ONE active site: its NextDNS
                    profiles belong to it — `auto` 90 only when the profile's
                    mapping is the operator's own ('manual') AND at least 80 %
                    of its queries over 7 days (3+ days of data) came from that
                    site's egress (G5); otherwise `suggested` 85. With a second
                    site, L-SOLE's auto refs drop to `suggested`.
  L-EGRESS          a profile whose queries came from a site's egress on 3+
                    distinct days and are 80 %+ of its 7-day volume:
                    `suggested` 85 (one click in the review queue)
  N-SITE            a profile whose name equals a site's label: `suggested`,
                    at most 45, its own tab — never used by S1
  (combined)        L-SOLE, L-EGRESS and N-SITE give OPINIONS; each (site,
                    profile) gets ONE suggestion — the strongest opinion, every
                    agreeing rule kept as provenance — written only when its
                    effective state changes (`profile_sites`). The counts in
                    its evidence are refreshed at most once a day, silently.
  routing sanity    a profile whose traffic came from NONE of the tenant's
                    egresses on 3+ days while the tenant has live UniFi
                    egress: "profile may belong to another client" (Conflicts
                    + one notice). Uses only this tenant's data. A Resolve
                    sticks until the evidence materially changes; "accept as
                    expected" suppresses it for the profile; seeing it again
                    is never a change.
  NextDNS ↔ Datto   the NextDNS app's device name equals a Datto hostname,
                    each UNIQUE in this tenant: `suggested` 45 (N-DEV); the
                    same name AND the same LAN address (NextDNS `localIp` =
                    Datto `intIpAddress`): `auto` 80 (L-NDNS-DATTO — two
                    agents agreeing on two keys). Ambiguous names link
                    nothing; an auto link whose name stops being unique is
                    retired.
"""
from __future__ import annotations

import json
import sqlite3
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Optional

from apps.octo.entity import intervals as iv
from apps.octo.entity import normalize as nz
from apps.octo.entity import sites as st
from apps.octo.entity.feeders import mapping

L_SOLE_AUTO = 90
L_SOLE_SUGGEST = 85
L_EGRESS_SUGGEST = 85
COVERAGE_SHARE = 0.8
COVERAGE_DAYS = 3
COVERAGE_WINDOW_DAYS = 7
ROUTING_SILENT_DAYS = 3
# A resolved routing conflict whose condition went away reopens only when it
# comes back after this many days (a material change of the evidence).
ROUTING_REOPEN_DAYS = 3
# The suppression an operator's "accept as expected" writes (a_type 'routing',
# a_value 'nextdns:<profile>').
ROUTING_EXPECTED = ("expected", "other_egress")
DEVICE_LINK_AUTO = 80
DEVICE_LINK_NAME = 45


# ---------------------------------------------------------------------------
# UniFi mappings → refs
# ---------------------------------------------------------------------------

def reconcile_unifi(conn: sqlite3.Connection, slug: str, now: str) -> int:
    scopes = mapping.mapped_scopes("unifi", slug)
    if scopes is None:
        return 0                        # registry unreadable: change nothing
    mapped = {(inst, scope) for inst, scope, _src, _lbl in scopes}
    by_scope: dict[str, list[tuple[int, str]]] = defaultdict(list)
    for inst, scope, src, _lbl in scopes:
        by_scope[scope].append((inst, src))
    rows = conn.execute(
        "SELECT DISTINCT adapter_instance_id, vendor_scope_id FROM site_vendor_ref "
        "WHERE vendor = 'unifi' AND valid_to IS NULL AND state IN ('auto','confirmed','suggested')"
    ).fetchall()
    n = 0
    for r in rows:
        key = (int(r["adapter_instance_id"]), r["vendor_scope_id"])
        if key in mapped:
            continue
        others = by_scope.get(key[1])
        if others:
            # Still THIS tenant's site, read through another instance (a key
            # rotation): the Athena site belongs to the scope — the ref moves
            # to the instance that maps it now; no lookup closes.
            from apps.octo.entity.feeders.unifi import attach_ref

            site_id = st.refs(conn, "unifi", key[1], instance_id=key[0],
                              states=("confirmed", "auto", "suggested"))[0].site_id
            for inst, src in others:
                if not st.refs(conn, "unifi", key[1], instance_id=inst,
                               states=("confirmed", "auto", "suggested")):
                    attach_ref(conn, site_id=site_id, instance_id=inst, scope=key[1],
                               match_source=src, now=now)
            st.retire_scope(conn, vendor="unifi", instance_id=key[0], scope_id=key[1], now=now,
                            reason="the UniFi site is mapped to this client through another "
                                   "adapter instance now")
            n += 1
            continue
        st.retire_scope(conn, vendor="unifi", instance_id=key[0], scope_id=key[1], now=now,
                        reason="the UniFi site is no longer mapped to this client")
        iv.close_scope(conn, key[1], now, "unmapped")
        n += 1
    return n


# ---------------------------------------------------------------------------
# NextDNS profiles → sites
# ---------------------------------------------------------------------------

def coverage(conn: sqlite3.Connection, profile_id: str, site_id: str,
             now: str) -> dict[str, Any]:
    """The share of the profile's queries over the last 7 days that came from
    `site_id`'s egress addresses (NextDNS analytics by IP, read daily; other
    public addresses are never stored, only counted)."""
    since = nz.shift(nz.day_start(now), -COVERAGE_WINDOW_DAYS * 86400)[:10]
    days = conn.execute(
        "SELECT day, egress_queries, total_queries, egress_ips FROM ndns_ip_day "
        "WHERE profile_id = ? AND day >= ? ORDER BY day", (profile_id, since)).fetchall()
    total = site_q = 0
    matching_days = 0
    data_days = 0
    for d in days:
        if int(d["total_queries"] or 0) <= 0:
            continue
        data_days += 1
        total += int(d["total_queries"])
        try:
            per_ip = json.loads(d["egress_ips"] or "[]")
        except ValueError:
            per_ip = []
        day_q = 0
        for entry in per_ip:
            if not isinstance(entry, list) or len(entry) != 2 or not isinstance(entry[0], str):
                continue
            ip, q = entry
            # An address, or "<prefix>/<len>" (IPv6 traffic from inside a
            # delegated prefix, counted under the prefix).
            addr, _, plen = ip.partition("/")
            sql = ("SELECT 1 FROM lk_site_egress WHERE site_id = ? AND addr = ? AND valid_from "
                   "<= ? AND (valid_to IS NULL OR valid_to >= ?)")
            args: list[Any] = [site_id, addr, d["day"] + "T23:59:59.999Z",
                               d["day"] + "T00:00:00.000Z"]
            if plen:
                sql += " AND prefix_len = ?"
                args.append(int(plen) if plen.isdigit() else -1)
            if conn.execute(sql + " LIMIT 1", args).fetchone() is not None:
                day_q += int(q)
        site_q += day_q
        if day_q > 0:
            matching_days += 1
    share = (site_q / total) if total else 0.0
    return {"days_with_data": data_days, "days_from_site": matching_days,
            "queries": total, "queries_from_site": site_q, "share": round(share, 4)}


def _profiles(slug: str) -> Optional[list[tuple[int, str, str, Optional[str]]]]:
    """The tenant's mapped NextDNS profiles; None = the registry could not be
    read (the rules then change nothing)."""
    return mapping.mapped_scopes("nextdns", slug)


@dataclass(frozen=True)
class Opinion:
    """One rule's opinion that a NextDNS profile belongs to a site."""
    site_id: str
    instance_id: int
    scope_id: str
    state: str
    score: int
    rule_id: str
    evidence: dict[str, Any]


# Which rule's evidence leads when two agree at the same state and score.
RULE_RANK = {"L-SOLE": 3, "L-EGRESS": 2, "N-SITE": 1}


def l_sole(conn: sqlite3.Connection, slug: str, now: str,
           profiles: Optional[list[tuple[int, str, str, Optional[str]]]] = None,
           sites: Optional[list[sqlite3.Row]] = None) -> list[Opinion]:
    profiles = _profiles(slug) if profiles is None else profiles
    sites = st.active_sites(conn) if sites is None else sites
    if profiles is None or len(sites) != 1:
        return []
    site_id = sites[0]["site_id"]
    out = []
    for inst, pid, source, _label in profiles:
        cov = coverage(conn, pid, site_id, now)
        auto = (source == "manual" and cov["days_with_data"] >= COVERAGE_DAYS
                and cov["share"] >= COVERAGE_SHARE)
        out.append(Opinion(site_id, inst, pid, "auto" if auto else "suggested",
                           L_SOLE_AUTO if auto else L_SOLE_SUGGEST, "L-SOLE",
                           {"match_source": source, "coverage": cov}))
    return out


def l_egress(conn: sqlite3.Connection, slug: str, now: str,
             profiles: Optional[list[tuple[int, str, str, Optional[str]]]] = None,
             sites: Optional[list[sqlite3.Row]] = None) -> list[Opinion]:
    sites = st.active_sites(conn) if sites is None else sites
    if len(sites) < 2:
        return []                      # one site: L-SOLE says it
    profiles = _profiles(slug) if profiles is None else profiles
    if profiles is None:
        return []
    out = []
    for inst, pid, _source, _label in profiles:
        for s in sites:
            cov = coverage(conn, pid, s["site_id"], now)
            if cov["days_from_site"] >= COVERAGE_DAYS and cov["share"] >= COVERAGE_SHARE:
                out.append(Opinion(s["site_id"], inst, pid, "suggested", L_EGRESS_SUGGEST,
                                   "L-EGRESS", {"coverage": cov}))
    return out


def n_site(conn: sqlite3.Connection, slug: str, now: str,
           profiles: Optional[list[tuple[int, str, str, Optional[str]]]] = None,
           sites: Optional[list[sqlite3.Row]] = None) -> list[Opinion]:
    sites = st.active_sites(conn) if sites is None else sites
    profiles = _profiles(slug) if profiles is None else profiles
    if profiles is None:
        return []
    out = []
    for inst, pid, _source, label in profiles:
        key = nz.name_key(label)
        if not key:
            continue
        # A profile already linked (auto / confirmed) gets no name suggestion
        # for ANOTHER site; for the linked site itself a name is provenance.
        linked = {r.site_id for r in st.refs(conn, "nextdns", pid, instance_id=inst,
                                             states=("auto", "confirmed"))}
        for s in sites:
            if linked and s["site_id"] not in linked:
                continue
            if nz.name_key(s["label"]) == key:
                out.append(Opinion(s["site_id"], inst, pid, "suggested", st.NAME_CAP, "N-SITE",
                                   {"same_name": True}))
    return out


def _demote_l_sole(conn: sqlite3.Connection, sites: list[sqlite3.Row], now: str) -> int:
    """With a second site, L-SOLE's auto refs drop to `suggested` (once)."""
    if len(sites) == 1:
        return 0
    changed = 0
    for r in conn.execute(
            "SELECT * FROM site_vendor_ref WHERE rule_id = 'L-SOLE' AND state = 'auto' "
            "AND valid_to IS NULL").fetchall():
        p = st.propose(conn, site_id=r["site_id"], vendor=r["vendor"],
                       instance_id=int(r["adapter_instance_id"]),
                       scope_id=r["vendor_scope_id"], state="suggested",
                       score=L_SOLE_SUGGEST, rule_id="L-SOLE", rule_version=1,
                       evidence={"why": "the client has more than one site now",
                                 "rules": ["L-SOLE"], "as_of": now[:10]},
                       now=now, provenance=["L-SOLE"])
        changed += p.outcome in ("inserted", "updated")
    return changed


def profile_sites(conn: sqlite3.Connection, slug: str, now: str) -> int:
    """L-SOLE, L-EGRESS and N-SITE as ONE combined suggestion per (site,
    profile): the strongest opinion (auto over suggested, then the score,
    then L-SOLE > L-EGRESS > N-SITE) with every agreeing rule as provenance
    (`evidence.rules`; the others' evidence under `evidence.also`). Written
    only when that effective state changes — two rules never take turns
    rewriting one row (which wrote a run row and a global audit row per
    client per minute). Returns the number of real changes."""
    profiles = _profiles(slug)
    if profiles is None:
        return 0                        # registry unreadable: change nothing
    sites = st.active_sites(conn)
    changed = _demote_l_sole(conn, sites, now)
    opinions = (l_sole(conn, slug, now, profiles, sites) + l_egress(conn, slug, now, profiles, sites)
                + n_site(conn, slug, now, profiles, sites))
    by_pair: dict[tuple[str, int, str], list[Opinion]] = defaultdict(list)
    for o in opinions:
        by_pair[(o.site_id, o.instance_id, o.scope_id)].append(o)
    for (site_id, inst, pid), ops in sorted(by_pair.items()):
        best = max(ops, key=lambda o: (o.state == "auto", o.score, RULE_RANK.get(o.rule_id, 0)))
        rules = sorted({o.rule_id for o in ops})
        evidence: dict[str, Any] = {**best.evidence, "rules": rules, "as_of": now[:10]}
        also = {o.rule_id: o.evidence for o in ops if o.rule_id != best.rule_id}
        if also:
            evidence["also"] = also
        p = st.propose(conn, site_id=site_id, vendor="nextdns", instance_id=inst, scope_id=pid,
                       state=best.state, score=best.score, rule_id=best.rule_id, rule_version=1,
                       evidence=evidence, now=now, provenance=rules)
        changed += p.outcome in ("inserted", "updated")
    return changed


def routing_subject(profile_id: str) -> str:
    return f"nextdns:{profile_id}"


def routing_accepted(conn: sqlite3.Connection, profile_id: str, now: str) -> Optional[str]:
    """'active' when an operator accepted the profile's traffic from
    elsewhere as EXPECTED (a branch office without UniFi, a second site);
    'expired' when that acceptance ran out; else None."""
    return st.suppressed(conn, "routing", routing_subject(profile_id), *ROUTING_EXPECTED,
                         now=now)


def routing_sanity(conn: sqlite3.Connection, slug: str, now: str) -> int:
    """'A profile whose traffic came from none of the tenant's egresses on 3+
    of the last 7 days.' Returns how many Conflicts cards it OPENED (or
    reopened) — seeing the same condition again is never a change:
      * an operator's Resolve sticks until the evidence materially changes:
        the tenant's own internet addresses change (a new egress), or the
        condition went away (`cleared_at`) and came back after
        ROUTING_REOPEN_DAYS days;
      * 'accept as expected' suppresses the check for that profile (until
        the acceptance expires, when it may open once more)."""
    if conn.execute("SELECT 1 FROM lk_site_egress WHERE source = 'unifi.sites' AND "
                    "valid_to IS NULL LIMIT 1").fetchone() is None:
        return 0
    since = nz.shift(nz.day_start(now), -COVERAGE_WINDOW_DAYS * 86400)[:10]
    profiles = _profiles(slug)
    if profiles is None:
        return 0
    egress = [r["addr"] + ("" if int(r["prefix_len"]) in (32, 128) else f"/{r['prefix_len']}")
              for r in conn.execute(
                  "SELECT DISTINCT addr, prefix_len FROM lk_site_egress WHERE valid_from <= ? AND "
                  "(valid_to IS NULL OR valid_to > ?) ORDER BY addr, prefix_len",
                  (now, now)).fetchall()]
    n = 0
    for _inst, pid, _source, label in profiles:
        subject = routing_subject(pid)
        accepted = routing_accepted(conn, pid, now)
        if accepted == "active":
            continue
        rows = conn.execute(
            "SELECT day, egress_queries, total_queries FROM ndns_ip_day WHERE profile_id = ? "
            "AND day >= ? ORDER BY day", (pid, since)).fetchall()
        silent = [r["day"] for r in rows
                  if int(r["total_queries"] or 0) > 0 and int(r["egress_queries"] or 0) == 0]
        row = conn.execute("SELECT * FROM link_conflict WHERE kind = 'routing' AND subject = ?",
                           (subject,)).fetchone()
        closed = row is not None and row["resolved_at"] is not None
        if len(silent) < ROUTING_SILENT_DAYS:
            if closed and row["cleared_at"] is None:
                conn.execute("UPDATE link_conflict SET cleared_at = ? WHERE id = ?",
                             (now, row["id"]))
            continue
        detail = {"profile_id": pid, "profile_name": label, "egress": egress,
                  "days_from_no_site": silent[-7:]}
        text = json.dumps(detail, sort_keys=True, separators=(",", ":"))
        if closed:
            back_after = (row["cleared_at"] is not None and nz.seconds_between(
                row["cleared_at"], now) >= ROUTING_REOPEN_DAYS * 86400)
            if (row["resolution"] == "accepted" and accepted == "expired") or back_after:
                st.reopen(conn, int(row["id"]), detail=text, now=now)
                n += 1
                continue
            if row["cleared_at"] is not None:
                # It came back within days: the operator's Resolve stands.
                conn.execute("UPDATE link_conflict SET cleared_at = NULL WHERE id = ?",
                             (row["id"],))
        _cid, outcome = st.observe_conflict(conn, "routing", subject, detail, now)
        n += outcome in ("opened", "reopened")
    return n


# ---------------------------------------------------------------------------
# NextDNS device ↔ Datto device
# ---------------------------------------------------------------------------

def _propose_device_link(conn: sqlite3.Connection, *, a_value: str, b_value: str, state: str,
                         score: int, rule_id: str, evidence: dict[str, Any],
                         now: str) -> str:
    supp = st.suppressed(conn, "nextdns_device", a_value, "datto_device", b_value, now=now)
    if supp == "active":
        return "suppressed"
    if supp == "expired" and state == "auto":
        state, score = "suggested", min(score, DEVICE_LINK_NAME)
    rows = conn.execute(
        "SELECT * FROM device_link WHERE a_value = ? AND b_value = ? AND valid_to IS NULL "
        "ORDER BY id", (a_value, b_value)).fetchall()
    for r in rows:
        if r["state"] in ("confirmed", "rejected"):
            return "unchanged"
        if r["state"] == state and int(r["score"]) == score and r["rule_id"] == rule_id:
            return "unchanged"
        conn.execute("UPDATE device_link SET state = ?, score = ?, rule_id = ?, evidence = ?, "
                     "decided_by = ?, decided_at = ? WHERE id = ?",
                     (state, score, rule_id, json.dumps(evidence, sort_keys=True),
                      f"rule:{rule_id}@1", now, r["id"]))
        return "updated"
    try:
        conn.execute(
            "INSERT INTO device_link (a_type, a_value, b_type, b_value, state, score, rule_id, "
            " rule_version, evidence, valid_from, decided_by, decided_at, created_at) "
            "VALUES ('nextdns_device', ?, 'datto_device', ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)",
            (a_value, b_value, state, score, rule_id, json.dumps(evidence, sort_keys=True), now,
             f"rule:{rule_id}@1", now, now))
    except sqlite3.IntegrityError as exc:
        if "operator decision" not in str(exc):
            raise
        st.record_conflict(conn, "device_link", f"nextdns_device:{a_value}",
                           {"wanted": b_value, "rule": rule_id}, now)
        return "conflict"
    return "inserted"


def device_links(conn: sqlite3.Connection, now: str) -> int:
    nd_by_key: dict[str, list[sqlite3.Row]] = defaultdict(list)
    for r in conn.execute("SELECT * FROM ndns_device WHERE name_key IS NOT NULL "
                          "ORDER BY profile_id, device_id").fetchall():
        nd_by_key[r["name_key"]].append(r)
    dd_by_key: dict[str, list[sqlite3.Row]] = defaultdict(list)
    for r in conn.execute("SELECT * FROM inv_device WHERE hostname_key IS NOT NULL AND "
                          "missing_since IS NULL ORDER BY adapter_instance_id, device_uid"
                          ).fetchall():
        dd_by_key[r["hostname_key"]].append(r)
    changed = 0
    linked: set[str] = set()
    for key in sorted(set(nd_by_key) & set(dd_by_key)):
        nds, dds = nd_by_key[key], dd_by_key[key]
        if len(nds) != 1 or len(dds) != 1:
            continue                    # ambiguous: names never decide between two
        nd, dd = nds[0], dds[0]
        a_value = f"{nd['profile_id']}:{nd['device_id']}"
        b_value = f"{dd['adapter_instance_id']}:{dd['device_uid']}"
        ip_agree = bool(nd["local_ip"] and dd["int_ip"] and nd["local_ip"] == dd["int_ip"])
        evidence = {"same_name": True, "same_lan_ip": ip_agree,
                    "nextdns_client": nd["client"], "datto_device_type": dd["device_type"]}
        if ip_agree:
            out = _propose_device_link(conn, a_value=a_value, b_value=b_value, state="auto",
                                       score=DEVICE_LINK_AUTO, rule_id="L-NDNS-DATTO",
                                       evidence=evidence, now=now)
        else:
            out = _propose_device_link(conn, a_value=a_value, b_value=b_value, state="suggested",
                                       score=DEVICE_LINK_NAME, rule_id="N-DEV",
                                       evidence=evidence, now=now)
        changed += out in ("inserted", "updated")
        linked.add(a_value)
    # A rule's own link whose evidence no longer holds (the name is no longer
    # unique, a device left) is retired — never an operator's.
    for r in conn.execute("SELECT * FROM device_link WHERE state IN ('auto','suggested') AND "
                          "valid_to IS NULL").fetchall():
        if r["a_value"] not in linked:
            conn.execute("UPDATE device_link SET state = 'retired', valid_to = ?, "
                         "decided_by = 'rule:retire', decided_at = ? WHERE id = ?",
                         (now, now, r["id"]))
            changed += 1
    return changed


def run_all(conn: sqlite3.Connection, slug: str, now: str) -> dict[str, int]:
    return {
        "unifi_unmapped": reconcile_unifi(conn, slug, now),
        "profile_sites": profile_sites(conn, slug, now),
        "routing": routing_sanity(conn, slug, now),
        "device_links": device_links(conn, now),
    }
