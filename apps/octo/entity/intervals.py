"""Lookup intervals from vendor snapshots — "who had what, when" (design 2.6,
with the adversarial fixes G7 and G10).

Every fact has a start and an end, and an edge only seen between two polls
carries an HONEST margin (`*_slack_s`): "somewhere in these 5 minutes".

  egress    (fleet report, per site) one row per WAN while its cloud-observed
            address stays the same. A report from a console that is not
            connected, or whose gateway is offline, is NOT an observation (G7):
            nothing closes, nothing extends, the site's watermark stays.
  leases    (client snapshot, per site) — a COMPLETE snapshot only (every
            page read, the gateway online):
              * outage (gap > 3 polls): never bridged — open rows close at the
                last good poll, unless the client is provably continuous
                (same IP, connectedAt <= the last good poll);
              * same MAC, same IP, connectedAt <= prev: nothing to write (the
                watermark extends it); connectedAt > prev: a RECONNECT — the
                row closes at prev (slack up to connectedAt) and reopens at
                connectedAt (exact): the hole gives no pick (G10);
              * a new holder: opens at connectedAt (exact) when it falls in
                (prev, p], else at mid(prev, p) with slack — or at the exact
                time of a system-log join for that MAC and IP in the window;
              * the old holder of an IP closes at mid(prev, p) WITH slack
                (G10: a sampled close always says so), clamped to the new
                holder's exact start;
              * absent → closes at mid(prev, p) with slack;
              * day-chunked: a continuing row is split at 00:00Z (exact), so
                no row spans much more than a day and every "at T" scan is
                bounded.
            A failed or partial snapshot writes the attempt only.
  joins     system-log CLIENT_* events (MAC, IP, name, uplink, time): exact
            edges, the ±20 s join heuristic, ghosts (a join no lease covers),
            the MAC-anomaly rule's evidence.
  conflicts CLIENT_IP_CONFLICT as a time-bounded fact (`lk_ip_conflict`):
            never a flag on a whole lease row (a rollover would carry it on).
  subnets   the networks' CIDR, VLAN, purpose and DHCP DNS path. A network
            is only ever filtered out of NextDNS candidates on POSITIVE
            evidence of a bypass (every DHCP DNS server public and not a
            NextDNS resolver): a LAN resolver (a domain controller, a Pi-hole,
            another VLAN's gateway) or a mixed list may well forward to NextDNS
            and is `unknown` (never filtered).

The MAC-ANOMALY rule (G2 / M1, Rick's safeguard for MAC auto-linking): two
machines using one global MAC. Triggers:
  * two_ips             a join with another IP while UniFi says the same client
                        stayed connected through it (connectedAt before it);
  * wired_and_wireless  a join on the other medium, same condition;
  * uplink_flap         a WIRED client that switches between the same two
                        uplinks more than twice within an hour (a clone on
                        another switch keeps the same IP and medium; wireless
                        roaming between two access points is normal and is
                        not counted).
Every join is checked exactly once, against the snapshot(s) covering it —
whenever the log line arrives (a late log is checked at the next snapshot,
or at once against the leases when a snapshot already covered it). The
finding is TIME-BOUNDED (`lk_mac_anomaly` from / to: D3 gives no pick for that
MAC near it), answers that relied on the MAC's leases are re-queued (stale),
and one MEDIUM "possible MAC impersonation" signal is raised (handed back to
the UniFi poller, which stores it as a UniFi signal).

Every function takes ONE open connection to ONE tenant's entities.db, inside
the caller's transaction.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import sqlite3
from dataclasses import dataclass, field
from typing import Any, Optional

from apps.octo.entity import normalize as nz

SKEW_S = 5
GAP_POLLS = 3
DEFAULT_POLL_S = 300
JOIN_EVENTS = frozenset({"CLIENT_CONNECTED_WIRED", "CLIENT_CONNECTED_WIRELESS",
                         "HOTSPOT_GUEST_AUTHORIZED", "TELEPORT_CLIENT_CONNECTED"})
LEAVE_EVENTS = frozenset({"CLIENT_DISCONNECTED_WIRED", "CLIENT_DISCONNECTED_WIRELESS",
                          "TELEPORT_CLIENT_DISCONNECTED"})
CONFLICT_EVENTS = frozenset({"CLIENT_IP_CONFLICT"})
WIRED_JOIN = "CLIENT_CONNECTED_WIRED"
ANOMALY_JOINS = frozenset({"CLIENT_CONNECTED_WIRED", "CLIENT_CONNECTED_WIRELESS"})
# A join and the client record it is compared with may be a few seconds
# apart (the join is logged after DHCP).
JOIN_TOLERANCE_S = 30
CONFLICT_WINDOW_S = 600
FLAP_WINDOW_S = 3600
FLAP_CHANGES = 2                 # MORE than this many changes within the window
ANOMALY_MERGE_S = 3600           # one finding per MAC + kind per episode
# NextDNS's own resolver ranges (a network whose DHCP hands these out queries
# NextDNS directly): bundle configuration, never a constant in the code —
# `OCTO_NEXTDNS_RESOLVER_NETS`, comma-separated CIDRs
# (docs/operations/bundle.md, v0.13). Unset: a public DHCP DNS server cannot
# be told apart from NextDNS, so no network is classed as bypassing it
# (nothing is filtered on a guess).
RESOLVER_NETS_ENV = "OCTO_NEXTDNS_RESOLVER_NETS"
_resolver_cache: tuple[str, tuple[Any, ...]] = ("", ())


def resolver_nets() -> tuple[Any, ...]:
    global _resolver_cache
    raw = os.environ.get(RESOLVER_NETS_ENV, "").strip()
    if raw == _resolver_cache[0]:
        return _resolver_cache[1]
    nets = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            continue
    _resolver_cache = (raw, tuple(nets))
    return _resolver_cache[1]


def _sha12(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()[:12]


# ---------------------------------------------------------------------------
# Watermarks — per (source, scope), per SITE (G7)
# ---------------------------------------------------------------------------

def watermark(conn: sqlite3.Connection, source: str, scope: str) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM lk_watermark WHERE source = ? AND scope = ?",
                        (source, scope)).fetchone()


def watermark_ok(conn: sqlite3.Connection, source: str, scope: str, at: str) -> Optional[str]:
    """A complete, fresh observation at `at`. Returns the previous one."""
    row = watermark(conn, source, scope)
    prev = row["last_ok_at"] if row is not None else None
    if prev is not None and at <= prev:
        conn.execute("UPDATE lk_watermark SET last_attempt_at = ?, last_error = NULL "
                     "WHERE source = ? AND scope = ?", (at, source, scope))
        return prev
    conn.execute(
        "INSERT INTO lk_watermark (source, scope, last_ok_at, prev_ok_at, last_attempt_at, "
        " last_error) VALUES (?, ?, ?, ?, ?, NULL) ON CONFLICT (source, scope) DO UPDATE SET "
        " prev_ok_at = lk_watermark.last_ok_at, last_ok_at = excluded.last_ok_at, "
        " last_attempt_at = excluded.last_attempt_at, last_error = NULL",
        (source, scope, at, prev, at))
    return prev


def watermark_failed(conn: sqlite3.Connection, source: str, scope: str, at: str,
                     error: str) -> None:
    """An attempt that observed nothing: the watermark does NOT move."""
    conn.execute(
        "INSERT INTO lk_watermark (source, scope, last_ok_at, prev_ok_at, last_attempt_at, "
        " last_error) VALUES (?, ?, NULL, NULL, ?, ?) ON CONFLICT (source, scope) DO UPDATE SET "
        " last_attempt_at = excluded.last_attempt_at, last_error = excluded.last_error",
        (source, scope, at, error[:300]))


def _gap(prev: Optional[str], p: str, poll_s: float) -> bool:
    return prev is not None and nz.seconds_between(prev, p) > GAP_POLLS * poll_s


# ---------------------------------------------------------------------------
# Egress (fleet report)
# ---------------------------------------------------------------------------

@dataclass
class EgressResult:
    observed: bool
    opened: int = 0
    closed: int = 0


def apply_site_report(conn: sqlite3.Connection, *, site_id: str, scope: str,
                      report: dict[str, Any], poll_s: float = DEFAULT_POLL_S) -> EgressResult:
    p = nz.ts(report.get("polled_at"))
    if not p:
        return EgressResult(False)
    if report.get("report_fresh") is False or report.get("host_connected") is False:
        watermark_failed(conn, "unifi.sites", scope, p, "console not connected to UniFi's cloud")
        return EgressResult(False)
    if report.get("gateway_online") is False:
        watermark_failed(conn, "unifi.sites", scope, p, "the site's gateway is offline")
        return EgressResult(False)
    wm = watermark(conn, "unifi.sites", scope)
    prev = wm["last_ok_at"] if wm is not None else None
    if prev is not None and p <= prev:
        return EgressResult(True)
    out = EgressResult(True)
    ref = f"snap:unifi.sites:{scope}:{p}:{_sha12(report.get('wans'))}"
    open_rows = conn.execute(
        "SELECT * FROM lk_site_egress WHERE vendor_scope_id = ? AND source = 'unifi.sites' "
        "AND valid_to IS NULL ORDER BY id", (scope,)).fetchall()
    if _gap(prev, p, poll_s):
        for r in open_rows:
            conn.execute("UPDATE lk_site_egress SET valid_to = ?, to_exact = 0, to_slack_s = 0, "
                         "close_reason = 'gap' WHERE id = ?", (prev, r["id"]))
            out.closed += 1
        open_rows = []
    by_wan = {r["wan"]: r for r in open_rows}
    if prev is not None and open_rows:
        mid, slack = nz.midpoint(prev, p), int(nz.seconds_between(prev, p) / 2) + SKEW_S
    else:
        mid, slack = p, 0
    seen: set[str] = set()
    for w in report.get("wans") or []:
        if not isinstance(w, dict):
            continue
        addr = nz.ip(w.get("external_ip"))
        wan = str(w.get("wan") or "WAN")[:16]
        if not addr or not nz.is_public(addr):
            continue
        full = 32 if ":" not in addr else 128
        plen = w.get("prefix_len")
        # An IPv6 delegated prefix ("<WAN>/pd") is a network, else one address.
        plen = plen if isinstance(plen, int) and not isinstance(plen, bool) and \
            ":" in addr and 32 <= plen <= 128 else full
        seen.add(wan)
        nat = w.get("nat_kind") if w.get("nat_kind") in ("direct", "cgnat", "double_nat") \
            else "unknown"
        flags = sorted({"shared_external"} if w.get("shared_external") else set())
        asn = w.get("asn") if isinstance(w.get("asn"), int) else None
        isp = str(w.get("isp"))[:80] if w.get("isp") else None
        row = by_wan.get(wan)
        if row is not None and row["addr"] == addr and int(row["prefix_len"]) == plen:
            conn.execute(
                "UPDATE lk_site_egress SET samples = samples + 1, nat_kind = ?, flags = ?, "
                " asn = COALESCE(?, asn), isp = COALESCE(?, isp) WHERE id = ?",
                (nat, json.dumps(sorted(set(json.loads(row["flags"] or "[]")) | set(flags))),
                 asn, isp, row["id"]))
            continue
        if row is not None:
            conn.execute("UPDATE lk_site_egress SET valid_to = ?, to_exact = 0, to_slack_s = ?, "
                         "close_reason = 'changed' WHERE id = ?", (mid, slack, row["id"]))
            out.closed += 1
        start, start_slack = (mid, slack) if row is not None else (p, 0)
        conn.execute(
            "INSERT INTO lk_site_egress (site_id, vendor_scope_id, addr, prefix_len, wan, "
            " nat_kind, asn, isp, source, valid_from, from_exact, from_slack_s, flags, "
            " source_ref) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'unifi.sites', ?, 0, ?, ?, ?)",
            (site_id, scope, addr, plen, wan, nat, asn, isp,
             start, start_slack, json.dumps(flags), ref))
        out.opened += 1
    for wan, row in by_wan.items():
        if wan not in seen:
            conn.execute("UPDATE lk_site_egress SET valid_to = ?, to_exact = 0, to_slack_s = ?, "
                         "close_reason = 'absent' WHERE id = ?", (mid, slack, row["id"]))
            out.closed += 1
    watermark_ok(conn, "unifi.sites", scope, p)
    return out


def egress_network(row: Any) -> Optional[Any]:
    """An egress row as an `ipaddress` network (an IPv4 / IPv6 address is a
    /32 / /128; an IPv6 delegated prefix keeps its length)."""
    try:
        return ipaddress.ip_network(f"{row['addr']}/{int(row['prefix_len'])}", strict=False)
    except (ValueError, TypeError, KeyError, IndexError):
        return None


def egress_contains(row: Any, ip: str) -> bool:
    net = egress_network(row)
    if net is None:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.version == net.version and addr in net


def egress_key(row: Any) -> str:
    """How an egress is named in per-IP counts: the address, or
    "<prefix>/<len>" for an IPv6 delegated prefix."""
    plen = int(row["prefix_len"])
    return row["addr"] if plen in (32, 128) else f"{row['addr']}/{plen}"


def assert_egress(conn: sqlite3.Connection, *, site_id: str, addr: str, valid_from: str,
                  valid_to: Optional[str], asserted_by: str, reason: str,
                  nat_kind: str = "direct", flags: Optional[list[str]] = None) -> int:
    """An admin says "this public address is this site's internet" — for a
    site without UniFi (bounded interval, audited by the caller)."""
    cur = conn.execute(
        "INSERT INTO lk_site_egress (site_id, vendor_scope_id, addr, prefix_len, nat_kind, "
        " source, valid_from, from_exact, valid_to, to_exact, flags, source_ref, asserted_by, "
        " reason) VALUES (?, '', ?, ?, ?, 'operator', ?, 1, ?, ?, ?, ?, ?, ?)",
        (site_id, addr, 32 if ":" not in addr else 128, nat_kind, valid_from, valid_to,
         1 if valid_to else 0, json.dumps(sorted(flags or [])), f"operator:{asserted_by}",
         asserted_by, reason[:500]))
    return int(cur.lastrowid)


def close_scope(conn: sqlite3.Connection, scope: str, at: str, reason: str = "unmapped",
                poll_s: float = DEFAULT_POLL_S) -> int:
    """A UniFi site that left this tenant: every open egress / lease / subnet
    row of it closes at the scope's LAST OBSERVATION of that feed (its
    watermark) — never at `at`, the moment the unmap was noticed, which may
    be long after the feed stopped (an outage, a tenant switched off): an
    unmap never bridges a gap into a confident answer. Sampled edges
    (to_exact 0, no margin after the last observation); the reason is 'gap'
    when that observation is older than 3 polls. History stays until
    retention."""
    def mark(source: str) -> Optional[str]:
        row = watermark(conn, source, scope)
        return row["last_ok_at"] if row is not None and row["last_ok_at"] else None

    def why(last: Optional[str]) -> str:
        if last is None or nz.seconds_between(last, at) > GAP_POLLS * poll_s:
            return "gap"
        return reason

    sites_at, clients_at = mark("unifi.sites"), mark("unifi.clients")
    n = conn.execute(
        "UPDATE lk_site_egress SET valid_to = MAX(valid_from, COALESCE(?, valid_from)), "
        " to_exact = 0, to_slack_s = 0, close_reason = ? "
        "WHERE vendor_scope_id = ? AND valid_to IS NULL",
        (sites_at, why(sites_at), scope)).rowcount
    n += conn.execute(
        "UPDATE lk_ip_lease SET valid_to = MAX(valid_from, COALESCE(?, valid_from)), "
        " to_exact = 0, to_slack_s = 0, close_reason = ? "
        "WHERE vendor_scope_id = ? AND valid_to IS NULL",
        (clients_at, why(clients_at), scope)).rowcount
    seen = [m for m in (sites_at, clients_at, mark("unifi.networks")) if m]
    last = max(seen) if seen else None
    n += conn.execute(
        "UPDATE lk_site_subnet SET valid_to = MAX(valid_from, COALESCE(?, valid_from)) "
        "WHERE vendor_scope_id = ? AND valid_to IS NULL", (last, scope)).rowcount
    return n


# ---------------------------------------------------------------------------
# Subnets (networks)
# ---------------------------------------------------------------------------

_PURPOSE = {"corporate": "corporate", "guest": "guest", "remote-user-vpn": "vpn",
            "vlan-only": "unknown"}


def _dns_path(net: dict[str, Any], cidr: Any) -> str:
    """gateway | nextdns | other (POSITIVE evidence of a bypass: every DHCP
    DNS server is public and not a NextDNS resolver) | unknown (a LAN
    resolver — a domain controller, a Pi-hole, another VLAN's gateway — or a
    mixed list: it may well forward to NextDNS, so it is never filtered)."""
    if not net.get("dhcpd_dns_enabled"):
        return "gateway"            # UniFi's default: the gateway is the DNS server
    servers = [nz.ip(net.get(f"dhcpd_dns_{i}")) for i in range(1, 5)]
    servers = [s for s in servers if s]
    if not servers:
        return "gateway"
    nets = resolver_nets()
    kinds = set()
    for s in servers:
        addr = ipaddress.ip_address(s)
        if addr.version == cidr.version and addr in cidr:
            kinds.add("gateway")            # an address on the network itself
        elif any(addr.version == n.version and addr in n for n in nets):
            kinds.add("nextdns")
        elif nz.is_public(s) and nets:
            kinds.add("bypass")             # a public resolver that is not NextDNS
        else:
            kinds.add("unknown")            # a LAN resolver, or NextDNS's ranges unknown
    if len(kinds) != 1:
        return "unknown"
    kind = kinds.pop()
    return {"bypass": "other"}.get(kind, kind)


def apply_networks(conn: sqlite3.Connection, *, site_id: str, scope: str,
                   networks: list[dict[str, Any]], at: str) -> int:
    current = []
    for net in networks or []:
        if not isinstance(net, dict) or not net.get("ip_subnet"):
            continue
        purpose_raw = str(net.get("purpose") or "")
        if purpose_raw in ("wan", "site-vpn", "vpn-client"):
            continue
        try:
            cidr = ipaddress.ip_network(str(net.get("ip_subnet")), strict=False)
        except ValueError:
            continue
        vlan = net.get("vlan") if isinstance(net.get("vlan"), int) else None
        current.append((str(net.get("_id") or "")[:64] or None, str(net.get("name") or "")[:80],
                        str(cidr), vlan, _PURPOSE.get(purpose_raw, "unknown"),
                        _dns_path(net, cidr)))
    open_rows = conn.execute("SELECT * FROM lk_site_subnet WHERE vendor_scope_id = ? AND "
                             "valid_to IS NULL", (scope,)).fetchall()
    have = {(r["net_id"], r["name"], r["cidr"], r["vlan"], r["purpose"], r["dns_path"]): r
            for r in open_rows}
    changed = 0
    for key, row in have.items():
        if key not in current:
            conn.execute("UPDATE lk_site_subnet SET valid_to = ? WHERE id = ?", (at, row["id"]))
            changed += 1
    for key in current:
        if key not in have:
            conn.execute(
                "INSERT INTO lk_site_subnet (site_id, vendor_scope_id, net_id, name, cidr, vlan, "
                " purpose, dns_path, valid_from, source) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, "
                " 'unifi.networks')", (site_id, scope, *key, at))
            changed += 1
    watermark_ok(conn, "unifi.networks", scope, at)
    if changed:
        _refresh_open_leases(conn, site_id, scope)
    return changed


def _refresh_open_leases(conn: sqlite3.Connection, site_id: str, scope: str) -> int:
    """Subnets arrived or changed: every OPEN lease of the scope gets its
    network and guest mark from them (a guest lease stored before the
    networks were read would otherwise keep 90 days, not 7)."""
    n = 0
    for r in conn.execute("SELECT id, ip, net_id, is_guest FROM lk_ip_lease WHERE "
                          "vendor_scope_id = ? AND valid_to IS NULL", (scope,)).fetchall():
        sub = subnet_of(conn, site_id, r["ip"])
        if sub is None:
            continue
        guest = 1 if sub["purpose"] == "guest" else 0
        if r["net_id"] != sub["net_id"] or int(r["is_guest"]) != guest:
            conn.execute("UPDATE lk_ip_lease SET net_id = ?, is_guest = ? WHERE id = ?",
                         (sub["net_id"], guest, r["id"]))
            n += 1
    return n


def subnet_of(conn: sqlite3.Connection, site_id: str, ip: Optional[str],
              at: Optional[str] = None) -> Optional[sqlite3.Row]:
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    sql = "SELECT * FROM lk_site_subnet WHERE site_id = ?"
    args: list[Any] = [site_id]
    if at is None:
        sql += " AND valid_to IS NULL"
    else:
        # Valid at T — or, for a T before the networks were first read, the
        # earliest configuration known after it (networks rarely change).
        sql += " AND (valid_to IS NULL OR valid_to > ?)"
        args += [at]
    best = None
    for r in conn.execute(sql + " ORDER BY id", args).fetchall():
        try:
            net = ipaddress.ip_network(r["cidr"])
        except ValueError:
            continue
        if addr.version == net.version and addr in net:
            if best is None or net.prefixlen > ipaddress.ip_network(best["cidr"]).prefixlen:
                best = r
    return best


# ---------------------------------------------------------------------------
# Joins (system log)
# ---------------------------------------------------------------------------

@dataclass
class LogResult:
    joins: int = 0
    closes: int = 0
    conflicts: int = 0
    anomalies: list[int] = field(default_factory=list)


def apply_log_events(conn: sqlite3.Connection, *, site_id: str, scope: str,
                     events: list[dict[str, Any]], poll_s: float = DEFAULT_POLL_S) -> LogResult:
    out = LogResult()
    wired_joins: list[tuple[str, str, str]] = []
    for ev in events or []:
        if not isinstance(ev, dict):
            continue
        name = str(ev.get("event") or "")
        at = nz.ts(ev.get("ts_ms")) if isinstance(ev.get("ts_ms"), int) else nz.ts(ev.get("time"))
        vid = str(ev.get("id") or "")[:128]
        client = ev.get("client") if isinstance(ev.get("client"), dict) else {}
        mac = nz.mac(client.get("mac"))
        ip = nz.ip(client.get("ip"))
        if not at or not vid:
            continue
        if name in JOIN_EVENTS or name in LEAVE_EVENTS:
            label = str(client.get("hostname") or client.get("name") or "")[:120] or None
            uplink = str(client.get("uplink") or "")[:120] or None
            cur = conn.execute(
                "INSERT OR IGNORE INTO lk_join (site_id, vendor_scope_id, event, mac, ip, "
                " name_obs, uplink, at, vendor_event_id, checked) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (site_id, scope, name, mac, ip, label, uplink, at, vid,
                 0 if name in ANOMALY_JOINS and mac else 1))
            if cur.rowcount:
                out.joins += 1
                if name == WIRED_JOIN and mac and uplink and nz.mac_kind(mac) == "global":
                    wired_joins.append((at, mac, uplink))
            if name in LEAVE_EVENTS and mac and cur.rowcount:
                # An exact END for the client's open lease (a later snapshot
                # reopens it if it is back).
                n = conn.execute(
                    "UPDATE lk_ip_lease SET valid_to = ?, to_exact = 1, to_slack_s = 0, "
                    " close_reason = 'disconnect_event' WHERE vendor_scope_id = ? AND mac = ? "
                    " AND valid_to IS NULL AND valid_from <= ?", (at, scope, mac, at)).rowcount
                out.closes += n
        elif name in CONFLICT_EVENTS and ip:
            # A time-bounded fact: D3 gives no pick for this address within
            # ±10 minutes of it — never a flag on the whole lease row.
            cur = conn.execute(
                "INSERT OR IGNORE INTO lk_ip_conflict (site_id, vendor_scope_id, ip, at, "
                " vendor_event_id) VALUES (?, ?, ?, ?, ?)", (site_id, scope, ip, at, vid))
            if cur.rowcount:
                out.conflicts += 1
                stale_dependants(conn, [r["id"] for r in conn.execute(
                    "SELECT id FROM lk_ip_lease WHERE site_id = ? AND ip = ? AND valid_from <= ? "
                    "AND (valid_to IS NULL OR valid_to >= ?)",
                    (site_id, ip, nz.shift(at, CONFLICT_WINDOW_S),
                     nz.shift(at, -CONFLICT_WINDOW_S))).fetchall()])
    for at, mac, uplink in sorted(wired_joins):
        found = note_uplink(conn, site_id=site_id, scope=scope, mac=mac, source="log",
                            uplink=uplink, at=at)
        if found is not None:
            out.anomalies.append(found)
    # Joins a snapshot has already covered are checked NOW against the
    # leases it left (a late log line is never missed); later ones wait for
    # the next snapshot.
    wm = watermark(conn, "unifi.clients", scope)
    if wm is not None and wm["last_ok_at"]:
        out.anomalies += check_joins_against_leases(conn, site_id=site_id, scope=scope,
                                                    upto=wm["last_ok_at"])
    return out


def log_progress(conn: sqlite3.Connection, scope: str, scanned_to: str) -> None:
    """The system log of the site is read whole up to `scanned_to`."""
    watermark_ok(conn, "unifi.syslog", scope, scanned_to)


# ---------------------------------------------------------------------------
# Leases (client snapshot)
# ---------------------------------------------------------------------------

@dataclass
class SnapshotResult:
    observed: bool
    opened: int = 0
    closed: int = 0
    unchanged: int = 0
    anomalies: list[int] = field(default_factory=list)


def _conn_kind(value: Any) -> str:
    text = str(value or "").upper()
    if text.startswith("WIRED"):
        return "wired"
    if text.startswith("WIRELESS"):
        return "wireless"
    if "TELEPORT" in text:
        return "teleport"
    if "VPN" in text:
        return "vpn"
    return "unknown"


def _close(conn: sqlite3.Connection, row_id: int, at: str, *, exact: bool, slack: int,
           reason: str) -> None:
    conn.execute("UPDATE lk_ip_lease SET valid_to = ?, to_exact = ?, to_slack_s = ?, "
                 "close_reason = ? WHERE id = ?",
                 (at, 1 if exact else 0, 0 if exact else int(slack), reason, int(row_id)))


def _open(conn: sqlite3.Connection, *, site_id: str, scope: str, c: dict[str, Any], start: str,
          exact: bool, slack: int, source_ref: str, guest: bool, net_id: Optional[str],
          tokens: Any) -> int:
    mac = c.get("mac")
    cur = conn.execute(
        "INSERT INTO lk_ip_lease (site_id, vendor_scope_id, net_id, ip, mac, mac_tok, mac_kind, "
        " vendor_client_id, name_obs, name_tok, conn, is_guest, uplink_ref, connected_at, "
        " valid_from, from_exact, from_slack_s, source, source_ref) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'unifi.clients', ?)",
        (site_id, scope, net_id, c["ip"], mac, tokens("mac", mac) if mac else None,
         nz.mac_kind(mac), c.get("id"), c.get("name"),
         tokens("name", nz.name_key(c.get("name")) or "") if c.get("name") else None,
         _conn_kind(c.get("type")), 1 if guest else 0, c.get("uplink_device_id"),
         c.get("connected_at"), start, 1 if exact else 0, 0 if exact else int(slack),
         source_ref))
    return int(cur.lastrowid)


def apply_client_snapshot(conn: sqlite3.Connection, *, site_id: str, scope: str,
                          snapshot: dict[str, Any], tokens: Any,
                          poll_s: float = DEFAULT_POLL_S) -> SnapshotResult:
    """`tokens(kind, value)` = the tenant's token function."""
    p = nz.ts(snapshot.get("polled_at"))
    if not p:
        return SnapshotResult(False)
    if not snapshot.get("complete") or snapshot.get("gateway_online") is False:
        # G7: a list read while the gateway is offline shows last-known IPs.
        watermark_failed(conn, "unifi.clients", scope, p,
                         "gateway offline" if snapshot.get("gateway_online") is False
                         else "snapshot incomplete")
        return SnapshotResult(False)
    wm = watermark(conn, "unifi.clients", scope)
    prev = wm["last_ok_at"] if wm is not None else None
    if prev is not None and p <= prev:
        return SnapshotResult(True)
    out = SnapshotResult(True)
    ref = f"snap:unifi.clients:{scope}:{p}:{_sha12(sorted(str(c) for c in snapshot.get('clients') or []))}"

    clients: dict[str, dict[str, Any]] = {}
    for raw in snapshot.get("clients") or []:
        if not isinstance(raw, dict):
            continue
        ip = nz.ip(raw.get("ip"))
        mac = nz.mac(raw.get("mac"))
        if not ip or not (mac or raw.get("id")):
            continue
        connected = nz.ts(raw.get("connected_at"))
        if connected and connected > p:
            connected = None            # a console clock ahead of ours: not exact
        key = mac or f"id:{raw.get('id')}"
        clients[key] = {"ip": ip, "mac": mac, "id": (str(raw.get("id"))[:64] or None)
                        if raw.get("id") else None,
                        "name": str(raw.get("name"))[:120] if raw.get("name") else None,
                        "type": raw.get("type"), "uplink_device_id": raw.get("uplink_device_id"),
                        "connected_at": connected}

    def key_of(row: sqlite3.Row) -> str:
        return row["mac"] or f"id:{row['vendor_client_id']}"

    open_rows = conn.execute("SELECT * FROM lk_ip_lease WHERE vendor_scope_id = ? AND "
                             "valid_to IS NULL ORDER BY id", (scope,)).fetchall()
    gap = _gap(prev, p, poll_s)
    gap_prev: Optional[str] = None
    if gap:
        assert prev is not None
        gap_prev = prev
        kept = []
        for r in open_rows:
            c = clients.get(key_of(r))
            if (c is not None and c["ip"] == r["ip"] and c["connected_at"]
                    and c["connected_at"] <= prev):
                kept.append(r)                  # provably continuous through the outage
                continue
            _close(conn, r["id"], prev, exact=False, slack=0, reason="gap")
            out.closed += 1
        open_rows = kept
        prev = None                             # the window starts again at p

    # Day-chunking: a continuing row is split at 00:00Z.
    midnight = nz.day_start(p)
    rolled = []
    for r in open_rows:
        c = clients.get(key_of(r))
        if r["valid_from"] < midnight and c is not None and c["ip"] == r["ip"] and \
                not (c["connected_at"] and prev is not None and c["connected_at"] > prev):
            _close(conn, r["id"], midnight, exact=True, slack=0, reason="rollover")
            subnet = subnet_of(conn, site_id, r["ip"])
            # A conflict / anomaly is a time-bounded fact of its own: nothing
            # is carried over to the new day's row.
            new_id = _open(conn, site_id=site_id, scope=scope, c=c, start=midnight, exact=True,
                           slack=0, source_ref=ref,
                           guest=bool(subnet is not None and subnet["purpose"] == "guest"),
                           net_id=subnet["net_id"] if subnet is not None else r["net_id"],
                           tokens=tokens)
            rolled.append(conn.execute("SELECT * FROM lk_ip_lease WHERE id = ?",
                                       (new_id,)).fetchone())
        else:
            rolled.append(r)
    open_rows = rolled

    by_key = {key_of(r): r for r in open_rows}
    by_ip: dict[str, list[sqlite3.Row]] = {}
    for r in open_rows:
        by_ip.setdefault(r["ip"], []).append(r)
    if prev is not None:
        mid = nz.midpoint(prev, p)
        slack = int(nz.seconds_between(prev, p) / 2) + SKEW_S
    else:
        mid, slack = p, 0
    closed_ids: set[int] = set()

    def exact_join(c: dict[str, Any]) -> Optional[str]:
        if prev is None or not c.get("mac"):
            return None
        row = conn.execute(
            "SELECT at FROM lk_join WHERE vendor_scope_id = ? AND mac = ? AND ip = ? AND at > ? "
            "AND at <= ? AND event IN ('CLIENT_CONNECTED_WIRED','CLIENT_CONNECTED_WIRELESS',"
            "'HOTSPOT_GUEST_AUTHORIZED','TELEPORT_CLIENT_CONNECTED') ORDER BY at DESC LIMIT 1",
            (scope, c["mac"], c["ip"], prev, p)).fetchone()
        return row["at"] if row else None

    for key in sorted(clients):
        c = clients[key]
        row = by_key.get(key)
        subnet = subnet_of(conn, site_id, c["ip"])
        guest = bool(subnet is not None and subnet["purpose"] == "guest")
        net_id = subnet["net_id"] if subnet is not None else None
        connected = c["connected_at"]
        if row is not None and row["ip"] == c["ip"] and row["id"] not in closed_ids:
            if prev is not None and connected and connected > prev and \
                    (row["connected_at"] is None or connected != row["connected_at"]):
                # A reconnect between polls with the same IP: the hole
                # [prev, connectedAt] gives no pick (G10).
                _close(conn, row["id"], prev, exact=False,
                       slack=int(nz.seconds_between(prev, connected)), reason="reconnect")
                closed_ids.add(row["id"])
                out.closed += 1
                _open(conn, site_id=site_id, scope=scope, c=c, start=connected, exact=True,
                      slack=0, source_ref=ref, guest=guest, net_id=net_id, tokens=tokens)
                out.opened += 1
            else:
                conn.execute(
                    "UPDATE lk_ip_lease SET name_obs = COALESCE(?, name_obs), "
                    " connected_at = COALESCE(?, connected_at), uplink_ref = COALESCE(?, uplink_ref) "
                    "WHERE id = ?", (c.get("name"), connected, c.get("uplink_device_id"), row["id"]))
                out.unchanged += 1
            continue
        # A new holder of this IP (or this client on a new IP).
        if prev is not None:
            joined = exact_join(c)
            if connected and prev < connected <= p:
                start, exact, start_slack = connected, True, 0
            elif joined:
                start, exact, start_slack = joined, True, 0
            else:
                start, exact, start_slack = mid, False, slack
        elif gap_prev is not None:
            # After an outage: never bridged — from connectedAt when it is
            # inside the outage-to-now window, else from now.
            if connected and gap_prev < connected <= p:
                start, exact, start_slack = connected, True, 0
            else:
                start, exact, start_slack = p, False, 0
        elif connected:
            # The first snapshot: connectedAt proves presence since then (V1),
            # day-chunked at 00:00Z.
            start, exact, start_slack = max(connected, nz.day_start(p)), True, 0
        else:
            start, exact, start_slack = p, False, 0
        end_at = start if exact else mid
        if row is not None and row["id"] not in closed_ids:
            _close(conn, row["id"], min(end_at, mid) if exact else mid, exact=False,
                   slack=slack, reason="ip_changed")
            closed_ids.add(row["id"])
            out.closed += 1
        for other in by_ip.get(c["ip"], []):
            if other["id"] in closed_ids or key_of(other) == key:
                continue
            _close(conn, other["id"], min(end_at, mid) if exact else mid, exact=False,
                   slack=slack, reason="mac_changed")
            closed_ids.add(other["id"])
            out.closed += 1
        _open(conn, site_id=site_id, scope=scope, c=c, start=start, exact=exact,
              slack=start_slack, source_ref=ref, guest=guest, net_id=net_id, tokens=tokens)
        out.opened += 1

    for key, row in by_key.items():
        if key not in clients and row["id"] not in closed_ids:
            _close(conn, row["id"], mid, exact=False, slack=slack, reason="absent")
            closed_ids.add(row["id"])
            out.closed += 1
    watermark_ok(conn, "unifi.clients", scope, p)
    for key in sorted(clients):
        c = clients[key]
        if c.get("mac") and c.get("uplink_device_id") and _conn_kind(c.get("type")) == "wired" \
                and nz.mac_kind(c["mac"]) == "global":
            found = note_uplink(conn, site_id=site_id, scope=scope, mac=c["mac"],
                                source="snapshot", uplink=str(c["uplink_device_id"])[:120], at=p)
            if found is not None:
                out.anomalies.append(found)
    out.anomalies += check_anomalies(conn, site_id=site_id, scope=scope, clients=clients,
                                     window_to=p)
    return out


# ---------------------------------------------------------------------------
# The MAC-anomaly rule (M1)
# ---------------------------------------------------------------------------

def stale_dependants(conn: sqlite3.Connection, lease_ids: list[int]) -> int:
    """Stored answers that relied on these lease rows are re-queued (`stale`:
    the worker redoes them) — a conflict or an anomaly found AFTER an answer
    was given still reaches it."""
    ids = sorted({str(int(i)) for i in lease_ids})
    n = 0
    for k in range(0, len(ids), 500):
        part = ids[k:k + 500]
        marks = ",".join("?" * len(part))
        n += conn.execute(
            "UPDATE resolution SET status = 'stale' WHERE status IN ('final','provisional') AND "
            f"res_id IN (SELECT res_id FROM resolution_dep WHERE dep_kind = 'lease' AND dep_id IN "
            f"({marks}))", part).rowcount
    return n


def _record_anomaly(conn: sqlite3.Connection, *, site_id: str, scope: str, mac: str, kind: str,
                    from_ts: str, to_ts: str, detail: dict[str, Any], now: str) -> Optional[int]:
    """One finding per MAC + kind per episode: a finding within an hour of an
    earlier one widens it (no second signal). Returns a NEW finding's id."""
    prior = conn.execute(
        "SELECT id, from_ts, to_ts FROM lk_mac_anomaly WHERE site_id = ? AND mac = ? AND kind = ? "
        "AND to_ts >= ? AND from_ts <= ? ORDER BY id DESC LIMIT 1",
        (site_id, mac, kind, nz.shift(from_ts, -ANOMALY_MERGE_S),
         nz.shift(to_ts, ANOMALY_MERGE_S))).fetchone()
    new_id: Optional[int] = None
    if prior is not None:
        conn.execute("UPDATE lk_mac_anomaly SET from_ts = MIN(from_ts, ?), to_ts = MAX(to_ts, ?) "
                     "WHERE id = ?", (from_ts, to_ts, prior["id"]))
        lo, hi = min(from_ts, prior["from_ts"]), max(to_ts, prior["to_ts"])
    else:
        cur = conn.execute(
            "INSERT OR IGNORE INTO lk_mac_anomaly (site_id, vendor_scope_id, mac, kind, from_ts, "
            " to_ts, detail, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (site_id, scope, mac, kind, from_ts, to_ts, json.dumps(detail, sort_keys=True), now))
        if cur.rowcount:
            new_id = int(cur.lastrowid)
        lo, hi = from_ts, to_ts
    # Effects: answers that picked this MAC's leases near the finding are
    # redone (D3 reads the finding: candidates, never a pick).
    stale_dependants(conn, [r["id"] for r in conn.execute(
        "SELECT id FROM lk_ip_lease WHERE site_id = ? AND mac = ? AND valid_from <= ? "
        "AND (valid_to IS NULL OR valid_to >= ?)",
        (site_id, mac, nz.shift(hi, ANOMALY_MERGE_S), nz.shift(lo, -ANOMALY_MERGE_S))).fetchall()])
    return new_id


def _verdict(j: sqlite3.Row, ip: Optional[str], medium: str) -> Optional[tuple[str, dict]]:
    """A join against the client record UniFi says stayed connected through
    it (IP `ip`, medium `medium`): the anomaly kind + detail, or None."""
    if j["ip"] and ip and j["ip"] != ip:
        return "two_ips", {"ips": sorted({j["ip"], ip})}
    joined = "wired" if j["event"].endswith("WIRED") else "wireless"
    if medium in ("wired", "wireless") and medium != joined:
        return "wired_and_wireless", {"snapshot_medium": medium, "join_medium": joined}
    return None


def check_anomalies(conn: sqlite3.Connection, *, site_id: str, scope: str,
                    clients: dict[str, dict[str, Any]], window_to: str) -> list[int]:
    """Every join of the scope not yet checked, at or before this snapshot
    (`window_to`) — however late its log line arrived — against the client
    record of this snapshot: UniFi says the client stayed connected through
    the join (connectedAt before it), yet the join has another IP, or the
    other medium. Each join is checked once. New anomaly ids."""
    found: list[int] = []
    joins = conn.execute(
        "SELECT * FROM lk_join WHERE vendor_scope_id = ? AND checked = 0 AND at <= ? "
        "ORDER BY at, id", (scope, window_to)).fetchall()
    for j in joins:
        conn.execute("UPDATE lk_join SET checked = 1 WHERE id = ?", (j["id"],))
        c = clients.get(j["mac"]) if j["mac"] else None
        if c is None or nz.mac_kind(j["mac"]) != "global":
            continue
        connected = c.get("connected_at")
        if not connected or connected > nz.shift(j["at"], -JOIN_TOLERANCE_S):
            continue            # the client record restarted at / after the join
        verdict = _verdict(j, c["ip"], _conn_kind(c.get("type")))
        if verdict is None:
            continue
        kind, extra = verdict
        new_id = _record_anomaly(
            conn, site_id=site_id, scope=scope, mac=j["mac"], kind=kind, from_ts=j["at"],
            to_ts=window_to, now=window_to,
            detail={"join_event": j["event"], "join_at": j["at"], "snapshot_at": window_to,
                    **extra})
        if new_id is not None:
            found.append(new_id)
    return found


def check_joins_against_leases(conn: sqlite3.Connection, *, site_id: str, scope: str,
                               upto: str) -> list[int]:
    """Joins not yet checked that a snapshot already covered (at <= `upto`,
    the client watermark): checked against the lease rows that snapshot left
    — a row of the MAC holding ANOTHER address (or the other medium) right
    through the join, whose client record had connected before it."""
    found: list[int] = []
    joins = conn.execute(
        "SELECT * FROM lk_join WHERE vendor_scope_id = ? AND checked = 0 AND at <= ? "
        "ORDER BY at, id", (scope, upto)).fetchall()
    for j in joins:
        conn.execute("UPDATE lk_join SET checked = 1 WHERE id = ?", (j["id"],))
        if not j["mac"] or nz.mac_kind(j["mac"]) != "global":
            continue
        rows = conn.execute(
            "SELECT * FROM lk_ip_lease WHERE vendor_scope_id = ? AND mac = ? AND valid_from <= ? "
            "AND (valid_to IS NULL OR valid_to > ?) AND connected_at IS NOT NULL "
            "AND connected_at <= ? ORDER BY id",
            (scope, j["mac"], j["at"], nz.shift(j["at"], JOIN_TOLERANCE_S),
             nz.shift(j["at"], -JOIN_TOLERANCE_S))).fetchall()
        for r in rows:
            verdict = _verdict(j, r["ip"], r["conn"])
            if verdict is None:
                continue
            kind, extra = verdict
            new_id = _record_anomaly(
                conn, site_id=site_id, scope=scope, mac=j["mac"], kind=kind, from_ts=j["at"],
                to_ts=upto, now=upto,
                detail={"join_event": j["event"], "join_at": j["at"], "snapshot_at": upto,
                        **extra})
            if new_id is not None:
                found.append(new_id)
            break
    return found


def note_uplink(conn: sqlite3.Connection, *, site_id: str, scope: str, mac: str, source: str,
                uplink: str, at: str) -> Optional[int]:
    """One uplink observation of a WIRED global MAC. Only a change is
    written (each source compared with itself: snapshot ids and log ids are
    not the same namespace). More than FLAP_CHANGES changes within an hour,
    back and forth between the SAME two uplinks: an `uplink_flap` finding
    (a clone on another switch — same IP, same medium). New finding id."""
    last = conn.execute(
        "SELECT uplink FROM lk_uplink WHERE vendor_scope_id = ? AND mac = ? AND source = ? "
        "AND at <= ? ORDER BY at DESC, id DESC LIMIT 1", (scope, mac, source, at)).fetchone()
    if last is not None and last["uplink"] == uplink:
        return None
    conn.execute(
        "INSERT INTO lk_uplink (site_id, vendor_scope_id, mac, source, uplink, prev_uplink, at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (site_id, scope, mac, source, uplink, last["uplink"] if last is not None else None, at))
    if last is None:
        return None
    changes = conn.execute(
        "SELECT uplink, prev_uplink, at FROM lk_uplink WHERE vendor_scope_id = ? AND mac = ? "
        "AND source = ? AND prev_uplink IS NOT NULL AND at > ? AND at <= ? ORDER BY at, id",
        (scope, mac, source, nz.shift(at, -FLAP_WINDOW_S), at)).fetchall()
    involved = {u for c in changes for u in (c["uplink"], c["prev_uplink"])}
    if len(changes) <= FLAP_CHANGES or len(involved) != 2:
        return None
    return _record_anomaly(
        conn, site_id=site_id, scope=scope, mac=mac, kind="uplink_flap",
        from_ts=changes[0]["at"], to_ts=at, now=at,
        detail={"source": source, "changes": len(changes), "window_s": FLAP_WINDOW_S,
                "uplinks": len(involved)})


def unsignaled_anomalies(conn: sqlite3.Connection, scope: str) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM lk_mac_anomaly WHERE vendor_scope_id = ? AND signaled = 0 "
                        "ORDER BY id", (scope,)).fetchall()
