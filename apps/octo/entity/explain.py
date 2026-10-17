"""The "Why?" panel — a stored chain in plain sentences, DETERMINISTIC (the
same chain always reads the same; the LLM never writes this). Names are read
from the lease rows the chain points at while they exist (device names are
not masked — Rick, 2026-10-01); a chain whose leases were pruned says so.
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any, Optional

TIER_WORDS = {"exact": "EXACT", "strong": "STRONG", "medium": "PROBABLE", "weak": "POSSIBLE",
              "candidate": "CANDIDATES", "suggest": "NAME MATCH ONLY", "conflict": "CONFLICT",
              "none": "NOT IDENTIFIED"}
FLAG_WORDS = {
    "bucket_later_hits": "Later hits in the same hour were counted on this alert — they may "
                         "come from other devices.",
    "location_unverified": "The public address is shared, behind carrier NAT or of unknown "
                           "NAT: it does not prove the device was at the site.",
    "lookup_stale": "UniFi had not reported for this moment when the answer was finalised.",
    "data_gap": "The UniFi feed was down at that moment: this answer has a hole in it.",
    "via_vpn": "The device was connected through a VPN.",
    "egress_unstable": "The site's internet address is shared or behind carrier NAT, so an "
                       "address mismatch does not mean the device was elsewhere.",
    "ip_not_an_egress": "The address was not one of this client's internet connections at "
                        "that time (a laptop away from the office, a VPN, or another network).",
    "shared_in_tenant": "Several of this client's sites share that internet address.",
    "gateway_sourced": "NextDNS saw the lookup through the site's gateway, so the NextDNS app "
                       "devices (they report on their own) are excluded.",
    "lease_overlap": "The LAN address changed hands around that time.",
    "conflict": "UniFi reported an address conflict.",
    "mac_anomaly": "The MAC address behaved like two machines (possible impersonation).",
    "reconnect_hole": "The device reconnected between two polls: its address is not proven "
                      "for that moment.",
    "ghost_join": "A device joined and left between two polls.",
    "no_lease": "No UniFi lease held that address at that time.",
    "mac_mismatch": "The alert's MAC address is not the one UniFi had on that LAN address.",
    "location_unknown": "The site's own internet address at that moment is not known (UniFi "
                        "had not reported, or had a gap): no device list is given.",
    "ipv6_unknown": "The address is IPv6 and the site's IPv6 addresses at that moment are not "
                    "known (UniFi reported only IPv4): the location is unknown, not ruled out.",
}


def _lease_label(conn: Optional[sqlite3.Connection], lease_id: Optional[int]) -> Optional[str]:
    if conn is None or not lease_id:
        return None
    try:
        r = conn.execute("SELECT name_obs, ip, mac, conn FROM lk_ip_lease WHERE id = ?",
                         (int(lease_id),)).fetchone()
    except sqlite3.Error:
        return None
    if r is None:
        return None
    name = r["name_obs"] or "unnamed client"
    return f"{name} ({r['ip']}, {r['conn']})"


def site_label(conn: Optional[sqlite3.Connection], site_id: Optional[str]) -> Optional[str]:
    if conn is None or not site_id:
        return None
    try:
        r = conn.execute("SELECT label FROM site WHERE site_id = ?", (site_id,)).fetchone()
    except sqlite3.Error:
        return None
    return r["label"] if r else None


def hop_text(hop: dict[str, Any], conn: Optional[sqlite3.Connection]) -> str:
    rule = hop.get("rule")
    out = hop.get("out") or {}
    inp = hop.get("in") or {}
    score = hop.get("score")
    tail = f" (score {score})" if isinstance(score, int) else ""
    if rule == "S1":
        refs = hop.get("lookup") or []
        states = sorted({str(r.get("state")) for r in refs})
        names = [site_label(conn, s) or s for s in out.get("sites") or []]
        return (f"The alert's {inp.get('vendor')} scope belongs to {', '.join(names)} "
                f"({'/'.join(states)} link){tail}.")
    if rule == "S2":
        if out.get("basis") == "unknown":
            return str(hop.get("note") or "The site's internet address at that moment is unknown.")
        looks = hop.get("lookup") or []
        names = [site_label(conn, s) or s for s in out.get("sites") or []]
        parts = []
        for look in looks:
            when = "inside" if look.get("match") == "in_core" else "at the edge of"
            parts.append(f"{look.get('source')} ({look.get('nat_kind')}) {when} its interval")
        return (f"The public address was {', '.join(names)}'s internet connection at that "
                f"moment — {'; '.join(parts)}{tail}.")
    if rule == "S-AGREE":
        return (f"Both agree on the site{tail}." if out.get("basis") == "both"
                else f"The profile's site holds; the address does not corroborate it{tail}.")
    if rule == "S-NARROW":
        return f"The address narrows the profile's sites to one{tail}."
    if rule == "S-NOTLOC":
        return ("The address was not this client's internet connection at that time: the "
                "profile's site holds, but no device list is given" + tail + ".")
    if rule == "S-CONFLICT":
        return "The profile and the address point at two different sites: no answer is picked."
    if rule == "S3":
        return f"The LAN address is inside one site's network{tail}."
    if rule == "D3":
        if out.get("lease_id"):
            label = _lease_label(conn, out.get("lease_id")) or "a UniFi client (lease aged out)"
            return f"UniFi says that LAN address was {label} at that moment{tail}."
        return str(hop.get("note") or "No single UniFi client held that LAN address.")
    if rule == "D4":
        return str(hop.get("note") or "No LAN witness at this site.") + tail
    if rule == "D5":
        return "NextDNS's own app named the device (a name the device reports itself)" + tail + "."
    if rule == "D7":
        excluded = out.get("excluded") or {}
        ex = "; ".join(f"{n} excluded ({k.replace('_', ' ')})" for k, n in sorted(excluded.items()))
        return (f"{out.get('candidates', 0)} device(s) were connected at that moment"
                + (f" — {ex}" if ex else "") + ". A set never names one device.")
    if rule == "N-DEV":
        return str(hop.get("note") or "The same name elsewhere — names never decide.")
    return str(hop.get("note") or rule or "")


def explain(resolution: dict[str, Any], conn: Optional[sqlite3.Connection]) -> dict[str, Any]:
    """{headline, where, device, why[], flags[], candidates[]} for the panel."""
    try:
        chain = json.loads(resolution.get("chain") or "[]")
    except ValueError:
        chain = []
    try:
        flags = json.loads(resolution.get("flags") or "[]")
    except ValueError:
        flags = []
    try:
        cands = json.loads(resolution.get("candidates") or "[]")
    except ValueError:
        cands = []
    site = site_label(conn, resolution.get("site_id"))
    tier = resolution.get("tier") or "none"
    rows = []
    aged = False
    for c in cands:
        label = _lease_label(conn, c.get("lease_id")) if c.get("lease_id") else None
        if c.get("lease_id") and label is None:
            aged = True
        rows.append({"label": label or ("NextDNS app device" if c.get("nextdns_device")
                                        else "a device that joined and left between polls"
                                        if c.get("join_id") else "details aged out"),
                     "score": c.get("score"), "features": c.get("features") or [],
                     "conn": c.get("conn"), "match": c.get("match"),
                     "lease_id": c.get("lease_id"), "mac_kind": c.get("mac_kind")})
    return {
        "where": {"site_id": resolution.get("site_id"), "label": site,
                  "basis": resolution.get("site_basis"), "score": resolution.get("site_score"),
                  "tier": resolution.get("site_tier"),
                  "tier_word": TIER_WORDS.get(resolution.get("site_tier") or "none", "")},
        "device": {"ref": resolution.get("device_ref"), "tier": tier,
                   "tier_word": TIER_WORDS.get(tier, tier.upper()),
                   "score": resolution.get("score"),
                   "n_candidates": resolution.get("n_candidates")},
        "why": [hop_text(h, conn) for h in chain if isinstance(h, dict)],
        "flags": [FLAG_WORDS.get(f, f) for f in flags],
        "candidates": rows,
        "candidates_aged_out": aged or (not rows and int(resolution.get("n_candidates") or 0) > 0),
    }
