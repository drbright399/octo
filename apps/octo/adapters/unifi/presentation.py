"""UniFi alerts as an operator reads them.

Event types (all SIGNALS, events.db; roll-ups never become rows):

  unifi.ips_threat     IPS THREAT_DETECTED (NOT blocked — ranks first) /
                       THREAT_BLOCKED, HIGH, coalesced per site + LAN client +
                       signature per clock hour
  unifi.rogue_ap       a rogue access point near the site, MEDIUM
  unifi.admin_activity an administrator signed in to the console, LOW (audit)
  unifi.config_change  the console's configuration was changed, MEDIUM (audit)
  unifi.wan_down       a WAN link failed, MEDIUM (availability)
  unifi.wan_failover   the gateway failed over to its backup WAN, MEDIUM
  unifi.wan_restored   a WAN link came back, LOW
  unifi.vpn_down       a site-to-site VPN went down, MEDIUM
  unifi.system_event   an event the catalogue does not know that the vendor
                       rates HIGH / VERY_HIGH, MEDIUM (fail-safe)
  unifi.mac_anomaly    DERIVED by entity resolution: one MAC address held two
                       LAN addresses in one poll window, or was wired and
                       wireless at once — possible MAC impersonation, MEDIUM
  fleet.isp_outage     DERIVED by the Fleet v2 correlator: >= N sites on ONE
                       ISP ASN lost their internet within minutes — ONE
                       incident in the operator's internal tenant, HIGH
                       ("ISP outage: <ISP> — N sites")

Title: "UniFi <what> — <device or site>". The LAN device is named by its UniFi
client name (device names are not masked — the same names are in every
telemetry source, owner decision 2026-10-01), else its LAN IP. The remote
public address of an IPS event is the IOC.

Rows written by the RETIRED local-controller adapter (payload `key` / `msg`,
untyped) still read: `present` falls back to "UniFi event — <message>" with
`fallback=True`, so the alerts feed keeps their stored summary.
"""
from __future__ import annotations

from typing import Any, Optional

from apps.octo.ingest.presentation import EventPresentation, clean_block, clean_line

KIND_TO_EVENT = {
    "ips_threat": "unifi.ips_threat",
    "rogue_ap": "unifi.rogue_ap",
    "admin_activity": "unifi.admin_activity",
    "config_change": "unifi.config_change",
    "wan_down": "unifi.wan_down",
    "wan_failover": "unifi.wan_failover",
    "wan_restored": "unifi.wan_restored",
    "vpn_down": "unifi.vpn_down",
    "system_event": "unifi.system_event",
    "mac_anomaly": "unifi.mac_anomaly",
    "isp_outage": "fleet.isp_outage",
}
EVENT_TYPES = tuple(KIND_TO_EVENT.values())
LEGACY_EVENT = "unifi.legacy_event"
HEADLINE_PREFIX = "UniFi "


def _m(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def event_type_of(payload: Any) -> str:
    kind = _m(payload).get("kind")
    if isinstance(kind, str) and kind in KIND_TO_EVENT:
        return KIND_TO_EVENT[kind]
    return LEGACY_EVENT


def site_label(payload: Any) -> str:
    p = _m(payload)
    site = clean_line(p.get("site_name"), 80)
    console = clean_line(p.get("console_name"), 80)
    if site and console and site.lower() != console.lower():
        return f"{site} ({console})"
    return site or console or "a UniFi site"


def device_label(payload: Any) -> Optional[str]:
    """The LAN device of an IPS event: its UniFi name, else hostname, else
    LAN IP; None when the event names none. A MAC anomaly: the MAC."""
    an = _m(_m(payload).get("anomaly"))
    if an.get("mac"):
        return clean_line(an.get("mac"), 17) or None
    ips = _m(_m(payload).get("ips"))
    client = _m(ips.get("client"))
    for v in (client.get("name"), client.get("hostname"), ips.get("local_ip"), client.get("ip")):
        text = clean_line(v, 64)
        if text:
            return text
    return None


def indicator_of(payload: Any) -> Optional[str]:
    """The IOC: the PUBLIC remote address of an IPS event (a private one is
    the site's own network, never an indicator)."""
    ips = _m(_m(payload).get("ips"))
    ip = ips.get("remote_ip")
    return ip if isinstance(ip, str) and ip else None


GENERIC_TITLES = frozenset({"threat blocked", "threat detected", "threat detected and blocked"})


def _signature(payload: dict[str, Any]) -> str:
    """The threat's name: the signature (live: read from the event's text),
    else a title that names something, else a generic phrase."""
    ips = _m(payload.get("ips"))
    sig = clean_line(ips.get("signature"), 100)
    if sig:
        return sig
    title = clean_line(_m(payload.get("event")).get("title"), 100)
    if title and title.lower() not in GENERIC_TITLES:
        return title
    return "a known threat signature"


def _when(payload: dict[str, Any]) -> str:
    ts = clean_line(_m(payload.get("event")).get("timestamp"), 32)
    return f"{ts[:10]} {ts[11:19]} UTC" if len(ts) >= 19 else (ts or "an unknown time")


def _isp(payload: dict[str, Any]) -> tuple[str, int, int]:
    isp = _m(payload.get("isp"))
    asn = isp.get("asn") if isinstance(isp.get("asn"), int) else 0
    name = clean_line(isp.get("name"), 80) or (f"AS{asn}" if asn else "an ISP")
    sites = payload.get("sites") if isinstance(payload.get("sites"), int) else 0
    return name, asn, sites


def _isp_outage_detail(payload: dict[str, Any]) -> str:
    name, asn, sites = _isp(payload)
    lines = [
        f"Provider: {name}" + (f" (AS{asn})" if asn else ""),
        f"Since: {clean_line(payload.get('since'), 32) or 'unknown'} — {sites} sites lost their "
        f"internet connection within {payload.get('window_min') or 10} minutes of each other.",
        "Affected sites:",
    ]
    for a in (payload.get("affected") or [])[:25]:
        a = _m(a)
        lines.append(f"  · {clean_line(a.get('site_name'), 80)} ({clean_line(a.get('tenant'), 64)})"
                     f" — {clean_line(a.get('why'), 40)} since "
                     f"{clean_line(a.get('since'), 32)[11:16] or '?'} UTC")
    lines.append("What Athena does: each site's own WAN alerts are linked to this incident; it "
                 "closes with a note once most sites are back. Check the provider's status page "
                 "— this is one provider problem, not N site problems.")
    return clean_block([ln for ln in lines if ln])


def _headline(payload: dict[str, Any]) -> str:
    kind = payload.get("kind")
    if kind == "isp_outage":
        name, _asn, sites = _isp(payload)
        return f"ISP outage: {name} — {sites} sites"
    site = site_label(payload)
    if kind == "ips_threat":
        action = _m(payload.get("ips")).get("action")
        who = device_label(payload) or site
        verb = "IPS detected (NOT blocked)" if action == "detected" else "IPS blocked"
        return f"{HEADLINE_PREFIX}{verb} {_signature(payload)} — {who}"
    if kind == "rogue_ap":
        return f"{HEADLINE_PREFIX}rogue access point detected — {site}"
    if kind == "admin_activity":
        return f"{HEADLINE_PREFIX}administrator access on the console — {site}"
    if kind == "config_change":
        return f"{HEADLINE_PREFIX}configuration changed — {site}"
    if kind == "wan_down":
        return f"{HEADLINE_PREFIX}internet (WAN) connection failed — {site}"
    if kind == "wan_failover":
        return f"{HEADLINE_PREFIX}failed over to the backup internet connection — {site}"
    if kind == "wan_restored":
        return f"{HEADLINE_PREFIX}internet (WAN) connection restored — {site}"
    if kind == "vpn_down":
        return f"{HEADLINE_PREFIX}site-to-site VPN disconnected — {site}"
    if kind == "mac_anomaly":
        mac = clean_line(_m(payload.get("anomaly")).get("mac"), 17) or "a device"
        return f"{HEADLINE_PREFIX}possible MAC impersonation ({mac}) — {site}"
    title = clean_line(_m(payload.get("event")).get("title"), 100)
    return f"{HEADLINE_PREFIX}{title or 'high-severity system event'} — {site}"


def _detail(payload: dict[str, Any]) -> str:
    ev = _m(payload.get("event"))
    lines = [f"Site: {site_label(payload)}", f"When: {_when(payload)}"]
    message = clean_line(ev.get("message"), 240) or clean_line(ev.get("title"), 240)
    if message:
        lines.append(f"UniFi says: {message}")
    ips = _m(payload.get("ips"))
    if ips:
        client = _m(ips.get("client"))
        if client:
            parts = [clean_line(client.get(k), 64) for k in ("name", "hostname", "ip", "mac")]
            lines.append("LAN device: " + " · ".join(p for p in parts if p))
        src = clean_line(ips.get("src_ip"), 64)
        dst = clean_line(ips.get("dst_ip"), 64)
        if src or dst:
            sp = f":{ips['src_port']}" if ips.get("src_port") else ""
            dp = f":{ips['dst_port']}" if ips.get("dst_port") else ""
            proto = f" ({clean_line(ips.get('protocol'), 16)})" if ips.get("protocol") else ""
            lines.append(f"Traffic: {src or '?'}{sp} → {dst or '?'}{dp}{proto}")
        cat = clean_line(ips.get("category"), 80)
        if cat:
            lines.append(f"Category: {cat}")
        gw = clean_line(ips.get("gateway"), 80)
        if gw:
            lines.append(f"Reported by: {gw} (the gateway)")
        lines.append("Action: " + ("DETECTED, NOT BLOCKED — the connection may have gone through"
                                   if ips.get("action") == "detected"
                                   else "blocked by the gateway's IPS"))
    an = _m(payload.get("anomaly"))
    if an:
        ips = an.get("ips") if isinstance(an.get("ips"), list) else []
        lines.append("MAC: " + clean_line(an.get("mac"), 17)
                     + (f" · addresses {', '.join(clean_line(i, 45) for i in ips)}" if ips else ""))
        media = an.get("media") if isinstance(an.get("media"), list) else []
        if media:
            lines.append("Seen as: " + " and ".join(clean_line(m, 16) for m in media))
        lines.append("What Athena does: this device's leases in that window are never used to "
                     "name a device (candidates only) — check whether two machines share the "
                     "MAC (a spoofed or cloned address).")
        return clean_block([ln for ln in lines if ln])
    lines.append(f"Event: {clean_line(ev.get('category'), 40)} / {clean_line(ev.get('event'), 60)}")
    return clean_block([ln for ln in lines if ln])


def present(payload: Any) -> EventPresentation:
    p = _m(payload)
    if p.get("kind") == "isp_outage":
        return EventPresentation(
            event_type=KIND_TO_EVENT["isp_outage"],
            headline=clean_line(_headline(p)),
            detail=_isp_outage_detail(p),
            device=None,
            site=None,
        )
    if p.get("kind") in KIND_TO_EVENT:
        return EventPresentation(
            event_type=KIND_TO_EVENT[p["kind"]],
            headline=clean_line(_headline(p)),
            detail=_detail(p),
            device=device_label(p),
            site=clean_line(p.get("site_name"), 80) or None,
        )
    # A row from the retired local-controller adapter (key / msg).
    key = clean_line(p.get("key") or p.get("event_type"), 64)
    msg = clean_line(p.get("msg") or p.get("message") or p.get("description"), 160)
    head = f"UniFi event — {msg}" if msg else (f"UniFi event — {key}" if key else "UniFi event")
    host = clean_line(p.get("hostname") or p.get("device_name") or p.get("ap_name"), 64)
    return EventPresentation(
        event_type=LEGACY_EVENT,
        headline=clean_line(head),
        detail=clean_block([f"Event key: {key}"] if key else []),
        device=host or None,
        fallback=not (key or msg),
    )
