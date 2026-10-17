"""What each UniFi system-log event IS — a signal, a roll-up count, a lease
boundary — and the payload a signal is stored with.

From a 30-day catalogue of a production fleet's events (2026-09-30) and
the plan approved 2026-09-30:

  SIGNALS (events.db), coalesced per site + subject per CLOCK HOUR:
    ips_threat      SECURITY / SECURITY_INTRUSION_PREVENTION / THREAT_DETECTED,
                    THREAT_BLOCKED — HIGH (detected-not-blocked ranks above
                    blocked: its headline says NOT blocked and its L1 note
                    escalates first); subject = the LAN client + the signature
                    (+ the DIRECTION when known — N7: `inbound` = from the
                    internet to the LAN, `outbound` = a LAN host reaching out)
    rogue_ap        ROGUE_AP_DETECTED — MEDIUM
    admin_activity  AUDIT / SYSTEM_ADMIN / ADMIN_ACCESS, GENERATED — LOW
                    (an audit signal on a client's console)
    config_change   AUDIT / SYSTEM_ADMIN / MADE_CHANGES — MEDIUM
    wan_down        NETWORK_WAN_FAILED, NETWORK_WAN_FAILED_MULTIPLE_TIMES — MEDIUM
    wan_failover    NETWORK_FAILED_OVER_TO_BACKUP_WAN — MEDIUM
    wan_restored    NETWORK_WAN_RESTORED — LOW
    vpn_down        VPN_SITE_TO_SITE_DISCONNECTED — MEDIUM
    system_event    FAIL-SAFE: an event this catalogue does not know that the
                    vendor rates HIGH or VERY_HIGH — MEDIUM (an unknown thing
                    the vendor calls serious is never only counted)
    mac_anomaly     DERIVED (not a vendor event): entity resolution's MAC-anomaly
                    rule found one MAC holding two IPs in one poll window, or
                    wired and wireless at once, while UniFi kept the client
                    connected — "possible MAC impersonation", MEDIUM; subject =
                    the MAC (`derived_payload`)
  ROLL-UPS ONLY (hourly counts in telemetry.db, never stored one by one):
    firewall_block  SECURITY_FIREWALL / BLOCKED_BY_FIREWALL (1,075 in 30 d)
    client_connect  CLIENT_CONNECTED_WIRED / _WIRELESS, HOTSPOT_GUEST_AUTHORIZED,
                    TELEPORT_CLIENT_CONNECTED
    client_disconnect  CLIENT_DISCONNECTED_*, TELEPORT_CLIENT_DISCONNECTED
    client_roam     CLIENT_ROAMED (~18k client events in 30 d: telemetry)
    isp_quality     ISP_HIGH_LATENCY, ISP_PACKET_LOSS
    wan_flap        NETWORK_WAN_FAILED_TEMPORARY,
                    NETWORK_FAILED_OVER_TO_BACKUP_WAN_TEMPORARY
    device          UniFi device / power / firmware / port events
    other           anything else the vendor rates below HIGH
  LEASE BOUNDARIES (also handed to entity resolution, per mapped site): the
    client connect / disconnect / roam events, CLIENT_IP_CONFLICT and the WAN
    events — sanitised, with MAC / IP / time only.

IPS events, as the live API answers them (9 sampled, 2026-10-01 20:00):
parameters SRC_IP{id, name, not_actionable}, DST_IP{id, name, not_actionable},
DEVICE{… name, model_name, ip …} (the REPORTING GATEWAY — never the LAN
client), INITIATOR_ID{id}, CONSOLE_NAME{id, name}, CONSOLE_WITH_DEVICE_NAME —
NO signature and NO category parameter and no CLIENT. The threat's name is
taken from the event's own text (`threat_name`: title_raw / message_raw, read
as TEMPLATES — placeholders left out, so a remote address never becomes part
of the name or of the coalescing key); the LAN side is whichever of SRC_IP /
DST_IP is a local address (read tolerantly from ip / id / name, or an address
inside the text). Older or other shapes (CLIENT, SIGNATURE, CATEGORY …) are
still read when present, and the (sanitised) parameters stay on the payload
whole.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from apps.octo.adapters.unifi import ocsf, sanitize

SIGNAL, ROLLUP = "signal", "rollup"

_SIGNAL_EVENTS: dict[str, tuple[str, str]] = {
    # event → (kind, severity)
    "THREAT_DETECTED": ("ips_threat", "high"),
    "THREAT_BLOCKED": ("ips_threat", "high"),
    "ROGUE_AP_DETECTED": ("rogue_ap", "medium"),
    "ADMIN_ACCESS": ("admin_activity", "low"),
    "GENERATED": ("admin_activity", "low"),
    "MADE_CHANGES": ("config_change", "medium"),
    "NETWORK_WAN_FAILED": ("wan_down", "medium"),
    "NETWORK_WAN_FAILED_MULTIPLE_TIMES": ("wan_down", "medium"),
    "NETWORK_FAILED_OVER_TO_BACKUP_WAN": ("wan_failover", "medium"),
    "NETWORK_WAN_RESTORED": ("wan_restored", "low"),
    "VPN_SITE_TO_SITE_DISCONNECTED": ("vpn_down", "medium"),
}
_ROLLUP_EVENTS: dict[str, str] = {
    "BLOCKED_BY_FIREWALL": "firewall_block",
    "CLIENT_CONNECTED_WIRED": "client_connect",
    "CLIENT_CONNECTED_WIRELESS": "client_connect",
    "HOTSPOT_GUEST_AUTHORIZED": "client_connect",
    "TELEPORT_CLIENT_CONNECTED": "client_connect",
    "CLIENT_DISCONNECTED_WIRED": "client_disconnect",
    "CLIENT_DISCONNECTED_WIRELESS": "client_disconnect",
    "TELEPORT_CLIENT_DISCONNECTED": "client_disconnect",
    "CLIENT_ROAMED": "client_roam",
    "ISP_HIGH_LATENCY": "isp_quality",
    "ISP_PACKET_LOSS": "isp_quality",
    "NETWORK_WAN_FAILED_TEMPORARY": "wan_flap",
    "NETWORK_FAILED_OVER_TO_BACKUP_WAN_TEMPORARY": "wan_flap",
    "CLIENT_IP_CONFLICT": "device",
}
_DEVICE_CATEGORIES = frozenset({"UNIFI_DEVICES", "UNIFI_ETHERNET_PORTS", "POWER",
                                "SOFTWARE_UPDATES"})
# The kinds whose events mark a lease / egress boundary for entity resolution.
BOUNDARY_EVENTS = frozenset({
    "CLIENT_CONNECTED_WIRED", "CLIENT_CONNECTED_WIRELESS", "CLIENT_DISCONNECTED_WIRED",
    "CLIENT_DISCONNECTED_WIRELESS", "CLIENT_ROAMED", "CLIENT_IP_CONFLICT",
    "HOTSPOT_GUEST_AUTHORIZED", "TELEPORT_CLIENT_CONNECTED", "TELEPORT_CLIENT_DISCONNECTED",
    "NETWORK_WAN_FAILED", "NETWORK_WAN_FAILED_TEMPORARY", "NETWORK_WAN_FAILED_MULTIPLE_TIMES",
    "NETWORK_WAN_RESTORED", "NETWORK_FAILED_OVER_TO_BACKUP_WAN",
    "NETWORK_FAILED_OVER_TO_BACKUP_WAN_TEMPORARY",
})
SIGNAL_KINDS = ("ips_threat", "rogue_ap", "admin_activity", "config_change", "wan_down",
                "wan_failover", "wan_restored", "vpn_down", "system_event", "mac_anomaly")
ROLLUP_KINDS = ("firewall_block", "client_connect", "client_disconnect", "client_roam",
                "isp_quality", "wan_flap", "device", "other")
_HIGH_VENDOR = frozenset({"HIGH", "VERY_HIGH", "CRITICAL"})
_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_PLACEHOLDER_RE = re.compile(r"\{([A-Z][A-Z0-9_]{0,63})\}")
MAX_PARAMETERS = 40


@dataclass(frozen=True)
class Classified:
    family: str          # SIGNAL | ROLLUP
    kind: str
    severity: str        # the signal's level ('' for a roll-up)


def _key(value: Any) -> str:
    text = value.strip().upper() if isinstance(value, str) else ""
    return text if _KEY_RE.fullmatch(text) else ""


def classify(category: Any, subcategory: Any, event: Any, vendor_severity: Any) -> Classified:
    ev = _key(event)
    cat = _key(category)
    if ev in _SIGNAL_EVENTS:
        kind, sev = _SIGNAL_EVENTS[ev]
        if kind == "ips_threat" and _key(subcategory) not in ("", "SECURITY_INTRUSION_PREVENTION"):
            return Classified(SIGNAL, "system_event", "medium")
        return Classified(SIGNAL, kind, sev)
    if ev in _ROLLUP_EVENTS:
        return Classified(ROLLUP, _ROLLUP_EVENTS[ev], "")
    if cat == "CLIENT_DEVICES":
        return Classified(ROLLUP, "client_connect" if "CONNECT" in ev else "other", "")
    if _key(vendor_severity) in _HIGH_VENDOR:
        return Classified(SIGNAL, "system_event", "medium")
    if cat in _DEVICE_CATEGORIES:
        return Classified(ROLLUP, "device", "")
    return Classified(ROLLUP, "other", "")


# ---------------------------------------------------------------------------
# One normalised event
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class LogEvent:
    id: str
    ts_ms: int
    category: str
    subcategory: str
    event: str
    vendor_severity: str
    title: str
    message: str
    parameters: dict[str, Any]
    target: str
    # The vendor's text as TEMPLATES ("{SRC_IP} …"), cleaned and bounded —
    # the IPS threat's name is read from them, never from the rendered text.
    title_raw: str = ""
    message_raw: str = ""

    @property
    def iso(self) -> str:
        return iso_ms(self.ts_ms)


def iso_ms(ts_ms: int) -> str:
    dt = datetime.fromtimestamp(ts_ms / 1000.0, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _clean(value: Any, limit: int = 240) -> str:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        value = str(value)
    if not isinstance(value, str):
        return ""
    flat = " ".join("".join(c if c.isprintable() else " " for c in value).split())
    return flat if len(flat) <= limit else flat[: limit - 1].rstrip() + "…"


def to_ms(value: Any) -> Optional[int]:
    """A vendor timestamp (ms or s since the epoch) → ms; None if unusable."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if value <= 0:
        return None
    ms = int(value) if value > 1e11 else int(value * 1000)
    return ms if ms < 32503680000000 else None          # before year 3000


def normalise(raw: Any) -> Optional[LogEvent]:
    """A system-log item → LogEvent (sanitised, bounded), or None when it has
    no usable time."""
    if not isinstance(raw, dict):
        return None
    ts = to_ms(raw.get("timestamp"))
    if ts is None:
        return None
    params = raw.get("parameters") if isinstance(raw.get("parameters"), dict) else {}
    params = sanitize.strip({k: v for k, v in list(params.items())[:MAX_PARAMETERS]
                             if _key(k)})
    vid = _clean(raw.get("id"), 128)
    if not vid:
        basis = "|".join(str(raw.get(k)) for k in ("timestamp", "event", "category", "target"))
        vid = "h" + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:31]
    return LogEvent(
        id=vid, ts_ms=ts,
        category=_key(raw.get("category")), subcategory=_key(raw.get("subcategory")),
        event=_key(raw.get("event")), vendor_severity=_key(raw.get("severity")),
        title=render(raw.get("title_raw"), params, 200),
        message=render(raw.get("message_raw"), params, 600),
        parameters=params, target=_clean(raw.get("target"), 120),
        title_raw=_clean(raw.get("title_raw"), 300), message_raw=_clean(raw.get("message_raw"), 600),
    )


def param_text(value: Any, prefer: tuple[str, ...] = ("name", "hostname", "id", "ip")) -> str:
    """One parameter as text: a scalar, or the first useful field of an
    object parameter ({id, name, ip, …})."""
    if isinstance(value, dict):
        for k in prefer:
            text = _clean(value.get(k), 120)
            if text:
                return text
        return ""
    return _clean(value, 120)


def render(template: Any, params: dict[str, Any], limit: int) -> str:
    """The vendor's message template ("{CLIENT} connected to {WLAN}") with
    its parameters filled in, cleaned and bounded."""
    if not isinstance(template, str):
        return ""
    text = _PLACEHOLDER_RE.sub(lambda m: param_text(params.get(m.group(1))) or m.group(0),
                               template[:2000])
    return _clean(text, limit)


# ---------------------------------------------------------------------------
# IPS fields (tolerant: the keys were not observed live)
# ---------------------------------------------------------------------------

def _ip(value: Any) -> Optional[str]:
    text = value.strip() if isinstance(value, str) else ""
    try:
        return str(ipaddress.ip_address(text.split("%")[0]))
    except ValueError:
        return None


def _port(value: Any) -> Optional[int]:
    if isinstance(value, dict):
        value = value.get("id") if value.get("id") is not None else value.get("name")
    try:
        port = int(str(value))
    except (TypeError, ValueError):
        return None
    return port if 0 < port < 65536 else None


def _mac(value: Any) -> Optional[str]:
    text = value.strip().lower().replace("-", ":") if isinstance(value, str) else ""
    return text if re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", text) else None


def _first(params: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for k in keys:
        if k in params and params[k] not in (None, "", {}):
            return params[k]
    return None


_ADDR_IN_TEXT = re.compile(r"(?<![\w:.])((?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})(?![\w:.])")


def _ip_in_text(value: Any) -> Optional[str]:
    """An address inside a label ("192.0.2.37 (FRONT-DESK)")."""
    if not isinstance(value, str):
        return None
    for m in _ADDR_IN_TEXT.finditer(value[:200]):
        ip = _ip(m.group(1))
        if ip:
            return ip
    return None


def _ip_of(value: Any) -> Optional[str]:
    """An address parameter, tolerantly: a scalar, or an object (the live
    IPS shape {id, name, not_actionable}) — ip, then id, then name, then an
    address written inside id / name."""
    if isinstance(value, dict):
        for k in ("ip", "id", "name"):
            ip = _ip(value.get(k))
            if ip:
                return ip
        for k in ("name", "id"):
            ip = _ip_in_text(value.get(k))
            if ip:
                return ip
        return None
    return _ip(value) or _ip_in_text(value)


# A site's OWN address space — explicitly, not `is_private` (which also
# counts documentation and other special-purpose ranges, so it cannot tell a
# LAN device from a remote end).
_LOCAL_NETS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16",
    "127.0.0.0/8", "fc00::/7", "fe80::/10", "::1/128",
))


def is_local(ip: Optional[str]) -> bool:
    """True for an address of the site's own networks (RFC 1918, CGNAT,
    link-local, loopback, IPv6 ULA / link-local)."""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr.version == net.version and addr in net for net in _LOCAL_NETS)


# Titles that name no threat ("Threat Blocked"): the name is then looked for
# in the message.
_GENERIC_TITLES = frozenset({
    "threat", "threat blocked", "threat detected", "threat detected and blocked",
    "intrusion prevention", "intrusion detected", "intrusion blocked", "ips", "ips alert",
    "ids alert", "security threat", "threat management", "security alert", "threat found",
})
_SIGNATURE_RE = re.compile(r"\b((?:ETPRO|ET|GPL|SURICATA)\s+[A-Z][A-Z0-9_-]+\s+[^{}\"“”]+)")
_QUOTED_RE = re.compile(r"[\"“']([^\"“”'{}]{4,160})[\"”']")
_PLACEHOLDER_ANY = re.compile(r"\{[A-Za-z0-9_]+\}")
_FILLER_TAIL = re.compile(r"(?:\s+(?:from|to|by|on|for|via|at|between|and|->|→|—|-|:))+\s*$",
                          re.IGNORECASE)


def _tidy(text: str) -> str:
    text = _PLACEHOLDER_ANY.sub(" ", text)
    text = " ".join(text.split()).strip(" .,;:-—→")
    return _FILLER_TAIL.sub("", text).strip(" .,;:-—→")


def threat_name(title_raw: str, message_raw: str) -> Optional[str]:
    """The IPS threat's name from the event's own text — the live IPS event
    has no signature parameter. Read from the TEMPLATES (placeholders such as
    {SRC_IP} dropped), so the same threat from two remote addresses has one
    name: a Suricata-style signature ("ET POLICY …") anywhere, else a quoted
    name, else the text after the last colon, else a title that is not
    generic ("Threat Blocked"). None when the text names nothing."""
    texts = [t for t in (title_raw, message_raw) if t]
    for text in texts:
        m = _SIGNATURE_RE.search(text)
        if m:
            name = _tidy(m.group(1))
            if name:
                return name[:160]
    for text in texts:
        m = _QUOTED_RE.search(text)
        if m and _tidy(m.group(1)):
            return _tidy(m.group(1))[:160]
    for text in texts:
        if ":" in _PLACEHOLDER_ANY.sub("", text):
            tail = _tidy(text.rsplit(":", 1)[1])
            if len(tail) >= 4 and tail.lower() not in _GENERIC_TITLES:
                return tail[:160]
    title = _tidy(title_raw)
    if title and title.lower() not in _GENERIC_TITLES:
        return title[:160]
    return None


def ips_fields(ev: LogEvent) -> dict[str, Any]:
    """{action, client{mac, ip, name, hostname}, src_ip/port, dst_ip/port,
    protocol, signature, signature_id, category, gateway, local_ip,
    remote_ip, direction}. The live shape (module docstring): SRC_IP / DST_IP
    objects, DEVICE = the reporting gateway (`gateway`, never the client),
    the signature from the text (`threat_name`). `direction` (N7): 'inbound'
    when the source is remote and the destination one of the site's own
    addresses, 'outbound' the other way round; absent when the addresses do
    not say (never guessed — an unknown direction stays Yellow)."""
    p = ev.parameters
    client = _first(p, ("CLIENT", "SRC_CLIENT", "SOURCE_CLIENT", "DST_CLIENT"))
    client = client if isinstance(client, dict) else {}
    src_ip = _ip_of(_first(p, ("SRC_IP", "SOURCE_IP", "SRC", "IP"))) or _ip(client.get("ip"))
    dst_ip = _ip_of(_first(p, ("DST_IP", "DESTINATION_IP", "DEST_IP", "REMOTE_IP", "DST")))
    sig = _first(p, ("SIGNATURE", "IPS_SIGNATURE", "THREAT", "RULE", "ALERT"))
    category = _first(p, ("CATEGORY", "THREAT_CATEGORY", "IPS_CATEGORY"))
    device = p.get("DEVICE") if isinstance(p.get("DEVICE"), dict) else {}
    out = {
        "action": "detected" if ev.event == "THREAT_DETECTED" else "blocked",
        "client": {k: v for k, v in {
            "mac": _mac(client.get("id")) or _mac(client.get("mac")),
            "ip": _ip(client.get("ip")),
            "name": _clean(client.get("name"), 120) or None,
            "hostname": _clean(client.get("hostname"), 120) or None,
        }.items() if v},
        "src_ip": src_ip,
        "src_port": _port(_first(p, ("SRC_PORT", "SOURCE_PORT"))),
        "dst_ip": dst_ip,
        "dst_port": _port(_first(p, ("DST_PORT", "DESTINATION_PORT", "DEST_PORT"))),
        "protocol": param_text(_first(p, ("PROTOCOL", "PROTO")), ("name", "id")) or None,
        "signature": (param_text(sig, ("name", "id")) if sig is not None else None)
        or threat_name(ev.title_raw, ev.message_raw),
        "signature_id": param_text(sig, ("id",)) if isinstance(sig, dict) else None,
        "category": param_text(category, ("name", "id")) or None,
        "gateway": param_text(device, ("name", "model_name", "model", "id")) or None,
    }
    local = [ip for ip in (src_ip, dst_ip, out["client"].get("ip")) if is_local(ip)]
    remote = [ip for ip in (dst_ip, src_ip) if ip and not is_local(ip)]
    out["local_ip"] = local[0] if local else None
    out["remote_ip"] = remote[0] if remote else None
    out["direction"] = ips_direction(src_ip, dst_ip)
    return {k: v for k, v in out.items() if v not in (None, "", {})}


IPS_DIRECTIONS = ("inbound", "outbound")


def ips_direction(src_ip: Optional[str], dst_ip: Optional[str]) -> Optional[str]:
    """N7: which way the flagged traffic went — only when BOTH ends are known
    and exactly one is the site's own."""
    if not src_ip or not dst_ip:
        return None
    src_local, dst_local = is_local(src_ip), is_local(dst_ip)
    if src_local and not dst_local:
        return "outbound"
    if dst_local and not src_local:
        return "inbound"
    return None


def client_of(ev: LogEvent) -> dict[str, Any]:
    """The client a CLIENT_* event is about: {mac, ip, name, hostname,
    network, wlan, uplink} — `uplink` the UniFi device it joined through (the
    `DEVICE` parameter: a switch for a wired join; the MAC-anomaly rule's
    uplink-flap trigger)."""
    c = ev.parameters.get("CLIENT")
    c = c if isinstance(c, dict) else {}
    ip = _ip(c.get("ip")) or _ip_of(ev.parameters.get("IP"))
    return {k: v for k, v in {
        "mac": _mac(c.get("id")) or _mac(c.get("mac")),
        "ip": ip,
        "name": _clean(c.get("name"), 120) or None,
        "hostname": _clean(c.get("hostname"), 120) or None,
        "network": param_text(ev.parameters.get("NETWORK"), ("name", "id")) or None,
        "wlan": param_text(ev.parameters.get("WLAN"), ("name", "id")) or None,
        "uplink": param_text(ev.parameters.get("DEVICE"), ("id", "mac", "name")) or None,
    }.items() if v}


# ---------------------------------------------------------------------------
# Coalescing subject + the stored payload
# ---------------------------------------------------------------------------

def _digest(text: str, n: int = 16) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:n]


def subject_of(kind: str, ev: LogEvent, ips: Optional[dict[str, Any]] = None) -> str:
    """What a signal is coalesced on within its site and hour."""
    p = ev.parameters
    if kind == "ips_threat":
        ips = ips or {}
        client = (ips.get("client") or {}).get("mac") or ips.get("local_ip") or "?"
        # The threat: its id, its name, else the TEMPLATE text (never the
        # rendered text, which carries the remote address).
        sig = ips.get("signature_id") or ips.get("signature")
        if not sig:
            sig = _digest(f"{ev.title_raw}|{ev.message_raw}") \
                if (ev.title_raw or ev.message_raw) else (ev.event or "?")
        # N7: the direction sits BEFORE the action (the action stays last —
        # every reader takes the subject's last part as the action); a hit
        # whose direction is not known keeps the three-part subject.
        direction = ips.get("direction")
        if direction in IPS_DIRECTIONS:
            return f"{client}|{sig}|{direction}|{ips.get('action', '')}"
        return f"{client}|{sig}|{ips.get('action', '')}"
    if kind in ("admin_activity", "config_change"):
        admin = param_text(_first(p, ("ADMIN", "USER", "ACTOR")), ("id", "name")) or ev.target
        return f"{ev.event}|{_digest(admin or '?')}"
    if kind in ("wan_down", "wan_failover", "wan_restored"):
        return f"{ev.event}|{param_text(_first(p, ('WAN', 'INTERFACE', 'PORT')), ('name', 'id'))}"
    if kind == "vpn_down":
        return f"{ev.event}|{param_text(_first(p, ('VPN', 'PEER', 'REMOTE_SITE')), ('name', 'id'))}"
    if kind == "rogue_ap":
        return f"{ev.event}|{param_text(_first(p, ('ROGUE_AP', 'BSSID', 'AP', 'SSID')), ('id', 'name'))}"
    return ev.event or ev.category or "?"


def bucket_hour(ts_ms: int) -> str:
    dt = datetime.fromtimestamp(ts_ms / 1000.0, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:00:00Z")


def bucket_key(scope: str, kind: str, subject: str, hour: str) -> str:
    return _digest("\n".join((scope, kind, subject, hour)), 32)


@dataclass(frozen=True)
class SiteContext:
    scope: str              # "<hostId>/<siteId>"
    host_id: str
    site_id: str
    internal_ref: str
    site_name: str
    console_name: str
    timezone: str = ""


def signal_payload(cls: Classified, ev: LogEvent, site: SiteContext) -> dict[str, Any]:
    """The payload ONE signal is stored with (events.db). Sanitised, bounded,
    a pure function of (event, site) — so a re-read event has the same
    identity and the sink stores it once."""
    ips = ips_fields(ev) if cls.kind == "ips_threat" else None
    hour = bucket_hour(ev.ts_ms)
    subject = subject_of(cls.kind, ev, ips)
    vendor = {"category": ev.category, "subcategory": ev.subcategory, "event": ev.event,
              "severity": ev.vendor_severity, "id": ev.id}
    title = ev.title or ev.message or ev.event
    src = dst = None
    analytic = None
    disposition = None
    protocol = None
    actor = None
    if ips is not None:
        client = ips.get("client") or {}
        local, remote = ips.get("local_ip"), ips.get("remote_ip")
        src_is_local = ips.get("src_ip") is None or is_local(ips.get("src_ip"))
        src = ocsf.endpoint(ip=ips.get("src_ip") or local,
                            port=ips.get("src_port"),
                            mac=client.get("mac") if src_is_local else None,
                            hostname=client.get("hostname") if src_is_local else None,
                            name=client.get("name") if src_is_local else None)
        dst = ocsf.endpoint(ip=ips.get("dst_ip") or (remote if src_is_local else local),
                            port=ips.get("dst_port"))
        analytic = {k: v for k, v in {"name": ips.get("signature"), "uid": ips.get("signature_id"),
                                      "category": ips.get("category"), "type_id": 1,
                                      "type": "Rule"}.items() if v}
        disposition = ips.get("action")
        protocol = ips.get("protocol")
    if cls.kind in ("admin_activity", "config_change"):
        actor = param_text(_first(ev.parameters, ("ADMIN", "USER", "ACTOR")), ("name", "id")) or None
        ip = _ip_of(_first(ev.parameters, ("IP", "SRC_IP")))
        src = ocsf.endpoint(ip=ip) if ip else None
    payload: dict[str, Any] = {
        "vendor_event_id": f"{site.scope}:{ev.id}",
        "kind": cls.kind,
        "scope": site.scope,
        "host_id": site.host_id,
        "site_id": site.site_id,
        "site_ref": site.internal_ref,
        "site_name": site.site_name,
        "console_name": site.console_name,
        "event": {
            "id": ev.id, "timestamp": ev.iso, "category": ev.category,
            "subcategory": ev.subcategory, "event": ev.event,
            "severity": ev.vendor_severity, "title": ev.title, "message": ev.message,
            "target": ev.target, "parameters": ev.parameters,
        },
        "signal": {"level": cls.severity, "bucket_hour": hour, "subject": subject},
        "ocsf": ocsf.project(
            cls.kind, time_ms=ev.ts_ms, severity=cls.severity, event_uid=ev.id,
            scope=site.scope, site_name=site.site_name, console_name=site.console_name,
            title=title, original_time=ev.iso, vendor=vendor, src=src, dst=dst,
            protocol=protocol, disposition=disposition, analytic=analytic, actor_name=actor,
        ),
    }
    if ips is not None:
        payload["ips"] = ips
    return sanitize.strip(payload)


def boundary_event(ev: LogEvent) -> Optional[dict[str, Any]]:
    """The minimal record entity resolution reads for a lease / egress
    boundary: what happened, when, and the client's MAC / IP (no names of
    people beyond the device names UniFi shows — Rick's decision 2026-10-01:
    device names are not masked)."""
    if ev.event not in BOUNDARY_EVENTS:
        return None
    out = {"id": ev.id, "ts_ms": ev.ts_ms, "time": ev.iso, "event": ev.event,
           "ocsf_class_uid": ocsf.class_of(_ROLLUP_EVENTS.get(ev.event)
                                           or _SIGNAL_EVENTS.get(ev.event, ("other", ""))[0])[0]}
    if ev.event.startswith(("CLIENT_", "HOTSPOT_", "TELEPORT_")):
        out["client"] = client_of(ev)
    else:
        out["wan"] = param_text(_first(ev.parameters, ("WAN", "INTERFACE", "PORT")), ("name", "id"))
    return out


# ---------------------------------------------------------------------------
# Derived signals (entity resolution's findings, stored as UniFi signals)
# ---------------------------------------------------------------------------

ANOMALY_TEXT = {
    "two_ips": "the same MAC address held two LAN addresses within one poll window",
    "wired_and_wireless": "the same MAC address was wired and wireless at the same time",
    "uplink_flap": "the same MAC address kept switching between two switch ports",
}


def derived_payload(item: dict[str, Any], site: SiteContext) -> Optional[dict[str, Any]]:
    """The payload of a DERIVED signal (`feed.derived_signals`): the MAC-
    anomaly rule's finding. A pure function of the finding, so a re-delivery
    is the same alert."""
    mac = _mac(item.get("mac"))
    if mac is None or item.get("kind") != "mac_anomaly":
        return None
    anomaly = str(item.get("anomaly") or "")[:32]
    detail = item.get("detail") if isinstance(item.get("detail"), dict) else {}
    at = _clean(item.get("to"), 40) or _clean(detail.get("join_at"), 40)
    ts = to_ms(int(datetime.strptime(at, "%Y-%m-%dT%H:%M:%S.%fZ")
                   .replace(tzinfo=timezone.utc).timestamp() * 1000)) if at else None
    if ts is None:
        return None
    ips = [ip for ip in (_ip(x) for x in (detail.get("ips") or [])) if ip][:4]
    title = f"Possible MAC impersonation: {ANOMALY_TEXT.get(anomaly, 'a MAC address anomaly')}"
    hour = bucket_hour(ts)
    eid = f"m1-{anomaly}-{mac}-{_digest(str(item.get('from')) + str(item.get('to')), 12)}"
    vendor = {"category": "ATHENA_DERIVED", "subcategory": "MAC_ANOMALY", "event": anomaly.upper(),
              "severity": "MEDIUM", "id": eid}
    src = ocsf.endpoint(ip=ips[0] if ips else None, mac=mac)
    payload: dict[str, Any] = {
        "vendor_event_id": f"{site.scope}:{eid}",
        "kind": "mac_anomaly",
        "scope": site.scope,
        "host_id": site.host_id,
        "site_id": site.site_id,
        "site_ref": site.internal_ref,
        "site_name": site.site_name,
        "console_name": site.console_name,
        "event": {"id": eid, "timestamp": iso_ms(ts), "category": "ATHENA_DERIVED",
                  "subcategory": "MAC_ANOMALY", "event": anomaly.upper(), "severity": "MEDIUM",
                  "title": title, "message": "", "target": "", "parameters": {}},
        "anomaly": {"kind": anomaly, "mac": mac, "ips": ips,
                    "window": {"from": _clean(item.get("from"), 40),
                               "to": _clean(item.get("to"), 40)},
                    "join_event": _clean(detail.get("join_event"), 40) or None,
                    "join_at": _clean(detail.get("join_at"), 40) or None,
                    "media": [m for m in (_clean(detail.get("snapshot_medium"), 16),
                                          _clean(detail.get("join_medium"), 16)) if m]},
        "signal": {"level": "medium", "bucket_hour": hour, "subject": f"{mac}|{anomaly}"},
        "ocsf": ocsf.project(
            "mac_anomaly", time_ms=ts, severity="medium", event_uid=eid, scope=site.scope,
            site_name=site.site_name, console_name=site.console_name, title=title,
            original_time=iso_ms(ts), vendor=vendor, src=src,
            analytic={"name": "MAC anomaly (M1)", "uid": "athena.entity.M1", "type_id": 1,
                      "type": "Rule"}),
    }
    return sanitize.strip(payload)


# ---------------------------------------------------------------------------
# The Fleet v2 ISP-outage incident (DERIVED: apps/octo/fleet/isp_outage.py)
# ---------------------------------------------------------------------------

def isp_outage_payload(view: dict[str, Any]) -> dict[str, Any]:
    """The payload of ONE `fleet.isp_outage` signal, built at the adapter
    boundary from the correlator's view of the incident (with its OCSF
    Incident Finding). A pure function of the view — the correlator fixes
    the view when it queues the signal, so a re-delivery is the same row.
    Stored in the operator's INTERNAL tenant: it names the affected sites and
    their tenants."""
    opened = str(view.get("opened_at") or "")
    try:
        ts_ms = int(datetime.fromisoformat(opened.replace("Z", "+00:00")).timestamp() * 1000)
    except ValueError:
        ts_ms = 0
    asn = int(view.get("asn") or 0)
    isp = str(view.get("isp") or f"AS{asn}")[:80]
    affected = [a for a in (view.get("affected") or []) if isinstance(a, dict)]
    sites = int(view.get("sites") or len(affected))
    payload: dict[str, Any] = {
        "vendor_event_id": str(view.get("vid") or "")[:128],
        "kind": "isp_outage",
        "isp": {"name": isp, "asn": asn},
        "sites": sites,
        "since": view.get("since"),
        "min_sites": view.get("min_sites"),
        "window_min": view.get("window_min"),
        "affected": [{k: a.get(k) for k in ("scope", "site_name", "tenant", "since", "why")}
                     for a in affected],
        "event": {"timestamp": opened, "event": "ISP_OUTAGE",
                  "title": f"ISP outage: {isp} — {sites} sites"},
        "signal": {"level": "high", "subject": f"asn:{asn}"},
        "ocsf": ocsf.project_isp_outage(
            vid=str(view.get("vid") or ""), time_ms=ts_ms, original_time=opened, asn=asn,
            isp=isp, sites=sites, since=str(view.get("since") or ""), affected=affected),
    }
    return sanitize.strip(payload)
