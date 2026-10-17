"""Ingest tiering — which store an event belongs in. THE one registry.

Every event is classified at ingest as a SIGNAL or as TELEMETRY:

  SIGNAL     stays in the tenant's `events.db` under the tenant's full
             retention (the 'events' class, a year by default). Alerts,
             detections, honeypot hits, blocked DNS, control events —
             anything an analyst may have to account for later.
  TELEMETRY  goes to the tenant's `telemetry.db`
             (`apps.octo.ingest.telemetry`): raw rows for a week, hourly
             roll-ups for six months, and the first-seen-domain ledger.
             Measured on a small buoy site (owner decision 2026-09-29):
             ~1,300 events/hour, ~97 % of it DNS — suricata.dns and
             pihole.query recording the same lookups twice.

Fail-safe: anything this module does not POSITIVELY recognise as telemetry
is a signal — an unknown event type, a telemetry type whose payload is not
the expected shape, an unknown or missing Pi-hole status, a Suricata record
that carries an alert, an elevated severity. Misfiling a signal as
telemetry would put it on a 7-day clock; misfiling telemetry as a signal
only costs disk.

Telemetry types and their predicates:

  pihole.query   telemetry only when the query was ANSWERED (forwarded,
                 cached, retried, …). BLOCKED queries — gravity, regex,
                 exact denylist, upstream blocking, deep-CNAME blocks,
                 special-domain and database-busy blocks — are signals.
                 Decided from the documented Pi-hole FTL query status
                 codes (docs.pi-hole.net → Query database → "Query status";
                 the same numeric codes in FTL v5 and v6, v6 adding 18),
                 read from the payload's NUMERIC `raw_query.status` (or the
                 v6 API's status NAME). Never from the buoy forwarder's own
                 `status_label` / severity: before v0.11 its table was
                 shifted against the documented codes (it called 1
                 "allowed" and 2 "blocked-gravity"; FTL documents 1 =
                 gravity-blocked, 2 = forwarded), and buoys not yet updated
                 still send those labels — the numeric status is the one
                 source that is right on every buoy.
  suricata.dns / .tls / .http / .flow
                 telemetry when the record is protocol metadata. A record
                 whose eve `event_type` is not that protocol (alert,
                 anomaly, drop, …) or that carries an `alert` block is a
                 signal.

Everything else — wazuh.*, datto.*, rocketcyber.*, unifi.*, suricata.alert,
suricata.anomaly, opencanary.*, buoy.* — is a signal (listed below for the
reader; the default does the work).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional

SIGNAL = "signal"
TELEMETRY = "telemetry"

# Severities at which an event is a signal whatever its type: a sender that
# rates a DNS record medium or above is saying it matters.
_ELEVATED = frozenset({"medium", "high", "critical"})

# Documented Pi-hole FTL query status codes → (FTL name, blocked?).
# Source: Pi-hole docs, "Query database → Query status" (FTL v5 codes 0-17,
# v6 adds 18). 0 is "unknown / not yet known" — neither, and fail-safe.
PIHOLE_STATUS: dict[int, tuple[str, Optional[bool]]] = {
    0: ("UNKNOWN", None),                  # status not (yet) known
    1: ("GRAVITY", True),                  # domain in gravity database
    2: ("FORWARDED", False),               # forwarded upstream
    3: ("CACHE", False),                   # replied from cache
    4: ("REGEX", True),                    # regex denylist match
    5: ("DENYLIST", True),                 # exact denylist match
    6: ("EXTERNAL_BLOCKED_IP", True),      # upstream: known blocking-page IP
    7: ("EXTERNAL_BLOCKED_NULL", True),    # upstream: 0.0.0.0 / ::
    8: ("EXTERNAL_BLOCKED_NXRA", True),    # upstream: NXDOMAIN, RA bit unset
    9: ("GRAVITY_CNAME", True),            # gravity, deep CNAME inspection
    10: ("REGEX_CNAME", True),             # regex, deep CNAME inspection
    11: ("DENYLIST_CNAME", True),          # exact denylist, deep CNAME
    12: ("RETRIED", False),                # retried query
    13: ("RETRIED_DNSSEC", False),         # retried but ignored (DNSSEC)
    14: ("IN_PROGRESS", False),            # already forwarded, not again
    15: ("DBBUSY", True),                  # blocked: database busy
    16: ("SPECIAL_DOMAIN", True),          # blocked: special domain
    17: ("CACHE_STALE", False),            # replied from stale cache
    18: ("EXTERNAL_BLOCKED_EDE15", True),  # upstream: EDE 15 "Blocked"
}

# The v6 API reports the status by NAME; v5 called the denylist BLACKLIST.
_PIHOLE_STATUS_BY_NAME: dict[str, Optional[bool]] = {
    name: blocked for name, blocked in PIHOLE_STATUS.values()
}
_PIHOLE_STATUS_BY_NAME.update({
    "BLACKLIST": True,
    "BLACKLIST_CNAME": True,
})

# Suricata eve record types that are metadata when they match the declared
# event type (`suricata.<proto>`).
SURICATA_TELEMETRY_PROTOCOLS = frozenset({"dns", "tls", "http", "flow"})

# Signals by family — documentation for the reader and for the report; the
# fail-safe default already files every one of them as a signal.
SIGNAL_FAMILIES: tuple[str, ...] = (
    "wazuh.*", "datto.*", "rocketcyber.*", "unifi.*", "opencanary.*",
    "buoy.*", "suricata.alert", "suricata.anomaly",
)


@dataclass(frozen=True)
class Classification:
    tier: str       # SIGNAL | TELEMETRY
    reason: str     # short machine-readable why (tests, logs, move report)

    @property
    def is_telemetry(self) -> bool:
        return self.tier == TELEMETRY


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def pihole_status_blocked(status: Any) -> Optional[bool]:
    """True = the documented status is a block, False = answered, None =
    unknown / missing / unparseable (the caller treats None as a signal)."""
    if isinstance(status, bool):
        return None
    if isinstance(status, int):
        entry = PIHOLE_STATUS.get(status)
        return entry[1] if entry else None
    if isinstance(status, str):
        text = status.strip()
        if text.isdigit():
            return pihole_status_blocked(int(text))
        return _PIHOLE_STATUS_BY_NAME.get(text.upper())
    return None


def _pihole_rule(payload: Mapping[str, Any]) -> Classification:
    raw = _mapping(payload.get("raw_query"))
    status = raw.get("status") if "status" in raw else payload.get("status")
    blocked = pihole_status_blocked(status)
    if blocked is None:
        return Classification(SIGNAL, "pihole:status-unknown")
    if blocked:
        return Classification(SIGNAL, "pihole:blocked")
    return Classification(TELEMETRY, "pihole:answered")


def _suricata_rule(protocol: str) -> Callable[[Mapping[str, Any]], Classification]:
    def rule(payload: Mapping[str, Any]) -> Classification:
        if "alert" in payload:
            return Classification(SIGNAL, "suricata:alert-block")
        eve = payload.get("raw_eve")
        if eve is not None:
            if not isinstance(eve, Mapping):
                return Classification(SIGNAL, "suricata:eve-unreadable")
            if "alert" in eve:
                return Classification(SIGNAL, "suricata:alert-block")
            eve_type = eve.get("event_type")
            if eve_type is not None and eve_type != protocol:
                return Classification(SIGNAL, f"suricata:eve-{str(eve_type)[:24]}")
        return Classification(TELEMETRY, f"suricata:{protocol}")
    return rule


# THE registry: event_type → the predicate that may file it as telemetry.
# An event type that is not a key here is a signal.
TELEMETRY_RULES: dict[str, Callable[[Mapping[str, Any]], Classification]] = {
    "pihole.query": _pihole_rule,
    **{f"suricata.{p}": _suricata_rule(p) for p in sorted(SURICATA_TELEMETRY_PROTOCOLS)},
}

TELEMETRY_CANDIDATE_TYPES: frozenset[str] = frozenset(TELEMETRY_RULES)


def classify(
    event_type: Optional[str],
    payload: Any,
    severity: Optional[str] = None,
) -> Classification:
    """Signal or telemetry for one event. Never raises."""
    et = event_type if isinstance(event_type, str) else ""
    rule = TELEMETRY_RULES.get(et)
    if rule is None:
        return Classification(SIGNAL, "type")
    if isinstance(severity, str) and severity.lower() in _ELEVATED:
        return Classification(SIGNAL, "severity")
    if not isinstance(payload, Mapping):
        return Classification(SIGNAL, "payload-unreadable")
    try:
        return rule(payload)
    except Exception:  # noqa: BLE001 — an odd payload is a signal, never an error
        return Classification(SIGNAL, "payload-unreadable")


# ---------------------------------------------------------------------------
# Dimensions for the roll-ups: WHICH domain, WHICH device
# ---------------------------------------------------------------------------

MAX_DOMAIN_CHARS = 253      # the DNS limit — anything longer is not a name
MAX_DEVICE_CHARS = 128


def normalize_domain(value: Any) -> str:
    """Lower-case name without the root dot, or "" when it is not usable as
    one (not text, whitespace/control characters inside, over 253 chars)."""
    if not isinstance(value, str):
        return ""
    text = value.strip().rstrip(".").lower()
    if not text or len(text) > MAX_DOMAIN_CHARS:
        return ""
    if any(c.isspace() or not c.isprintable() for c in text):
        return ""
    return text


def normalize_device(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return ""
    text = str(value).strip()
    if not text or len(text) > MAX_DEVICE_CHARS:
        return ""
    if any(c.isspace() or not c.isprintable() for c in text):
        return ""
    return text


def _first(*values: Any) -> Any:
    for v in values:
        if v not in (None, ""):
            return v
    return None


def _suricata_dns_name(dns: Mapping[str, Any]) -> Any:
    # eve DNS v1/v2 put rrname on the record; v3 lists queries.
    name = dns.get("rrname")
    if name:
        return name
    queries = dns.get("queries")
    if isinstance(queries, list) and queries and isinstance(queries[0], Mapping):
        return queries[0].get("rrname")
    return None


def extract_dimensions(event_type: str, payload: Any) -> tuple[str, str]:
    """(domain, device) for a telemetry event — "" for whichever is unknown.
    `device` is the LAN client (never the buoy that saw it) keyed by its
    ADDRESS wherever the sensor gives one — the key Suricata has, so one
    device is one key across sensors and a search by IP finds Pi-hole rows
    too. The name Pi-hole v6 knows it by is `extract_device_name` (stored
    beside it)."""
    p = _mapping(payload)
    domain: Any = None
    device: Any = None
    if event_type == "pihole.query":
        raw = _mapping(p.get("raw_query"))
        domain = _first(raw.get("domain"), p.get("domain"))
        device = _first(raw.get("client"), p.get("client"),
                        raw.get("client_name"), p.get("client_name"))
    elif event_type.startswith("suricata."):
        eve = _mapping(p.get("raw_eve"))
        proto = event_type.split(".", 1)[1]
        if proto == "dns":
            dns = _mapping(eve.get("dns"))
            domain = _suricata_dns_name(dns)
            # A response travels server → client: the client is the dest.
            if str(dns.get("type", "")).lower() in ("answer", "response"):
                device = eve.get("dest_ip")
            else:
                device = eve.get("src_ip")
        elif proto == "tls":
            domain = _mapping(eve.get("tls")).get("sni")
            device = eve.get("src_ip")
        elif proto == "http":
            domain = _mapping(eve.get("http")).get("hostname")
            device = eve.get("src_ip")
        else:
            device = eve.get("src_ip")
        domain = _first(domain, p.get("domain"), p.get("query"), p.get("rrname"),
                        p.get("sni"), p.get("hostname"))
        device = _first(device, p.get("src_ip"), p.get("client"), p.get("device"))
    return normalize_domain(domain), normalize_device(device)


def extract_device_name(event_type: str, payload: Any) -> str:
    """The NAME the sensor knows the LAN client by (Pi-hole v6's
    `client_by_id.name`), or "" — none, or the same as the address key.
    Stored beside `device` so a device is found by its IP OR its name."""
    if event_type != "pihole.query":
        return ""
    p = _mapping(payload)
    raw = _mapping(p.get("raw_query"))
    name = normalize_device(_first(raw.get("client_name"), p.get("client_name")))
    device = extract_dimensions(event_type, payload)[1]
    return "" if name == device else name


# ---------------------------------------------------------------------------
# Roll-up key and first-seen eligibility
# ---------------------------------------------------------------------------

SURICATA_DNS_ANSWER = "suricata.dns.answer"


def rollup_event_type(event_type: str, payload: Any) -> str:
    """The hourly roll-up's type key for a telemetry event.

    Suricata logs a DNS exchange as TWO eve records — the query and the
    answer (`dns.type` "query" / "answer"; older eve "request" /
    "response") — so counting both as `suricata.dns` makes every lookup two.
    Answer records are rolled up under `suricata.dns.answer` instead, so the
    `suricata.dns` count is queries; the raw row keeps its event type
    untouched. Everything else rolls up under its own type."""
    if event_type == "suricata.dns":
        dns = _mapping(_mapping(_mapping(payload).get("raw_eve")).get("dns"))
        if str(dns.get("type", "")).lower() in ("answer", "response"):
            return SURICATA_DNS_ANSWER
    return event_type


# Names that are never "a domain the tenant had not looked up before" in a
# useful sense: reverse lookups (one per new address — PTR queries under
# in-addr.arpa / ip6.arpa, home.arpa), multicast-DNS names, and single-label
# names — Chrome's intranet-redirect probes (three random labels at every
# browser start or network change) and bare LAN host names. They are still
# COUNTED in the roll-up; they just never enter the first-seen ledger.
_NOT_NOVEL_SUFFIXES = (".arpa", ".local")


def first_seen_eligible(domain: str) -> bool:
    """Whether a (normalised) name may enter the first-seen ledger.

    Deliberately NOT excluded: names that did not resolve (NXDOMAIN). A
    never-seen name that does not exist is what DGA malware looks like —
    exactly what the first-seen list is for; the noise the rule removes
    (PTR churn, random single-label probes) is recognisable by the name."""
    if not domain or "." not in domain:
        return False
    if domain in ("arpa", "local", "localhost") or domain.endswith(_NOT_NOVEL_SUFFIXES):
        return False
    return True


# ---------------------------------------------------------------------------
# Classifying STORED events.db rows in SQL (aggregate reads)
# ---------------------------------------------------------------------------
#
# The DNS summary counts the Pi-hole lookups events.db holds by what they
# ARE — blocked (signals) vs answered rows that only sit there because the
# telemetry store refused them at ingest (the nightly sweep moves them) —
# without parsing every payload in Python on every dashboard poll. SQLite
# extracts exactly the fields the rules above read; rows are grouped by
# them, and each group is classified ONCE by `classify()` itself on a
# payload rebuilt from those fields. A parity test runs every rule fixture
# through both paths.

_J = "CASE WHEN json_valid(payload) THEN {} END"

STORED_FEATURES_SQL = ", ".join(_J.format(e) for e in (
    "json_type(payload)",
    "json_type(payload, '$.raw_query.status')",
    "json_extract(payload, '$.raw_query.status')",
    "json_type(payload, '$.status')",
    "json_extract(payload, '$.status')",
    "json_type(payload, '$.alert')",
    "json_type(payload, '$.raw_eve')",
    "json_type(payload, '$.raw_eve.alert')",
    "json_type(payload, '$.raw_eve.event_type')",
    "json_extract(payload, '$.raw_eve.event_type')",
))
"""SELECT-list expressions (10 columns) for `classify_stored`; the table
must have a `payload` column."""

_JSON_SCALARS: dict[str, Callable[[Any], Any]] = {
    "true": lambda _v: True,
    "false": lambda _v: False,
    "null": lambda _v: None,
    "integer": int,
    "real": float,
    "text": str,
    "object": lambda _v: {},
    "array": lambda _v: [],
}


def _value(json_type: Optional[str], value: Any) -> Any:
    conv = _JSON_SCALARS.get(json_type or "")
    return conv(value) if conv is not None else value


def classify_stored(
    event_type: Optional[str], severity: Optional[str], features: tuple,
) -> Classification:
    """`classify()` for a stored row, from its `STORED_FEATURES_SQL` values."""
    (ptype, st_q_type, st_q, st_type, st, alert_type, eve_type, eve_alert_type,
     eve_et_type, eve_et) = features
    if ptype != "object":
        return classify(event_type, None, severity)
    payload: dict[str, Any] = {}
    if st_q_type is not None:
        payload["raw_query"] = {"status": _value(st_q_type, st_q)}
    if st_type is not None:
        payload["status"] = _value(st_type, st)
    if alert_type is not None:
        payload["alert"] = True
    if eve_type is not None:
        if eve_type == "object":
            eve: Any = {}
            if eve_alert_type is not None:
                eve["alert"] = True
            if eve_et_type is not None:
                eve["event_type"] = _value(eve_et_type, eve_et)
        elif eve_type == "null":
            eve = None
        else:
            eve = "not-a-mapping"          # a scalar / array: unreadable
        payload["raw_eve"] = eve
    return classify(event_type, payload, severity)
