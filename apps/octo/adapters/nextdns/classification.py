"""Which NextDNS block reasons are SIGNALS — the one table.

A NextDNS log line is blocked for one or more `reasons` ({id, name}). Most
blocks are policy doing its job (ad / tracker blocklists, TLD bans, the
denylist, parental controls): counted in the hourly roll-up, never an alert.
A few say a device reached for something dangerous — THOSE are signals.

  HIGH    threat-intelligence-feeds, googlesafebrowsing, cryptojacking, dga,
          csam, and any dns-data-exfiltration / dns-payload-delivery /
          tunneling-endpoints / fast-flux-networks id
  MEDIUM  ai-threat-detection, typosquatting, idn-homographs, nrd,
          newly-active-domains, ddns, free-hosting, parked-domains,
          residential-hosting, decentralized-web-gateways, data-drop-services,
          untrusted-certificates, bypass-methods (policy evasion: VPN / proxy /
          Tor)
  LOW     drp (DNS-rebinding protection — often a benign local device)
  NOT A SIGNAL
          blocklist:*, tld:*, denylist, disguised-trackers, safesearch-*,
          native:*, parental-control categories and services, and anything
          clearly ad / tracker / content policy

FAIL-SAFE: an id this table does not know, and that is not a list-type id
(blocklist:, tld:, native:, …), is a LOW signal — a new NextDNS security
feature must surface, never vanish into the roll-up. Security features not
seen live yet get kebab-case ids derived from their settings keys; a few
plausible spellings are accepted, and the fail-safe covers the rest.

A line whose reasons include ANY signal-class id is a signal at the highest
matching level; its PRIMARY reason is the first reason at that level —
except (v0.17.1, Rick 2026-10-06) that a RESTRICTED reason (csam) is always
primary, and a DEVICE-ORIGINATED reason (dga / domain-generation-algorithms,
tunneling-endpoints, dns-data-exfiltration, dns-payload-delivery: software,
not a person, makes those lookups) comes before any other HIGH reason — so
a line carrying one is filed under it, whatever order NextDNS lists them in.

RESTRICTED (csam): never a fleet colour and never an ordinary alert — the
poller keeps such a line ONLY as restricted evidence
(`apps.octo.threat.restricted`) and the tier engine opens rule B7 (an
automated, restricted Black) from it.

COALESCING SHAPE — owner decision (Rick, 2026-09-30), "split by severity":
  * HIGH reasons: ONE alert per (profile, device or client IP, ROOT domain,
    reason) per CLOCK HOUR — immediate and specific;
  * DGA (HIGH) leaves the root out: one alert per (profile, device, reason)
    per clock hour, counting the distinct domains — an infected device looks
    up a NEW algorithm-generated domain every time;
  * MEDIUM and LOW reasons (ai-threat-detection, nrd, typosquatting, ddns,
    free-hosting, parked-domains, bypass-methods, drp, homographs,
    residential / free hosting, and the unknown → LOW fail-safe): ONE alert
    per (profile, device, reason) per UTC DAY, whatever the domain — the
    note counts the lookups and the distinct domains, with a few masked
    samples. A busy site is about one alert per device per reason per day.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, Optional

HIGH = "high"
MEDIUM = "medium"
LOW = "low"

LEVEL_RANK = {LOW: 1, MEDIUM: 2, HIGH: 3}

BYPASS_REASON = "bypass-methods"
DNS_REBINDING_REASON = "drp"

# id → (level, label). Labels read in "NextDNS blocked <label> — <device>".
SIGNAL_REASONS: dict[str, tuple[str, str]] = {
    # HIGH
    "threat-intelligence-feeds": (HIGH, "a threat-intelligence domain"),
    "googlesafebrowsing": (HIGH, "a Google Safe Browsing threat"),
    "google-safe-browsing": (HIGH, "a Google Safe Browsing threat"),
    "cryptojacking": (HIGH, "a cryptojacking domain"),
    "dga": (HIGH, "a DGA (algorithm-generated) domain"),
    "domain-generation-algorithms": (HIGH, "a DGA (algorithm-generated) domain"),
    "csam": (HIGH, "a CSAM domain"),
    "dns-data-exfiltration": (HIGH, "DNS data exfiltration"),
    "dns-payload-delivery": (HIGH, "DNS payload delivery"),
    "tunneling-endpoints": (HIGH, "a DNS tunneling endpoint"),
    "fast-flux-networks": (HIGH, "a fast-flux network"),
    # MEDIUM
    "ai-threat-detection": (MEDIUM, "an AI-detected threat"),
    "typosquatting": (MEDIUM, "a typosquatting domain"),
    "idn-homographs": (MEDIUM, "an IDN homograph domain"),
    "idn-homograph-attacks": (MEDIUM, "an IDN homograph domain"),
    "nrd": (MEDIUM, "a newly registered domain"),
    "newly-registered-domains": (MEDIUM, "a newly registered domain"),
    "newly-active-domains": (MEDIUM, "a newly active domain"),
    "ddns": (MEDIUM, "a dynamic-DNS domain"),
    "dynamic-dns": (MEDIUM, "a dynamic-DNS domain"),
    "free-hosting": (MEDIUM, "a free-hosting domain"),
    "parked-domains": (MEDIUM, "a parked domain"),
    "parking": (MEDIUM, "a parked domain"),
    "residential-hosting": (MEDIUM, "a residential-hosting domain"),
    "decentralized-web-gateways": (MEDIUM, "a decentralized-web gateway"),
    "data-drop-services": (MEDIUM, "a data-drop service"),
    "untrusted-certificates": (MEDIUM, "a domain with an untrusted certificate"),
    BYPASS_REASON: (MEDIUM, "a DNS-filter bypass (VPN / proxy / Tor)"),
    # LOW
    DNS_REBINDING_REASON: (LOW, "a DNS-rebinding answer"),
    "dns-rebinding": (LOW, "a DNS-rebinding answer"),
    "dns-rebinding-protection": (LOW, "a DNS-rebinding answer"),
}

# "Any … id": the families below are HIGH whatever prefix / suffix NextDNS
# puts around them.
HIGH_FAMILIES: tuple[str, ...] = (
    "dns-data-exfiltration", "dns-payload-delivery", "tunneling-endpoints",
    "fast-flux-networks",
)

# RESTRICTED (Rick, 2026-10-06): "confirmed CSAM lookups is an automated
# Black Tier item" — law-enforcement territory. Never an ordinary alert, never
# in a fleet count or a "top reasons" list, never enriched or previewed.
# The id "csam" has not been confirmed against a live log line (the module
# note above), so the match is deliberately LOOSE — a miss would file a CSAM
# lookup as an ordinary LOW alert (domain in events.db, no Black, no page):
# any id with a "csam" token ("csam", "blocklist:csam", "csam-list") or a
# "child sexual abuse" phrase in any spelling, and any reason NAME saying so.
CSAM_REASONS: frozenset[str] = frozenset({"csam"})
CSAM_KEY = "csam"
_CSAM_TOKEN = re.compile(r"(?:^|[^a-z0-9])csam(?:$|[^a-z0-9])")
_CSAM_PHRASE = re.compile(r"child[^a-z0-9]*sexual[^a-z0-9]*abuse")

# Reasons SOFTWARE makes, not a person (Rick, 2026-10-06): ONE block in these
# makes the device Yellow ("the device looks wrong").
DEVICE_ORIGINATED_REASONS: frozenset[str] = frozenset({
    "dga", "domain-generation-algorithms", "tunneling-endpoints", "dns-data-exfiltration",
    "dns-payload-delivery",
})
# …and any id of those families with a prefix / suffix NextDNS adds.
DEVICE_ORIGINATED_FAMILIES: tuple[str, ...] = (
    "tunneling-endpoints", "dns-data-exfiltration", "dns-payload-delivery",
)


def is_csam(reason_id: Any) -> bool:
    """A RESTRICTED (CSAM) reason id — "csam", any id with a "csam" token,
    or a "child sexual abuse" phrase in any spelling (loose on purpose)."""
    rid = _norm(reason_id)
    return bool(rid) and (rid in CSAM_REASONS or _CSAM_TOKEN.search(rid) is not None
                          or _CSAM_PHRASE.search(rid) is not None)


def name_is_csam(name: Any) -> bool:
    """A reason NAME that says CSAM ("Child Sexual Abuse Material", "CSAM")."""
    return is_csam(name)


def line_is_csam(reasons: Any) -> bool:
    """True when ANY reason of a log line is a CSAM reason (wherever NextDNS
    lists it) — by its id or by its name."""
    return any(is_csam(rid) or name_is_csam(name) for rid, name in _reason_items(reasons))


def is_device_originated(reason_id: Any) -> bool:
    rid = _norm(reason_id)
    return rid in DEVICE_ORIGINATED_REASONS or any(f in rid for f in DEVICE_ORIGINATED_FAMILIES)


# HIGH reasons whose blocks are about MANY distinct domains by nature:
# coalesced per (profile, device, reason, hour) — the root domain is not in
# the key. (Every MEDIUM / LOW reason is domain-agnostic too: per day.)
CROSS_DOMAIN_REASONS: frozenset[str] = frozenset({"dga", "domain-generation-algorithms"})

# NextDNS parental-control SERVICES (github.com/nextdns/services) — a blocked
# app / site is content policy, never a security signal.
PARENTAL_CONTROL_SERVICES: frozenset[str] = frozenset({
    "9gag", "amazon", "bereal", "blizzard", "chatgpt", "dailymotion", "discord",
    "disneyplus", "ebay", "facebook", "fortnite", "google-chat", "hbomax", "hulu",
    "imgur", "instagram", "leagueoflegends", "mastodon", "messenger", "minecraft",
    "netflix", "pinterest", "playstation-network", "primevideo", "reddit", "roblox",
    "signal", "skype", "snapchat", "spotify", "steam", "telegram", "tiktok", "tinder",
    "tumblr", "twitch", "twitter", "vimeo", "vk", "whatsapp", "xboxlive", "youtube",
    "zoom",
})

# Policy blocks — counted, never an alert.
NOT_SIGNAL_EXACT: frozenset[str] = frozenset({
    "denylist", "disguised-trackers", "blocked-by-denylist",
    # Parental-control categories and similar content policy.
    "porn", "gambling", "dating", "piracy", "social-networks", "gaming",
    "online-gaming", "video-streaming", "recreation", "youtube-restricted-mode",
    "safesearch", "safe-search",
    # Privacy / tracker features.
    "affiliate-tracking-links", "tracking", "trackers", "ads",
}) | PARENTAL_CONTROL_SERVICES
NOT_SIGNAL_PREFIXES: tuple[str, ...] = (
    "blocklist:", "tld:", "native:", "safesearch", "safe-search",
    "parental-control", "parentalcontrol", "parental_control",
    "category:", "categories:", "service:", "services:", "recreation:",
    "privacy:", "tracker:", "trackers:", "ads:",
)


@dataclass(frozen=True)
class ReasonClass:
    id: str
    level: Optional[str]        # HIGH | MEDIUM | LOW | None (not a signal)
    label: str
    known: bool                 # False = the fail-safe decided it

    @property
    def is_signal(self) -> bool:
        return self.level is not None


def _norm(reason_id: Any) -> str:
    return reason_id.strip().lower() if isinstance(reason_id, str) else ""


def classify_reason(reason_id: Any, name: Any = None) -> ReasonClass:
    """The class of one reason id. Never raises."""
    rid = _norm(reason_id)
    shown = name.strip()[:64] if isinstance(name, str) and name.strip() else rid
    if not rid:
        # A blocked line without a readable reason: fail-safe low.
        return ReasonClass("", LOW, "an unexplained block", False)
    known = SIGNAL_REASONS.get(rid)
    if known is not None:
        return ReasonClass(rid, known[0], known[1], True)
    if is_csam(rid) or name_is_csam(name):
        # A CSAM spelling the table does not list: HIGH, never the LOW
        # fail-safe (the poller keeps such a line as restricted evidence).
        return ReasonClass(rid, HIGH, SIGNAL_REASONS[CSAM_KEY][1], True)
    for family in HIGH_FAMILIES:
        if family in rid:
            return ReasonClass(rid, HIGH, SIGNAL_REASONS[family][1], True)
    if rid in NOT_SIGNAL_EXACT or rid.startswith(NOT_SIGNAL_PREFIXES):
        return ReasonClass(rid, None, shown, True)
    # Unknown and not list-type → LOW signal (fail-safe).
    return ReasonClass(rid, LOW, f"“{shown[:48]}”", False)


@dataclass(frozen=True)
class LineClass:
    level: Optional[str]
    primary: Optional[ReasonClass]
    reasons: tuple[ReasonClass, ...]

    @property
    def is_signal(self) -> bool:
        return self.level is not None


def _reason_items(reasons: Any) -> Iterable[tuple[Any, Any]]:
    if not isinstance(reasons, list):
        return ()
    out = []
    for item in reasons[:32]:
        if isinstance(item, dict):
            out.append((item.get("id"), item.get("name")))
        elif isinstance(item, str):
            out.append((item, None))
    return out


def classify_line(reasons: Any) -> LineClass:
    """The class of a blocked log line from its `reasons`: the highest level
    among them; the primary reason is the first one at that level. A line
    that names no reason at all is not a signal: the analytics that trigger
    a log pull never count it, so it can only ride along in a pull another
    signal caused. (A reason entry with a blank or unknown id IS — the
    fail-safe of `classify_reason`.)"""
    classes = tuple(classify_reason(rid, name) for rid, name in _reason_items(reasons))
    if not classes:
        return LineClass(None, None, ())
    best: Optional[ReasonClass] = None
    for rc in classes:
        if rc.level is None:
            continue
        if best is None or _precedence(rc) > _precedence(best):
            best = rc
    return LineClass(best.level if best else None, best, classes)


def _precedence(rc: ReasonClass) -> tuple[int, int]:
    """Level first; within a level a CSAM reason, then a device-originated
    one, then the rest (the first listed wins a tie)."""
    rank = 2 if is_csam(rc.id) else 1 if is_device_originated(rc.id) else 0
    return LEVEL_RANK[rc.level or LOW], rank


def short_label(reason_id: Any) -> str:
    """"threat-intelligence domain", "DGA (algorithm-generated) domain" — a
    reason's label without its article (the operator's "top reasons")."""
    label = classify_reason(reason_id).label
    for article in ("a ", "an "):
        if label.startswith(article):
            return label[len(article):]
    return label


def bucket_span(level: Optional[str]) -> str:
    """The coalescing span of a signal: "hour" for HIGH, "day" otherwise."""
    return "hour" if level == HIGH else "day"


def is_cross_domain(reason_id: Any, level: Optional[str] = None) -> bool:
    """True when the reason's buckets leave the root domain out: DGA, and
    every MEDIUM / LOW reason. `level` = the line's signal level (default:
    the reason's own)."""
    if _norm(reason_id) in CROSS_DOMAIN_REASONS:
        return True
    if level is None:
        level = classify_reason(reason_id).level
    return level in (MEDIUM, LOW)


def signal_reason_counts(reasons: dict[str, tuple[str, int]]) -> dict[str, int]:
    """{reason id: queries} for the signal-class reasons with a count. Every
    CSAM spelling (by id or by name) is counted under "csam" — so the Fleet,
    which takes CSAM out of every count, finds it whatever NextDNS calls it."""
    out: dict[str, int] = {}
    for rid, (name, count) in reasons.items():
        if count > 0 and classify_reason(rid, name).is_signal:
            key = CSAM_KEY if (is_csam(rid) or name_is_csam(name)) else rid
            out[key] = out.get(key, 0) + count
    return out


def class_counts(reasons: dict[str, tuple[str, int]]) -> dict[str, int]:
    """Blocked queries by reason class: high / medium / low / policy."""
    out = {HIGH: 0, MEDIUM: 0, LOW: 0, "policy": 0}
    for rid, (name, count) in reasons.items():
        level = classify_reason(rid, name).level
        out[level or "policy"] += max(0, int(count))
    return out
