"""Heuristic L1 triage engine — deterministic, pure, no I/O (Task #119a).

The "brain" of the autonomous Triage L1 agent. Given a feature set for a
single event, it returns a triage decision: a disposition from the
autonomous taxonomy, a suggested severity, a confidence, and an
operator-readable rationale.

Design principles
-----------------
* **Pure.** No database access, no clock, no network. All context the
  engine needs (recurrence counts, indicator hits, known-FP match) is
  computed by the worker (119b) and passed in as `TriageFeatures`. This
  makes the engine exhaustively unit-testable and keeps it invariant to
  how/where the worker runs.
* **Deterministic.** Same features → same decision, every time. No
  randomness, no model calls. The LLM only enters the picture *after*
  this engine returns `uncertain` (handled in 119c), never inside it.
* **Confident on the clear cases, humble on the rest.** The whole point
  of the `uncertain` disposition is to hand the ambiguous middle off to
  the LLM (or a human). So the engine returns high confidence only when
  a rule fires cleanly, and falls through to a low-confidence
  `uncertain` otherwise.

Disposition taxonomy (mirrors apps/octo_llm/models.py `Disposition`):

  * ``noise``     — auto-suppress (+ future upstream round-trip closure)
  * ``pattern``   — recognized recurring pattern; flag inline, do NOT
                    bump severity
  * ``escalate``  — severity bump + (future) auto-create ticket
  * ``uncertain`` — defer to LLM/analyst; the agent takes NO autonomous
                    action

Rules are evaluated in order; the first match wins. Order matters —
the most decisive / highest-stakes rules come first so a critical alert
is never accidentally swallowed by a recurrence rule.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

# These mirror the canonical sets in shared_adapter_contract.types and
# apps/octo_llm/models.py. Redefined locally (not imported) to avoid a
# cross-package import from the data-plane engine into the LLM sibling;
# the values are identical and guarded by tests.
Severity = Literal["info", "low", "medium", "high", "critical"]
Disposition = Literal["noise", "pattern", "escalate", "uncertain"]

# Severity ordering for comparisons.
_SEVERITY_RANK: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

# --- Tunable thresholds -----------------------------------------------------
# Recurrence count at/above which a LOW/INFO event is suppressed as noise.
RECUR_NOISE_THRESHOLD = 5
# Recurrence count at/above which a MEDIUM event is treated as a recognized
# pattern (flagged, severity unchanged) rather than escalated.
RECUR_PATTERN_THRESHOLD = 3

# Confidence constants. Calibration is a post-launch workstream (the
# response is marked calibration_state='uncalibrated' downstream); these
# are deliberate, ordered, and documented rather than tuned.
_CONF_KNOWN_FP = 0.95
_CONF_VENDOR_CLOSURE = 0.92
_CONF_DNS_FILTER = 0.90
_CONF_NETWORK = 0.88
_CONF_CRITICAL_ESCALATE = 0.90
_CONF_HIGH_ESCALATE = 0.85
_CONF_RECUR_NOISE = 0.85
_CONF_INFO_NOISE = 0.80
_CONF_RECUR_PATTERN = 0.80
_CONF_INDICATOR_ESCALATE = 0.78
_CONF_LOW_NOISE = 0.70
_CONF_UNCERTAIN = 0.30


@dataclass(frozen=True)
class VendorClosure:
    """The event is a VENDOR-REPORTED CLOSURE of an incident the vendor
    raised earlier (RocketCyber: the incident's status became resolved /
    suppressed — its SOC closed it). Gathered by the worker; the engine
    only reads it."""

    vendor: str
    """Display name, e.g. "RocketCyber"."""
    status: str
    """The closing status as the vendor reports it (lower case)."""
    incident_id: str | None = None
    """The vendor's incident id, when it has one."""
    open_event_id: int | None = None
    """This tenant's earlier stored OPEN row of the same incident (the one
    the triage worker escalated), when it is in the store."""


@dataclass(frozen=True)
class DnsFilterEvent:
    """The event is a DNS-filtering record (NextDNS): a security block, or
    the filtering of a site lapsing / resuming. Gathered by the worker (or
    by the NextDNS poller for the low-severity restoration it notes itself);
    the engine only reads it."""

    kind: Literal["block", "lapsed", "restored", "fleet_outage"]
    level: str = "medium"
    """The block's signal level (high / medium / low)."""
    reason_id: str = ""
    """NextDNS reason id of a block ("threat-intelligence-feeds", …)."""
    reason_label: str = ""
    device: str = ""
    """The device's name, else its client IP ("" when unknown)."""
    profile: str = ""
    """The NextDNS profile (site) the record is about."""
    lapse_event_id: int | None = None
    """For a restoration: this tenant's stored LAPSED alert, when known."""
    lapsed_since: str | None = None
    restored_hour: str | None = None
    cause: str = ""
    """For a lapse: why ("" / "no_queries" — the site stopped reporting;
    "before_watch" — already dark when mapped; "not_visible" /
    "not_accessible" — the API key no longer sees the profile; "logs_off" —
    logging was turned off at NextDNS)."""
    fleet_sites: int | None = None
    fleet_watched: int | None = None
    """A fleet-wide outage: how many of the watched sites went dark at once
    (on the fleet signal, and on a site's lapse grouped under it)."""


@dataclass(frozen=True)
class NetworkEvent:
    """The event is a UniFi gateway record (the UniFi connector adapter): an
    IPS detection / block, a rogue AP, administrator access or a
    configuration change on the console, a WAN / VPN availability change.
    Gathered by the worker from the stored payload; the engine only reads it."""

    kind: str
    """Catalogue kind: ips_threat | rogue_ap | admin_activity | config_change |
    wan_down | wan_failover | wan_restored | vpn_down | system_event |
    isp_outage (Fleet v2: N sites on one ISP down at once)."""
    site: str = ""
    """The UniFi site (and console) the record is about."""
    device: str = ""
    """The LAN device of an IPS event (its UniFi name, else its LAN IP)."""
    action: str = ""
    """IPS: 'detected' (NOT blocked) or 'blocked'."""
    signature: str = ""
    remote: str = ""
    """IPS: the public remote address (the IOC), when there is one."""
    isp: str = ""
    """ISP outage: the provider's name."""
    asn: int = 0
    sites: int = 0
    """ISP outage: how many sites went down at once."""


# The NextDNS policy-evasion reason (VPN / proxy / Tor lookups).
DNS_BYPASS_REASON = "bypass-methods"
DNS_REBINDING_REASONS = frozenset({"drp", "dns-rebinding", "dns-rebinding-protection"})


@dataclass(frozen=True)
class TriageFeatures:
    """Everything the pure engine needs to decide, gathered by the worker.

    The worker (119b) derives these from the event row plus per-tenant
    context (recurrence over events.db, indicator hits over indicators.db,
    tenant false-positive rules). The engine itself never touches a DB.
    """

    severity: Severity
    """Heuristic/canonical severity as set by the source adapter's
    severity_map — the engine's starting point."""

    has_indicator: bool
    """True if the event carries an IOC (ip/domain/url/hash)."""

    indicator_hits: int = 0
    """How many times this IOC has been seen before for THIS tenant
    (0 if novel or no indicator). A repeat hit on a known indicator
    raises stakes."""

    recurrence_count: int = 0
    """How many prior events share this event's recurrence signature
    (same host + event shape) for this tenant. High recurrence at low
    severity = noise; at medium = recognized pattern."""

    known_false_positive: bool = False
    """True if the event matches a tenant-defined false-positive rule.
    (Seam for a future per-tenant FP ruleset; defaults False today.)"""

    vendor_closure: VendorClosure | None = None
    """Set when the event is a vendor-reported closure of an incident
    (`VendorClosure`)."""

    dns_filter: DnsFilterEvent | None = None
    """Set when the event is a DNS-filtering record (`DnsFilterEvent`)."""

    network: NetworkEvent | None = None
    """Set when the event is a UniFi gateway record (`NetworkEvent`)."""


@dataclass(frozen=True)
class TriageDecision:
    """The engine's verdict for one event."""

    disposition: Disposition
    suggested_severity: Severity
    confidence: float
    rationale: str
    """Operator-readable one-liner; becomes the autonomous agent_note body
    (prefixed with the disposition by `note_text`)."""

    def note_text(self) -> str:
        """The text persisted as the autonomous agent_note body."""
        return f"[{self.disposition}] {self.rationale}"


def triage(f: TriageFeatures) -> TriageDecision:
    """Map a feature set to a triage decision. Pure + deterministic.

    Rules are ordered most-decisive-first; first match wins.
    """
    sev_rank = _SEVERITY_RANK[f.severity]

    # 1. Tenant-defined known false positive → suppress, very confident.
    if f.known_false_positive:
        return TriageDecision(
            disposition="noise",
            suggested_severity=f.severity,
            confidence=_CONF_KNOWN_FP,
            rationale="Matches a known false-positive rule for this tenant.",
        )

    # 1b. A vendor-reported CLOSURE of an incident (RocketCyber: resolved /
    #     suppressed by its SOC) → no action: the record is the vendor
    #     telling us the incident it raised is closed, not a new alert. It
    #     used to fall through to "uncertain — deferring to LLM/analyst" (a
    #     single medium with no context) and sat as a to-do. Only at medium
    #     or below: a closure a vendor rates high/critical still escalates.
    if f.vendor_closure is not None and sev_rank <= _SEVERITY_RANK["medium"]:
        vc = f.vendor_closure
        what = f"incident {vc.incident_id}" if vc.incident_id else "an incident"
        earlier = (
            f"the closure of the open incident recorded as event #{vc.open_event_id}"
            if vc.open_event_id is not None
            else "its open record is not in this tenant's store"
        )
        return TriageDecision(
            disposition="noise",
            suggested_severity=f.severity,
            confidence=_CONF_VENDOR_CLOSURE,
            rationale=(
                f"{vc.vendor} reports {what} {vc.status} — {earlier}. "
                "Vendor-reported closure; no action needed."
            ),
        )

    # 1c. DNS filtering (NextDNS) — deterministic notes that say what the
    #     record MEANS: a blocked lookup never connected; evasion is a policy
    #     question about one device; a lapse is a site's filtering gone.
    if f.dns_filter is not None:
        return _dns_filter_decision(f)

    # 1d. UniFi gateway records — deterministic notes that say what the
    #     record MEANS (an unknown kind falls through to the generic rules).
    if f.network is not None:
        decision = _network_decision(f)
        if decision is not None:
            return decision

    # 2. Critical / high severity → escalate. Never let a recurrence or
    #    noise rule swallow a high-stakes alert, so this comes early.
    if f.severity == "critical":
        return TriageDecision(
            disposition="escalate",
            suggested_severity="critical",
            confidence=_CONF_CRITICAL_ESCALATE,
            rationale=(
                "Critical-severity alert"
                + (" on a previously-seen indicator" if f.indicator_hits > 0 else "")
                + "; auto-escalated for analyst attention."
            ),
        )
    if f.severity == "high":
        return TriageDecision(
            disposition="escalate",
            suggested_severity="high",
            confidence=_CONF_HIGH_ESCALATE,
            rationale=(
                "High-severity alert"
                + (" on a previously-seen indicator" if f.indicator_hits > 0 else "")
                + "; auto-escalated for analyst attention."
            ),
        )

    # 3. Recurring low/info → noise. A low-value event seen many times on
    #    the same host is the canonical noise case.
    if f.recurrence_count >= RECUR_NOISE_THRESHOLD and sev_rank <= _SEVERITY_RANK["low"]:
        return TriageDecision(
            disposition="noise",
            suggested_severity=f.severity,
            confidence=_CONF_RECUR_NOISE,
            rationale=(
                f"Recurring low-severity event (seen {f.recurrence_count}× on this "
                "host); suppressing as noise."
            ),
        )

    # 4. Recurring medium → recognized pattern: flag, but don't bump severity.
    if f.recurrence_count >= RECUR_PATTERN_THRESHOLD and f.severity == "medium":
        return TriageDecision(
            disposition="pattern",
            suggested_severity="medium",
            confidence=_CONF_RECUR_PATTERN,
            rationale=(
                f"Recurring medium-severity pattern (seen {f.recurrence_count}×); "
                "flagged as a recognized pattern, severity unchanged."
            ),
        )

    # 5. Medium severity tied to a previously-seen indicator → escalate.
    if f.severity == "medium" and f.indicator_hits > 0:
        return TriageDecision(
            disposition="escalate",
            suggested_severity="high",
            confidence=_CONF_INDICATOR_ESCALATE,
            rationale=(
                f"Medium alert tied to a previously-seen indicator "
                f"(seen {f.indicator_hits}×); escalating."
            ),
        )

    # 6. Informational single event → noise (high-volume, low-value).
    if f.severity == "info":
        return TriageDecision(
            disposition="noise",
            suggested_severity="info",
            confidence=_CONF_INFO_NOISE,
            rationale="Informational single event; suppressing as noise.",
        )

    # 7. Low severity, no indicator, not recurring → noise.
    if f.severity == "low" and not f.has_indicator:
        return TriageDecision(
            disposition="noise",
            suggested_severity="low",
            confidence=_CONF_LOW_NOISE,
            rationale="Low-severity single event with no indicator; suppressing as noise.",
        )

    # 8. Everything ambiguous (single medium with no prior context; a low
    #    event that DOES carry a novel indicator) → uncertain. This is the
    #    hand-off point: 119c may consult the LLM; otherwise an analyst
    #    reviews. The agent takes no autonomous action on `uncertain`.
    return TriageDecision(
        disposition="uncertain",
        suggested_severity=f.severity,
        confidence=_CONF_UNCERTAIN,
        rationale=(
            "Ambiguous signal with no decisive heuristic; deferring to "
            "LLM/analyst review."
        ),
    )


def _hour_text(value: str | None) -> str:
    text = (value or "").strip()
    return f"{text[:10]} {text[11:16]} UTC" if len(text) >= 16 else "an unknown time"


def _dns_filter_decision(f: TriageFeatures) -> TriageDecision:
    """Rule 1c. The wording is the owner's (2026-09-30):
      * blocked threat → "Blocked by NextDNS before any connection. If this
        repeats or is C2/threat-intel, check <device> for the source."
      * bypass-methods → "A device is trying to evade DNS filtering
        (VPN/proxy/Tor)".
    Dispositions: a HIGH block (threat intel, Safe Browsing, cryptojacking,
    DGA, CSAM, tunnelling …) escalates — the device reached for it, so
    something on it may be compromised; a MEDIUM block or an evasion attempt
    is a recognised pattern (flagged, severity unchanged); a LOW block
    (DNS-rebinding protection) is noise; a lapse escalates (a site lost its
    filtering) — unless it is grouped under a fleet-wide outage (a pattern:
    the ONE fleet signal escalates, not every site); a restoration is noise
    (good news, linked to its lapse)."""
    d = f.dns_filter
    assert d is not None
    device = d.device or "the device"
    at_once = (f"{d.fleet_sites} of {d.fleet_watched} sites stopped reporting at the same time"
               if d.fleet_sites and d.fleet_watched else "")
    if d.kind == "fleet_outage":
        return TriageDecision(
            disposition="escalate",
            suggested_severity=f.severity,
            confidence=_CONF_DNS_FILTER,
            rationale=(
                f"{at_once or 'Many sites stopped reporting at the same time'} "
                f"(since {_hour_text(d.lapsed_since)}) — one shared cause is likely: check "
                "NextDNS status first, then the UniFi DNS template / gateway DNS settings "
                "pushed to those sites. Each site's own lapse is grouped under this incident."
            ),
        )
    if d.kind == "lapsed" and at_once:
        where = f" for {d.profile}" if d.profile else ""
        return TriageDecision(
            disposition="pattern",
            suggested_severity=f.severity,
            confidence=_CONF_DNS_FILTER,
            rationale=(
                f"DNS filtering stopped reporting{where} — and {at_once}: part of a "
                "fleet-wide outage with likely one shared cause (NextDNS itself, or a DNS "
                "template pushed to many sites), tracked as ONE incident by the MSP. No "
                "separate escalation for this site; check it once the incident is resolved."
            ),
        )
    if d.kind == "lapsed":
        where = f" for {d.profile}" if d.profile else ""
        if d.cause in ("not_visible", "not_accessible"):
            rationale = (
                f"NextDNS no longer lets Athena's API key see the profile{where} "
                "(deleted, or no longer shared with the account) — check the profile at "
                "my.nextdns.io. Until it is visible again, this site's DNS filtering "
                "cannot be watched."
            )
        elif d.cause == "logs_off":
            rationale = (
                f"Logging was turned off at NextDNS{where}, so its queries are no longer "
                "reported — turn it back on (my.nextdns.io → Settings → Logs) if that was "
                "not intended. Filtering itself may still be working."
            )
        else:
            rationale = (
                f"DNS filtering stopped reporting{where} — check the site's UniFi "
                "DNS/NextDNS setup (a changed gateway DNS server, a removed "
                "NextDNS link, or the site is offline). Until it resumes, this "
                "site's lookups are not filtered."
            )
        return TriageDecision(
            disposition="escalate",
            suggested_severity=f.severity,
            confidence=_CONF_DNS_FILTER,
            rationale=rationale,
        )
    if d.kind == "restored":
        lapse = (
            f"the lapse recorded as event #{d.lapse_event_id}"
            if d.lapse_event_id is not None else "the earlier lapse"
        )
        return TriageDecision(
            disposition="noise",
            suggested_severity=f.severity,
            confidence=_CONF_DNS_FILTER,
            rationale=(
                f"DNS filtering resumed{' for ' + d.profile if d.profile else ''}: "
                f"NextDNS is reporting queries again (from {_hour_text(d.restored_hour)}) "
                f"after {lapse} (no queries since {_hour_text(d.lapsed_since)}). No "
                "action needed — confirm the gap was expected (maintenance, an outage)."
            ),
        )
    if d.reason_id == DNS_BYPASS_REASON:
        return TriageDecision(
            disposition="pattern",
            suggested_severity=f.severity,
            confidence=_CONF_DNS_FILTER,
            rationale=(
                f"A device is trying to evade DNS filtering (VPN/proxy/Tor) — {device}. "
                "NextDNS blocked the bypass lookup. Usual causes: Apple iCloud Private "
                "Relay or a browser's built-in secure DNS (DNS-over-HTTPS) setting, "
                "repeating every few minutes; a browser's built-in Tor window (e.g. "
                "Brave's private window with Tor); or a VPN / proxy app. Check which "
                f"setting or application on {device} made it before treating it as "
                "hostile."
            ),
        )
    base = (
        "Blocked by NextDNS before any connection. If this repeats or is "
        f"C2/threat-intel, check {device} for the source."
    )
    if d.level == "high":
        return TriageDecision(
            disposition="escalate",
            suggested_severity="high" if _SEVERITY_RANK[f.severity] < 3 else f.severity,
            confidence=_CONF_DNS_FILTER,
            rationale=base,
        )
    if d.level == "low" or d.reason_id in DNS_REBINDING_REASONS:
        extra = (
            " DNS-rebinding protection is often a benign local device (a printer, NAS "
            "or router page answering with a private address)."
            if d.reason_id in DNS_REBINDING_REASONS else ""
        )
        return TriageDecision(
            disposition="noise",
            suggested_severity=f.severity,
            confidence=_CONF_DNS_FILTER,
            rationale=base + extra,
        )
    return TriageDecision(
        disposition="pattern",
        suggested_severity=f.severity,
        confidence=_CONF_DNS_FILTER,
        rationale=base,
    )


def _network_decision(f: TriageFeatures) -> TriageDecision | None:
    """Rule 1d (UniFi). Dispositions:
      * IPS DETECTED, NOT blocked → escalate, suggested CRITICAL (ranks above
        a block: the connection may have gone through);
      * IPS blocked → escalate HIGH (a LAN device reached for a known threat;
        the gateway stopped it — find the source on the device);
      * rogue AP → pattern (usually a neighbour; an evil twin of the site's
        own SSID is the case to rule out);
      * administrator access / configuration change → pattern (an audit
        trail: confirm it was planned work);
      * WAN failed / failover / site-to-site VPN down → escalate
        (availability; several sites on one ISP at once = one ISP outage);
      * WAN restored → noise (good news, linked by time to its failure);
      * ISP outage (Fleet v2: several sites on ONE provider down at once) →
        escalate HIGH, once — the per-site WAN alerts are linked to it;
      * anything else → None (the generic rules decide)."""
    n = f.network
    assert n is not None
    if n.kind == "isp_outage":
        isp = n.isp or (f"AS{n.asn}" if n.asn else "one provider")
        count = f"{n.sites} sites" if n.sites else "several sites"
        return TriageDecision(
            disposition="escalate",
            suggested_severity="high" if _SEVERITY_RANK[f.severity] < 3 else f.severity,
            confidence=_CONF_NETWORK,
            rationale=(
                f"ISP outage: {count} on {isp}" + (f" (AS{n.asn})" if n.asn and n.isp else "")
                + " lost their internet within minutes of each other — one provider problem, "
                "not N site problems. Check the provider's status page and open ONE ticket with "
                "them; each site's own WAN alert is linked to this incident."
            ),
        )
    site = n.site or "the site"
    if n.kind == "ips_threat":
        who = n.device or "a device on the site's network"
        sig = f" ({n.signature})" if n.signature else ""
        remote = f" — remote address {n.remote}" if n.remote else ""
        if n.action == "detected":
            return TriageDecision(
                disposition="escalate",
                suggested_severity="critical",
                confidence=_CONF_NETWORK,
                rationale=(
                    f"UniFi IPS DETECTED a threat{sig} for {who} at {site}{remote} but did NOT "
                    "block it — the connection may have gone through. Check the device now, "
                    "and whether the IPS category is set to detect only."
                ),
            )
        return TriageDecision(
            disposition="escalate",
            suggested_severity="high" if _SEVERITY_RANK[f.severity] < 3 else f.severity,
            confidence=_CONF_NETWORK,
            rationale=(
                f"Blocked by the UniFi IPS{sig} at {site}{remote}. The gateway stopped it, but "
                f"{who} reached for it: if this repeats or is C2 / malware, check that device "
                "for the source."
            ),
        )
    if n.kind == "rogue_ap":
        return TriageDecision(
            disposition="pattern",
            suggested_severity=f.severity,
            confidence=_CONF_NETWORK,
            rationale=(
                f"A rogue access point was seen at {site}. Usually a neighbour's network; rule "
                "out an evil twin — a network imitating the site's own Wi-Fi name — before "
                "dismissing it."
            ),
        )
    if n.kind in ("admin_activity", "config_change"):
        what = ("an administrator signed in to the console" if n.kind == "admin_activity"
                else "the console's configuration was changed")
        return TriageDecision(
            disposition="pattern",
            suggested_severity=f.severity,
            confidence=_CONF_NETWORK,
            rationale=(
                f"Audit: {what} at {site}. Confirm it was planned MSP work (a ticket or a "
                "maintenance window); an unexpected one is a compromised account until "
                "proven otherwise."
            ),
        )
    if n.kind in ("wan_down", "wan_failover", "vpn_down"):
        what = {"wan_down": "lost its internet (WAN) connection",
                "wan_failover": "failed over to its backup internet connection",
                "vpn_down": "lost its site-to-site VPN"}[n.kind]
        return TriageDecision(
            disposition="escalate",
            suggested_severity=f.severity,
            confidence=_CONF_NETWORK,
            rationale=(
                f"Availability: {site} {what}. If several sites on the same ISP fail at once "
                "it is one ISP outage, not N site problems; otherwise check the modem / ISP "
                "for this site."
            ),
        )
    if n.kind == "wan_restored":
        return TriageDecision(
            disposition="noise",
            suggested_severity=f.severity,
            confidence=_CONF_NETWORK,
            rationale=(
                f"The internet (WAN) connection of {site} is back. No action — confirm the "
                "outage window was expected (maintenance, an ISP fault)."
            ),
        )
    return None
