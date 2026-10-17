"""The threat-rule registry — FROZEN code (P5: identical in every MSP
bundle). A rule is a versioned dataclass with a code constant `stage`
(shadow | live) and the inputs it needs (P8 coverage). There is NO settings
field and no runtime switch: an MSP tunes Yellow / Notice (`registry.KNOBS`)
and may only TIGHTEN Red; Black is code only. Promotion shadow → live
happens by RELEASE, after ≥ 30 d (Black) / ≥ 14 d (Red) with every
would-fire explained.

Slice 1 (design 7.1):
  B6   analyst-declared Black                live  (human)
  R8   analyst-confirmed Red                 live  (human, reason ≥ 20 chars)
  R6   deception: a plaintext credential on a buoy canary
                                             SHADOW (the N15 scanner allowlist
                                             is its precondition)
  R2-W Wazuh malware-group verdict ≥ 12      SHADOW
  FR2  detection blindness (intake health)   live  (Yellow / banner only)

v0.17.1 (Rick, 2026-10-06):
  B7   CSAM lookup (a NextDNS block whose reason is csam, for a device of a
       tenant)                               LIVE  (automated, RESTRICTED)
       "Confirmed CSAM lookups is an automated Black Tier item. That's
       state/federal law enforcement territory that needs to be handled
       immediately." One incident per device (later lookups append). It is
       RESTRICTED (`Rule.restricted`): admin / super_admin only (an analyst
       sees "restricted incident at <tenant>", a client user nothing unless
       the MSP's switch says so), every view audited, paged at once with a
       neutral text that never names the domain, NO device action of any kind
       (no lockdown, isolation, allow or remediation proposal — the evidence
       is preserved and the user is not tipped off), never braked, never
       enriched, never previewed (`apps.octo.threat.restricted`).

CAUTION FIRST — a note for the slices that build B1 (NOT built here). Rick's
decision (2026-10-02, design section 9.1) SUPERSEDES the doc's section-8
recommendation: ONE unapproved persistent remote-control tool PLUS a young
(≤ 30 d) or UNKNOWN-age relay is **BLACK now**, not Red-after-a-30-day-
trial. Its first proposed step is "block the relay" (friction for an
unregistered vendor tool is acceptable: "that's not a failure, that's us
doing our job"). The 30-day trial still runs — to MEASURE B1's precision,
not to gate it. One of OUR accounts opening the firewall from an unfamiliar
network stays Red ("was this you?") and goes Black on a "no". Whatever B1
becomes, it keeps P3's evidence discipline for everything else, never lets
attacker-controlled text (the watermark, job stdout, `c=` labels) lower a
tier, and never lets a setting reach it.
"""
from __future__ import annotations

from dataclasses import dataclass, fields
from typing import Optional

SHADOW, LIVE = "shadow", "live"
STAGES = (SHADOW, LIVE)
BLACK, RED, YELLOW = "black", "red", "yellow"
HUMAN, AUTOMATED = "human", "automated"


@dataclass(frozen=True)
class Rule:
    id: str
    version: int
    tier: str                 # the highest tier the rule can open: black | red | yellow
    family: str               # dedupe family (one incident per device per family)
    stage: str                # SHADOW | LIVE — a code constant, promoted by release only
    kind: str                 # HUMAN | AUTOMATED
    title: str                # operator wording
    neutral: str              # client-safe wording (no vendor, device, indicator)
    inputs: tuple[str, ...]   # mandatory inputs (coverage)
    description: str = ""
    restricted: bool = False
    """A RESTRICTED rule's incidents (B7, CSAM): admin+ only, every view
    audited, no device action ever proposed or offered, neutral paging."""

    @property
    def automated(self) -> bool:
        return self.kind == AUTOMATED


RULES: dict[str, Rule] = {r.id: r for r in (
    Rule("B6", 1, BLACK, "analyst", LIVE, HUMAN, "analyst-declared Black",
         "urgent security incident", ("analyst",),
         "An analyst+ raises a signal, a Red, or a bare device or site to Black, with a "
         "reason — e.g. the client calls: \"someone is controlling my screen\"."),
    Rule("R8", 1, RED, "analyst", LIVE, HUMAN, "analyst-confirmed threat",
         "security issue under investigation", ("analyst",),
         "\"Confirm as threat\" on a Yellow signal, with a reason of at least 20 characters."),
    Rule("R6", 1, RED, "deception", SHADOW, AUTOMATED, "credential tried on a decoy",
         "security issue under investigation", ("buoy.opencanary", "canary_scanner_allowlist"),
         "From an internal address not on the scanner allowlist: a plaintext credential "
         "attempt on an SSH, RDP, HTTP, FTP or MSSQL canary. A port touch is Yellow; SMB / "
         "NTLM negotiation and SNMP probes are ignored. The submitted password is never "
         "stored (length + salted hash only)."),
    Rule("R2-W", 1, RED, "malware", SHADOW, AUTOMATED, "malware verdict (host monitoring)",
         "security issue under investigation", ("wazuh",),
         "A Wazuh rule ≥ 12 in a malware group: a VirusTotal positive, a YARA match, a "
         "rootcheck trojan. Other level-12 rules are not R2-W."),
    Rule("B7", 1, BLACK, "restricted", LIVE, AUTOMATED, "CSAM lookup blocked (restricted)",
         "urgent security incident", ("nextdns",),
         "Any NextDNS block whose reason is CSAM, for a device of a client: an automated "
         "Black, opened at once and paged at once (no business-hours deferral). One "
         "incident per device; later lookups append to it. RESTRICTED: admin and "
         "super_admin only; no device action of any kind; the domain is never resolved, "
         "fetched, enriched or previewed.", restricted=True),
    Rule("FR2", 1, YELLOW, "coverage", LIVE, AUTOMATED, "detection blindness",
         "monitoring interrupted", ("intake_health",),
         "Intake health, not event arrival: a vendor poll failing > 60 min, the Datto "
         "open-alert cap, a stale tier worker. Tenant-specific → Yellow; fleet-wide → "
         "Notice + the internal banner. Never touches an open incident."),
)}

# The fields a rule carries — asserted by a test: nothing in here is a setting.
RULE_FIELDS = tuple(f.name for f in fields(Rule))


def rule(rule_id: str) -> Optional[Rule]:
    return RULES.get(rule_id)


def restricted(rule_id: Optional[str]) -> bool:
    """Is an incident of this rule RESTRICTED (B7)? An unknown rule id is
    not."""
    r = RULES.get(rule_id or "")
    return bool(r and r.restricted)


def human_rule(tier: str) -> Rule:
    """The human path for a tier: B6 (black) or R8 (red)."""
    return RULES["B6"] if tier == BLACK else RULES["R8"]
