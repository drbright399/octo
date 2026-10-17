"""Where an alert stands after the humans' verdicts — `open` (needs
attention), `acknowledged`, `expected (rule #N)` or `resurfaced` (an ack
that a NEW occurrence outgrew) — computed at read time, never stored on the
event (an event is never altered: it stays for correlation, the pattern
pool and evidence windows).

ONE evaluator for both readers, so the list and the colour can never
disagree: the drawer's "needs attention" list hides exactly the alerts the
Fleet stops counting towards a site's Yellow (`AlertState.hidden`).

  EXPECTED     an ACTIVE expected condition (not revoked, before its review
               date) of the tenant whose device + signature keys equal the
               alert's — and, when the condition names a remote, EVERY
               remote of the alert under it (a coalesced bucket whose
               remotes are not all known never matches). Never for an alert
               that may not be expected (`keys.expected_refusal`: the
               caller sets `eligible`).
  ACKNOWLEDGED its own latest ack, unless the coalesced row GREW after it (a
               higher count or a newer last-seen) — then RESURFACED; an ack
               with "repeats for 24 h" keeps the growth (and every later
               occurrence of the same tenant + device + signature that began
               after the ack) acknowledged until `repeat_until`; past it, a
               new occurrence re-surfaces.
  SAME ALERT   an ack of one ROW of a vendor alert (`AlertKey.ref`) covers
               its other rows: a Datto alert's raise and its resolution
               (a resolution is not a new occurrence); a RocketCyber
               incident's EARLIER versions (a later version is new: it
               re-surfaces). Acks of the alerts judged are read by event /
               ref whatever their age (`ensure`) — a RocketCyber incident
               stays open for days.
  NO DEVICE    a rule or a repeat-ack with an empty device key (one that
               would cover the whole client — never written by the API, the
               schema refuses it) never matches.
  ACK ONLY     a RocketCyber alert (`keys.ACK_ONLY_SOURCES` — by source,
               whatever its payload names; Rick, 2026-10-07) is never
               expected and never covered by "repeats for 24 h": an expected
               rule or a repeat-ack of that source in the registry (an older
               release's, a hand-made row) is IGNORED — only an ack of the
               alert itself (or of another row of the same incident) counts.
  RECALLED     (v0.17.5; Rick, 2026-10-08) an ack with a 'recall' follow-up
               covers NOTHING — not its alert, not the other rows of its
               vendor alert, not its "repeats for 24 h": the alert is OPEN
               again (needs attention, counted towards the site's colour).
               The ack that DECIDES an alert is chosen as before, recalled or
               not (its own latest ack; else the ack of its vendor alert that
               covers the most; else the first "repeats for 24 h" ack whose
               window it began in) — when that one is recalled, the recall
               is the latest word on the alert: no ack made BEFORE the recall
               takes over (an older one, or one of another row / another
               repeat-ack that also covered it), and the choice is made
               again among the acks made AFTER it (acknowledging again — this
               row, another row of the vendor alert, a new repeat-ack — is a
               new ack, which decides). The OPEN state then carries the
               recalled ack (`AlertState.recalled`) so the drawer can say who
               recalled it and why.

Red / Black are never here: an incident is not an alert, and nothing in
this module reads or writes one.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from apps.octo.verdicts import store as vstore
from apps.octo.verdicts.keys import AlertKey, ack_only, ack_only_key

OPEN, ACKED, EXPECTED, RESURFACED = "open", "acknowledged", "expected", "resurfaced"
STATES = (OPEN, ACKED, EXPECTED, RESURFACED)


@dataclass
class Occurrence:
    event_id: Optional[int]
    key: AlertKey
    first_at: Optional[str]
    last_at: Optional[str]
    hits: Optional[int] = None
    """A coalesced row's count; None = one event, one occurrence."""
    remotes: Optional[dict[str, int]] = None
    """A coalesced row's remotes ({ip: hits}); None = not known."""
    eligible: bool = True
    """May an expected condition label it (`keys.expected_refusal`)."""


@dataclass(frozen=True)
class AlertState:
    status: str
    ack: Optional[vstore.Verdict] = None
    rule: Optional[vstore.ExpectedRule] = None
    by_repeat: bool = False
    new_hits: int = 0

    @property
    def hidden(self) -> bool:
        """Out of "needs attention" and not counted towards Yellow."""
        return self.status in (ACKED, EXPECTED)

    @property
    def recalled(self) -> bool:
        """OPEN because the ack that decided the alert was recalled (`ack`
        is that recalled ack — history, it covers nothing)."""
        return self.status == OPEN and self.ack is not None and self.ack.recalled


def _remotes_of(occ: Occurrence) -> Optional[list[str]]:
    """Every remote of the occurrence, or None when not all are known."""
    if occ.remotes is not None:
        known = {k: int(v) for k, v in occ.remotes.items() if k not in ("~", "?")}
        if occ.remotes.get("~") or occ.remotes.get("?"):
            return None
        if occ.hits is not None and sum(known.values()) < occ.hits:
            return None
        return sorted(known) or None
    if occ.hits in (None, 1) and occ.key.remote:
        return [occ.key.remote]
    return None


def _ref_order(a: vstore.Verdict) -> tuple[str, str, int]:
    """The ack of a ref that covers the most: the newest row acked, then the
    newest ack."""
    return (a.last_seen_at or "", a.at, a.id)


class TenantVerdicts:
    """The verdicts that apply to ONE tenant's alerts now."""

    def __init__(self, slug: str, acks: list[vstore.Verdict], rules: list[vstore.ExpectedRule],
                 *, now: datetime,
                 ptr_of: Optional[Callable[[str], Optional[dict[str, Any]]]] = None,
                 loader: Optional[Callable[..., list[vstore.Verdict]]] = None) -> None:
        self.slug = slug
        self.now = now
        # A rule with no device would cover the whole client, one for an
        # acknowledge-only source (RocketCyber) is a sweeping tag on vague
        # alerts: never applied.
        self.rules = [r for r in rules if r.active(now) and r.device_key.strip()
                      and not ack_only(r.source, r.signature_key)]
        # Every ack per event / per vendor alert (the deciding one is chosen
        # at read time: a recall may hand the choice to a LATER ack).
        self._by_event: dict[int, list[vstore.Verdict]] = {}
        self._by_ref: dict[str, list[vstore.Verdict]] = {}
        self._repeats: list[vstore.Verdict] = []
        self._seen: set[int] = set()
        self._asked_events: set[int] = set()
        self._asked_refs: set[str] = set()
        self._loader = loader
        self.add_acks(acks)
        self._ptr_of = ptr_of
        self._ptr_memo: dict[str, Optional[dict[str, Any]]] = {}

    def add_acks(self, acks: list[vstore.Verdict]) -> None:
        repeats = False
        for a in acks:
            if a.verdict != vstore.ACK or a.id in self._seen:
                continue
            self._seen.add(a.id)
            self._by_event.setdefault(a.event_id, []).append(a)
            if a.alert_ref:
                self._by_ref.setdefault(a.alert_ref, []).append(a)
            # A recalled repeat-ack stays a candidate: when it is the one that
            # decides an occurrence, the occurrence is OPEN (no repeat-ack made
            # before the recall takes over).
            if a.repeat_until and a.device_key.strip() and \
                    not ack_only(a.source, a.signature_key):
                self._repeats.append(a)
                repeats = True
        if repeats:
            # Oldest first whatever the order they were read in (`ensure`
            # adds older acks later): the list and the colour pick the same.
            self._repeats.sort(key=lambda a: (a.at, a.id))

    def ensure(self, *, event_ids: Any = (), refs: Any = ()) -> None:
        """Read the acks of these events / vendor alerts WHATEVER their age
        (the load reads the last 48 h): an alert judged now may have been
        acknowledged days ago (a RocketCyber incident open for days, a Datto
        alert resolved after its raise was acknowledged). Fail-soft: an
        unreadable registry adds nothing (louder)."""
        if self._loader is None:
            return
        ids = sorted({int(i) for i in event_ids if i} - self._asked_events)
        wanted = sorted({str(r) for r in refs if r} - self._asked_refs)
        self._asked_events.update(ids)
        self._asked_refs.update(wanted)
        if ids:
            self.add_acks(self._loader(self.slug, event_ids=ids, kinds=(vstore.ACK,)))
        if wanted:
            self.add_acks(self._loader(self.slug, refs=wanted, kinds=(vstore.ACK,)))

    @classmethod
    def load(cls, slug: str, now: Optional[datetime] = None) -> "TenantVerdicts":
        now = now or datetime.now(timezone.utc)
        acks = vstore.verdicts(slug, since=now - vstore.ACK_LOOKBACK, kinds=(vstore.ACK,))
        rules = vstore.active_rules(slug, now)
        return cls(slug, acks, rules, now=now, loader=vstore.verdicts)

    @property
    def empty(self) -> bool:
        return not self._by_event and not self.rules

    def _ptr(self, ip: str) -> Optional[dict[str, Any]]:
        if ip not in self._ptr_memo:
            if self._ptr_of is not None:
                self._ptr_memo[ip] = self._ptr_of(ip)
            else:
                from apps.octo.enrich import cache

                self._ptr_memo[ip] = cache.ip_info(ip)
        return self._ptr_memo[ip]

    def rule_for(self, occ: Occurrence) -> Optional[vstore.ExpectedRule]:
        if not occ.eligible or ack_only_key(occ.key):
            return None
        for r in self.rules:
            if r.device_key != occ.key.device_key or r.signature_key != occ.key.signature_key:
                continue
            if r.remote:
                remotes = _remotes_of(occ)
                host = vstore.is_host_remote(r.remote)
                if not remotes or not all(
                        vstore.remote_matches(r.remote, ip, self._ptr(ip) if host else None)
                        for ip in remotes):
                    continue
            return r
        return None

    def state(self, occ: Occurrence) -> AlertState:
        rule = self.rule_for(occ)
        if rule is not None:
            return AlertState(EXPECTED, rule=rule)
        last = vstore.parse(occ.last_at)
        first = vstore.parse(occ.first_at) or last
        after: Optional[datetime] = None
        done: set[int] = set()
        recalled: Optional[AlertState] = None
        while True:
            st = self._decide(occ, first, last, after, done)
            if st.ack is None or not st.ack.recalled:
                # A live ack decides — or nothing does: OPEN, carrying the
                # latest recall that decided it (history: who and why).
                return recalled if st.ack is None and recalled is not None else st
            # The deciding ack is RECALLED: the recall is the latest word —
            # only an ack made AFTER it may decide (chosen the same way).
            recalled = AlertState(OPEN, ack=st.ack, by_repeat=st.by_repeat)
            done.add(st.ack.id)
            when = vstore.parse(st.ack.recalled_at)
            if when is None:
                return recalled
            after = when if after is None else max(after, when)

    def _decide(self, occ: Occurrence, first: Optional[datetime], last: Optional[datetime],
                after: Optional[datetime], done: set[int]) -> AlertState:
        """The state the deciding ack gives (a RECALLED deciding ack → OPEN
        with that ack), among the acks made after `after` (None: all) and not
        in `done`."""

        def counts(a: vstore.Verdict) -> bool:
            if a.id in done:
                return False
            if after is None:
                return True
            at = vstore.parse(a.at)
            return at is not None and at > after

        own = max((a for a in self._by_event.get(occ.event_id, ()) if counts(a)),
                  key=lambda a: (a.at, a.id), default=None) if occ.event_id is not None else None
        if own is None and occ.key.ref:
            same = max((a for a in self._by_ref.get(occ.key.ref, ()) if counts(a)),
                       key=_ref_order, default=None)
            if same is not None:
                if same.recalled:
                    return AlertState(OPEN, ack=same)
                return self._same_alert(occ, same, last)
        if own is not None and own.recalled:
            return AlertState(OPEN, ack=own)
        if own is not None:
            if occ.hits is None:
                return AlertState(ACKED, ack=own)
            seen_then = vstore.parse(own.last_seen_at)
            grew = occ.hits > int(own.hits_at or 0) or \
                (last is not None and seen_then is not None and last > seen_then)
            if not grew:
                return AlertState(ACKED, ack=own)
            # "Repeats for 24 h" never covers an acknowledge-only source.
            until = None if ack_only_key(occ.key) else vstore.parse(own.repeat_until)
            if until is not None and last is not None and last <= until:
                return AlertState(ACKED, ack=own, by_repeat=True)
            return AlertState(RESURFACED, ack=own,
                              new_hits=max(0, occ.hits - int(own.hits_at or 0)))
        for r in () if ack_only_key(occ.key) else self._repeats:
            if r.device_key != occ.key.device_key or r.signature_key != occ.key.signature_key:
                continue
            at, until = vstore.parse(r.at), vstore.parse(r.repeat_until)
            if at is None or until is None or first is None or first < at or first > until:
                continue
            if not counts(r):
                continue
            if r.recalled:
                return AlertState(OPEN, ack=r, by_repeat=True)
            if last is None or last <= until:
                return AlertState(ACKED, ack=r, by_repeat=True)
            return AlertState(RESURFACED, ack=r, by_repeat=True)
        return AlertState(OPEN)

    @staticmethod
    def _same_alert(occ: Occurrence, ack: vstore.Verdict,
                    last: Optional[datetime]) -> AlertState:
        """Another row of a vendor alert one row of which was acknowledged:
        a Datto alert's other row (its raise / its resolution — the same
        alert) is acknowledged; a RocketCyber incident's version is
        acknowledged when it is not LATER than the version acked, else it
        re-surfaces (the incident changed after the ack)."""
        if occ.key.family == "rocketcyber":
            # The version acked is its row's time (`last_seen_at`); unknown →
            # no other version is covered (louder).
            acked_row = vstore.parse(ack.last_seen_at)
            if last is None or acked_row is None or last > acked_row:
                return AlertState(RESURFACED, ack=ack)
        return AlertState(ACKED, ack=ack)
