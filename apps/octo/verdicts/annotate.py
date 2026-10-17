"""Stored alert rows → their keys, their coalesced row (if any), whether they
may be marked expected, and where they stand (`state.AlertState`) — the
ONE path the drawer's list and the acknowledge / expected routes read, so
the keys an ack or a rule is written with are exactly the keys the Fleet's
counts are matched on (a ledger bucket's own scope + subject / columns
when the alert has one)."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from apps.octo.verdicts import keys, occurrences
from apps.octo.verdicts.state import AlertState, Occurrence, TenantVerdicts


@dataclass
class Annotated:
    row: dict[str, Any]
    payload: dict[str, Any]
    key: keys.AlertKey
    occurrence: Occurrence
    refusal: Optional[str]
    """Why it may not be marked expected (None: it may)."""
    linked: bool
    hits: Optional[int] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    state: Optional[AlertState] = None
    repeat_refusal: Optional[str] = None
    """Why "acknowledge repeats for 24 h" is not offered (None: it is)."""


def annotate(slug: str, rows: list[dict[str, Any]], *, verdicts: Optional[TenantVerdicts] = None,
             now: Optional[datetime] = None) -> list[Annotated]:
    from apps.octo.adapters.unifi import store as ustore

    now = now or datetime.now(timezone.utc)
    ids = [int(r["id"]) for r in rows]
    unifi = ustore.bucket_info(slug, [int(r["id"]) for r in rows if r.get("source") == "unifi"])
    ndns = occurrences.nextdns_by_event(
        slug, [int(r["id"]) for r in rows if r.get("source") == "nextdns"])
    linked = occurrences.linked_events(slug, ids)
    out: list[Annotated] = []
    for row in rows:
        eid = int(row["id"])
        p = keys.payload_of(row)
        refusal = keys.expected_refusal(row, p, linked_incident=eid in linked)
        csam = keys.is_csam(row, p)
        b = unifi.get(eid)
        nb = ndns.get(eid)
        if b is not None:
            ips = p.get("ips")
            remote = (str(ips.get("remote_ip") or "") or None) if isinstance(ips, dict) else None
            key = keys.unifi_key(b.scope, b.kind, b.subject, remote=remote)
            refusal = refusal or keys.device_refusal(key)
            occ = Occurrence(eid, key, b.first_seen, b.last_seen, b.hits, b.remotes,
                             eligible=refusal is None)
            item = Annotated(row, p, key, occ, refusal, eid in linked, b.hits, b.first_seen,
                             b.last_seen)
        elif nb is not None:
            occ = occurrences.nextdns_occurrence(nb, linked=eid in linked)
            if not occ.eligible and refusal is None:
                refusal = keys.CSAM_REFUSAL if keys.is_csam_key(occ.key) \
                    else keys.device_refusal(occ.key)
            occ.eligible = occ.eligible and refusal is None
            item = Annotated(row, p, occ.key, occ, refusal, eid in linked, occ.hits,
                             occ.first_at, occ.last_at)
        else:
            occ = occurrences.row_occurrence(row, linked=eid in linked, payload=p)
            item = Annotated(row, p, occ.key, occ, refusal, eid in linked)
        item.repeat_refusal = keys.repeat_refusal(item.key, csam=csam)
        out.append(item)
    if verdicts is not None:
        # Acks of the other rows of the same vendor alerts, whatever their
        # age (a raise acked days before its resolution; an incident's
        # earlier version). The rows' own acks are in the load's 48 h: an
        # ack is never older than its alert, and the list is 24 h.
        verdicts.ensure(refs=[a.key.ref for a in out if a.key.ref])
        for item in out:
            item.state = verdicts.state(item.occurrence)
    return out


def one(slug: str, row: dict[str, Any], *, verdicts: Optional[TenantVerdicts] = None) -> Annotated:
    return annotate(slug, [row], verdicts=verdicts)[0]
