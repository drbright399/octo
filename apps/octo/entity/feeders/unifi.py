"""The UniFi feed consumer — the UniFi poller's per-site feeds become THIS
tenant's lookups (design 5.1; `apps.octo.adapters.unifi.feed`).

  on_site_report       → the site (L-UNIFI: mapping a UniFi site creates the
                         Athena site and a confirmed ref — the operator's
                         decision) + egress intervals + the fleet watermark
  on_client_snapshot   → lease intervals (+ the MAC-anomaly rule; its
                         findings are handed back as signals for the UniFi
                         poller to store)
  on_client_snapshot_failed → the attempt only (nothing closes or extends)
  on_log_events        → joins, exact disconnect edges, IP conflicts
  on_log_progress      → the system-log watermark (G10: D3 waits for it)
  on_networks          → subnets, VLAN, purpose, DHCP DNS path
  on_signal_stored     → the anomaly's signal is stored (no second one)

Every call carries ONE tenant slug and ONE scope "<hostId>/<siteId>". The
tenant's switch must be shadow / on, AND the registry must map that scope to
that tenant — else nothing is written (I10). A consumer error never stops the
poller (the feed module logs it).
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from apps.octo.entity import intervals as iv
from apps.octo.entity import normalize as nz
from apps.octo.entity import sites as st
from apps.octo.entity import switch
from apps.octo.entity import tokens as tk
from apps.octo.entity.db import TenantDB
from apps.octo.entity.feeders.mapping import mapped

logger = logging.getLogger(__name__)

VENDOR = "unifi"
POLL_S = 300.0


def prior_site(conn: Any, scope: str) -> Optional[str]:
    """The ACTIVE Athena site this UniFi scope already belongs to in this
    tenant, under ANY adapter instance — an open ref first, else the most
    recent one ended by an unmap or a key rotation. A UniFi site's Athena
    site belongs to the SCOPE, never to the instance that reads it: rotating
    the key (disable, add a new instance, map the same site) must not split
    the tenant's site in two."""
    row = conn.execute(
        "SELECT r.site_id FROM site_vendor_ref r JOIN site s ON s.site_id = r.site_id "
        "WHERE r.vendor = ? AND r.vendor_scope_id = ? AND s.status = 'active' "
        "AND r.state IN ('confirmed','auto','suggested','retired') "
        "ORDER BY (r.valid_to IS NULL) DESC, COALESCE(r.valid_to, r.valid_from) DESC, r.id DESC "
        "LIMIT 1", (VENDOR, scope)).fetchone()
    return row["site_id"] if row is not None else None


def attach_ref(conn: Any, *, site_id: str, instance_id: int, scope: str, match_source: str,
               now: str) -> None:
    """The ref of (instance, scope) → site: CONFIRMED when the mapping is the
    operator's own ('manual' — the mapping is the operator's decision),
    else (a name-made mapping from before the same-name rule) SUGGESTED (G5)."""
    if match_source == "manual":
        st.operator_link(conn, site_id=site_id, vendor=VENDOR, instance_id=instance_id,
                         scope_id=scope, operator_id=st.OPERATOR_MAPPING, now=now,
                         rule_id="L-UNIFI",
                         reason="the UniFi site was mapped to this client by an operator",
                         evidence={"match_source": match_source})
    else:
        st.propose(conn, site_id=site_id, vendor=VENDOR, instance_id=instance_id,
                   scope_id=scope, state="suggested", score=85, rule_id="L-UNIFI",
                   rule_version=1, evidence={"match_source": match_source}, now=now)


def ensure_site(conn: Any, *, instance_id: int, scope: str, match_source: str,
                report: Optional[dict[str, Any]], now: str) -> str:
    """L-UNIFI: the Athena site of a mapped UniFi site — created on first
    sight with a CONFIRMED ref when the mapping is the operator's own
    ('manual'), else (a name-made mapping from before the same-name rule) a
    SUGGESTED one (G5). A scope this tenant already knows (another instance
    read it — a key rotation — or it was unmapped and mapped back) re-attaches
    to its site: only the ref is new."""
    rows = st.refs(conn, VENDOR, scope, instance_id=instance_id,
                   states=("confirmed", "auto", "suggested"))
    rows.sort(key=lambda r: ({"confirmed": 0, "auto": 1, "suggested": 2}[r.state], r.id))
    label = None
    tz = None
    loc: dict[str, Any] = {}
    if report:
        label = str(report.get("name") or "")[:200] or None
        tz = str(report.get("timezone") or "")[:64] or None
        loc = report.get("location") if isinstance(report.get("location"), dict) else {}
    if rows:
        site_id = rows[0].site_id
        if report:
            st.update_site_geo(conn, site_id, label=label, tz=tz, location=loc, now=now)
        return site_id
    known = prior_site(conn, scope)
    if known is not None:
        attach_ref(conn, site_id=known, instance_id=instance_id, scope=scope,
                   match_source=match_source, now=now)
        if report:
            st.update_site_geo(conn, known, label=label, tz=tz, location=loc, now=now)
        return known
    site_id = st.create_site(conn, label=label or scope.split("/")[-1], anchor="unifi",
                             now=now, created_by="rule:L-UNIFI", tz=tz, location=loc)
    attach_ref(conn, site_id=site_id, instance_id=instance_id, scope=scope,
               match_source=match_source, now=now)
    return site_id


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class UniFiEntityFeeder:
    def __init__(self, *, poll_s: float = POLL_S,
                 now: Callable[[], datetime] = _utcnow) -> None:
        self.poll_s = poll_s
        self._now = now

    def _target(self, slug: str, scope: str) -> Optional[tuple[TenantDB, int, str]]:
        if not switch.enabled(slug):
            return None
        m = mapped(VENDOR, scope, slug)
        if m is None:
            return None              # I10: not this tenant's site — write nothing
        return TenantDB.for_tenant(slug), m.instance_id, m.match_source

    def on_site_report(self, slug: str, scope: str, report: dict[str, Any]) -> None:
        target = self._target(slug, scope)
        if target is None:
            return
        tdb, inst, source = target
        now = nz.ts(report.get("polled_at"))
        if not now:
            return
        with tdb.write() as conn:
            site_id = ensure_site(conn, instance_id=inst, scope=scope, match_source=source,
                                  report=report, now=now)
            iv.apply_site_report(conn, site_id=site_id, scope=scope, report=report,
                                 poll_s=self.poll_s)

    def on_client_snapshot(self, slug: str, scope: str,
                           snapshot: dict[str, Any]) -> Optional[dict[str, Any]]:
        target = self._target(slug, scope)
        if target is None:
            return None
        tdb, inst, source = target
        now = nz.ts(snapshot.get("polled_at"))
        if not now:
            return None
        with tdb.write() as conn:
            site_id = ensure_site(conn, instance_id=inst, scope=scope, match_source=source,
                                  report=None, now=now)
            iv.apply_client_snapshot(
                conn, site_id=site_id, scope=scope, snapshot=snapshot, poll_s=self.poll_s,
                tokens=lambda kind, value: tk.token(slug, kind, value) if value else None)
            return self._signals(conn, scope)

    def on_client_snapshot_failed(self, slug: str, scope: str, failure: dict[str, Any]) -> None:
        target = self._target(slug, scope)
        if target is None:
            return
        at = nz.ts(failure.get("polled_at"))
        if not at:
            return
        with target[0].write() as conn:
            iv.watermark_failed(conn, "unifi.clients", scope, at,
                                str(failure.get("reason") or "snapshot not read whole"))

    def on_log_events(self, slug: str, scope: str,
                      events: list[dict[str, Any]]) -> Optional[dict[str, Any]]:
        target = self._target(slug, scope)
        if target is None:
            return None
        tdb, inst, source = target
        with tdb.write() as conn:
            site_id = ensure_site(conn, instance_id=inst, scope=scope, match_source=source,
                                  report=None, now=nz.iso(self._now()))
            iv.apply_log_events(conn, site_id=site_id, scope=scope, events=events)
            return self._signals(conn, scope)

    def on_log_progress(self, slug: str, scope: str, progress: dict[str, Any]) -> None:
        target = self._target(slug, scope)
        if target is None:
            return
        at = nz.ts(progress.get("scanned_to"))
        if not at:
            return
        with target[0].write() as conn:
            iv.log_progress(conn, scope, at)

    def wants(self, slug: str, scope: str, _data: Any = None) -> bool:
        """Whether this tenant's site is fed at all (switch shadow / on, the
        scope mapped to it) — the poller reads the daily networks only then,
        and marks them read only when they were taken."""
        return self._target(slug, scope) is not None

    def on_networks(self, slug: str, scope: str, networks: list[dict[str, Any]]) -> bool:
        """True when the networks were taken (the poller marks them read
        only then: a tenant switched off → shadow, or a site re-mapped, gets
        its subnets on the next cycle, not a day later)."""
        target = self._target(slug, scope)
        if target is None:
            return False
        tdb, inst, source = target
        at = nz.iso(self._now())
        with tdb.write() as conn:
            site_id = ensure_site(conn, instance_id=inst, scope=scope, match_source=source,
                                  report=None, now=at)
            iv.apply_networks(conn, site_id=site_id, scope=scope, networks=networks, at=at)
        return True

    def on_signal_stored(self, slug: str, scope: str, stored: dict[str, Any]) -> None:
        target = self._target(slug, scope)
        if target is None:
            return
        anomaly_id = stored.get("anomaly_id")
        if not isinstance(anomaly_id, int):
            return
        with target[0].write() as conn:
            conn.execute("UPDATE lk_mac_anomaly SET signaled = 1 WHERE id = ?", (anomaly_id,))

    @staticmethod
    def _signals(conn: Any, scope: str) -> Optional[dict[str, Any]]:
        rows = iv.unsignaled_anomalies(conn, scope)
        if not rows:
            return None
        out = []
        for r in rows:
            try:
                detail = json.loads(r["detail"] or "{}")
            except ValueError:
                detail = {}
            out.append({"kind": "mac_anomaly", "anomaly_id": int(r["id"]), "mac": r["mac"],
                        "anomaly": r["kind"], "from": r["from_ts"], "to": r["to_ts"],
                        "detail": detail})
        return {"signals": out}
