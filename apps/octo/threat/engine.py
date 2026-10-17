"""TierWorker — the tier engine's loop (design 6.2), slice-1 skeleton.

One pass every 30 s (and at once for a tenant `poke(slug)`ed — the API pokes
after a human opens / raises), per ACTIVE tenant with an event store:
  1. EVALUATE the tenant's new events after its cursor (registry
     `threat_worker_state`, `cursor:<slug>`) with slice 1's automated rules —
     R6 (deception) and R2-W (Wazuh malware), both SHADOW: a fact
     (`threat_fact`) and a would-fire row (`threat_would_fire`), never a
     colour; R6's port touches are Yellow facts the buoy layer counts. A
     tenant without a cursor starts at its NEWEST event: a restart or a first
     start never fires on backlog (G7);
  1b. RESTRICTED EVIDENCE (B7, v0.17.1): every CSAM lookup the NextDNS
     poller kept as restricted evidence and not yet processed opens — or
     appends to — the device's B7 Black (LIVE, automated). NO backlog skip
     here: a CSAM lookup is always raised, whenever it arrived;
  2. PAGE: every open incident's ladder (`notify.notify_threat`) — once per
     step, idempotent — and the acknowledged-but-idle follow-ups;
  3. CLIENT VISIBILITY: an incident unacknowledged for 60 min is stamped
     visible to the client's users (`client_visible_at`).
Then, fleet-wide: the daily 08:00 digest of unacknowledged Reds, one
`threat_coverage` notice per detection-blindness outage (FR2), the review
reminder of every expected condition 7 days from its review date (v0.17.2),
and the heartbeat (the threat layer reads "threat correlator not running" — Unknown —
when it goes stale and nothing is open).

The engine MAY open, append evidence and raise Red → Black (live automated
rules only — B7 since v0.17.1, never braked; a braked rule is held at Red).
It may NEVER close or lower a tier: there is no code path here that does
either.
"""
from __future__ import annotations

import asyncio
import logging
import os
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from apps.octo.ingest.timestamps import format_utc_ms
from apps.octo.threat import audit as taudit
from apps.octo.threat import (
    brake,
    client_view,
    evaluators,
    intake,
    notify,
    registry,
    restricted,
    rules,
    store,
)

logger = logging.getLogger(__name__)

INTERVAL_SEC = intake.WORKER_INTERVAL_SEC
BATCH = 500
ENABLE_ENV = "OCTO_TIER_WORKER"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def enabled() -> bool:
    return os.environ.get(ENABLE_ENV, "1").strip().lower() not in ("0", "false", "no", "off")


def _invalidate() -> None:
    try:
        from apps.octo.fleet import build

        build.invalidate()
    except Exception:  # noqa: BLE001
        pass


def _tenants() -> dict[str, str]:
    from apps.octo.fleet import sources

    try:
        return {slug: t.name for slug, t in sources.tenants().items()}
    except sqlite3.Error:
        return {}


def page_now(inc: store.Incident, *, tenant_name: str,
             now: Optional[datetime] = None) -> list[notify.Sent]:
    """Run one incident's ladder NOW (the API calls it right after a person
    opens or raises, so T0 never waits for the next pass). Never raises."""
    now = now or _utcnow()
    try:
        before = inc.escalation_step
        sent = notify.notify_threat(inc, now, tenant_name=tenant_name)
        errors = sorted({s.error for s in sent if s.error})
        if errors:
            # Not counted as done (notify_threat stopped before the step):
            # the next pass pages it again.
            taudit.system("incident.page_failed", inc.slug, "incident", str(inc.id),
                          after={"step_done": inc.escalation_step, "errors": errors},
                          reason="a paging step could not be written — it is retried")
        if inc.escalation_step != before:
            # Audit BEFORE the record is written (the incident's own
            # bookkeeping); a write that fails after it says so.
            taudit.system("incident.escalate_step", inc.slug, "incident", str(inc.id),
                          after={"step": inc.escalation_step, "tier": inc.tier,
                                 "recipients": sorted({r for s in sent for r in s.recipients})},
                          reason=f"paging ladder step {inc.escalation_step}")
            try:
                store.set_ladder(inc.slug, inc.id, step=inc.escalation_step, at=now,
                                 note=f"paged: step {inc.escalation_step}")
            except Exception as exc:  # noqa: BLE001
                taudit.system("incident.escalate_step_failed", inc.slug, "incident",
                              str(inc.id), after={"error": type(exc).__name__},
                              reason="the paging step was sent but not recorded — it is "
                                     "recorded on the next pass (idempotent ids: nobody is "
                                     "paged twice)")
                raise
        return sent
    except Exception as exc:  # noqa: BLE001
        logger.error("[tier-worker] paging %s#%s failed (%s)", inc.slug, inc.id,
                     type(exc).__name__)
        return []


class TierWorker:
    def __init__(self, *, now: Callable[[], datetime] = _utcnow,
                 interval_sec: float = INTERVAL_SEC, manager: Any = None) -> None:
        self._now = now
        self._interval = interval_sec
        self.manager = manager
        self._task: Optional[asyncio.Task] = None
        self._stopping = asyncio.Event()
        self._wake = asyncio.Event()
        self._poked: set[str] = set()
        self._poke_lock = threading.Lock()
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self.last_pass: dict[str, Any] = {}
        self.passes = 0

    # ----- one pass, synchronous (tests drive it directly) -----

    def run_once(self, only: Optional[set[str]] = None) -> dict[str, dict[str, int]]:
        now = self._now()
        names = _tenants()
        out: dict[str, dict[str, int]] = {}
        unacked: dict[str, list[store.Incident]] = {}
        for slug in sorted(names):
            if only is not None and slug not in only:
                continue
            try:
                out[slug], unacked[slug] = self.run_tenant(slug, now, tenant_name=names[slug])
            except Exception as exc:  # noqa: BLE001 — one tenant never stops the others
                logger.warning("[tier-worker] %s failed (%s)", slug, type(exc).__name__)
                out[slug] = {"error": 1}
        if only is None:
            try:
                notify.red_digest(unacked, now, tenant_names=names)
            except Exception as exc:  # noqa: BLE001
                logger.warning("[tier-worker] digest failed (%s)", type(exc).__name__)
            self._coverage_notices(now)
            # v0.17.2: an expected condition 7 days from its review date
            # tells the admins (once).
            from apps.octo.verdicts import reminders

            reminders.send_due_safely(now)
            self.passes += 1
            registry.state_put(intake.HEARTBEAT_KEY,
                               {"at": format_utc_ms(now), "passes": self.passes}, now)
        if any(any(v for k, v in counts.items() if k != "scanned") for counts in out.values()):
            _invalidate()
        self.last_pass = {"at": format_utc_ms(now), "tenants": out}
        return out

    def run_tenant(self, slug: str, now: datetime, *,
                   tenant_name: str) -> tuple[dict[str, int], list[store.Incident]]:
        counts = {"scanned": 0, "would_fire": 0, "yellow": 0, "opened": 0, "paged": 0,
                  "visible": 0}
        if not store.events_db_path(slug).exists():
            return counts, []
        store.ensure_schema(slug)
        self._evaluate(slug, now, counts)
        self._restricted(slug, now, counts)
        incidents = store.list_incidents(slug, statuses=store.OPEN_STATUSES, limit=500)
        for inc in incidents:
            sent = page_now(inc, tenant_name=tenant_name, now=now)
            counts["paged"] += len(sent)
            if inc.acked:
                counts["paged"] += len(notify.acked_followup(
                    inc, now, last_activity=self._last_activity(slug, inc.id),
                    tenant_name=tenant_name))
            elif inc.client_visible_at is None and client_view.visible_at(inc) is not None \
                    and client_view.visible_at(inc) <= now:  # type: ignore[operator]
                store.set_client_visible(slug, inc.id, now)
                counts["visible"] += 1
        return counts, incidents

    @staticmethod
    def _last_activity(slug: str, incident_id: int) -> Optional[datetime]:
        times = [store.parse(n.get("created_at")) for n in store.notes(slug, incident_id)
                 if not str(n.get("author") or "").startswith("system")]
        times = [t for t in times if t is not None]
        return max(times) if times else None

    # ----- evaluation (cursor over events.db) -----

    def _evaluate(self, slug: str, now: datetime, counts: dict[str, int]) -> None:
        key = f"cursor:{slug}"
        cursor = registry.state_get(key)
        path = store.events_db_path(slug)
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5.0)
        conn.row_factory = sqlite3.Row
        try:
            hi = int(conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0])
            if not isinstance(cursor, int):
                # First sight of this tenant: start at its newest event.
                registry.state_put(key, hi, now)
                return
            rows = [dict(r) for r in conn.execute(
                "SELECT id, received_at, source, source_host, event_type, severity, payload "
                "FROM events WHERE id > ? AND id <= ? AND (event_type LIKE 'opencanary.%' "
                "OR source = 'wazuh' OR event_type LIKE 'wazuh%') ORDER BY id LIMIT ?",
                (cursor, hi, BATCH)).fetchall()]
        finally:
            conn.close()
        allow = registry.canary_allowlist(slug) if any(evaluators.is_canary(r) for r in rows) \
            else set()
        for row in rows:
            counts["scanned"] += 1
            if evaluators.is_canary(row):
                self._apply(slug, row, evaluators.r6(row, allowlist=allow), now, counts)
            elif evaluators.is_wazuh(row):
                self._apply(slug, row, evaluators.r2_wazuh(row), now, counts)
        new = rows[-1]["id"] if len(rows) >= BATCH else hi
        if new != cursor:
            registry.state_put(key, int(new), now)

    def _apply(self, slug: str, row: dict[str, Any], out: evaluators.Outcome, now: datetime,
               counts: dict[str, int]) -> None:
        if out.kind == evaluators.IGNORE:
            return
        observed = str(row.get("received_at") or format_utc_ms(now))
        if out.kind == evaluators.YELLOW:
            if store.add_fact(slug, fact_key=out.fact_key, kind=out.fact_kind, stage="live",
                              observed_at=observed, source=str(row.get("source") or ""),
                              source_event_id=row.get("id"), device_ref=out.device_ref,
                              attrs=out.attrs):
                counts["yellow"] += 1
            return
        r = rules.rule(out.rule_id or "")
        if r is None:
            return
        stage = r.stage
        store.add_fact(slug, fact_key=out.fact_key, kind=out.fact_kind, stage=stage,
                       observed_at=observed, source=str(row.get("source") or ""),
                       source_event_id=row.get("id"), device_ref=out.device_ref,
                       attrs=out.attrs)
        key = store.dedupe_key(slug, device_ref=out.device_ref, family=r.family)
        if stage == rules.SHADOW:
            if store.would_fire(slug, rule_id=r.id, rule_version=r.version,
                                tier=out.tier or rules.RED, key=key, fact_key=out.fact_key,
                                summary=out.summary, device_ref=out.device_ref, now=now):
                counts["would_fire"] += 1
            return
        # A LIVE automated rule (none in slice 1): the brake holds it at Red.
        tier = brake.ceiling(r.id, out.tier or rules.RED, now)
        if registry.verdict_blocks(slug, key, now):
            return                     # an analyst verdict on this exact key (G10)
        # Audit BEFORE the write, naming what is about to happen.
        action = store.predict(slug, key, tier, now)
        taudit.system(f"incident.{action}", slug, "incident", None,
                      after={"tier": tier, "rule": r.id, "key": key}, reason=out.why)
        opened = store.open_incident(
            slug, tier=tier, rule_id=r.id, rule_version=r.version, key=key,
            summary=out.summary, scope="device" if out.device_ref else "tenant",
            opened_by=store.SYSTEM_ACTOR, reason=out.why, device_ref=out.device_ref,
            device_label=out.device_ref, event_ids=[int(row["id"])],
            evidence={"facts": [out.fact_key], "why": out.why}, now=now)
        if opened.incident is not None:
            counts["opened"] += 1
            actual = store.OUTCOME_ACTION.get(opened.outcome, opened.outcome)
            if actual != action:
                # A race changed it between the prediction and the write.
                taudit.system(f"incident.{actual}", slug, "incident", str(opened.incident.id),
                              after={"tier": opened.incident.tier, "rule": r.id, "key": key},
                              reason=f"the same key: {opened.outcome} (not {action})")

    # ----- B7: restricted evidence (CSAM lookups) -----

    def _restricted(self, slug: str, now: datetime, counts: dict[str, int]) -> None:
        """Open / append the B7 Black of every device with restricted
        evidence not yet processed. One incident per device (the key names
        the device); its rows are linked in the same transaction, so the
        evidence window starts at the first lookup. The audit row is written
        BEFORE the record and names no domain."""
        try:
            rows = restricted.pending(slug)
        except sqlite3.Error as exc:
            logger.warning("[tier-worker] %s: restricted evidence not read (%s)", slug,
                           type(exc).__name__)
            return
        if not rows:
            return
        r = rules.RULES["B7"]
        by_device: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            device = (row.get("device_key") or "").strip() or "unknown-device"
            by_device.setdefault(device, []).append(row)
        for device, group in by_device.items():
            self._restricted_device(slug, r, device, group, now, counts)

    def _restricted_device(self, slug: str, r: rules.Rule, device: str,
                           group: list[dict[str, Any]], now: datetime,
                           counts: dict[str, int]) -> None:
        ids = [int(g["id"]) for g in group]
        names = [g["device_name"] for g in group if g.get("device_name")]
        label = names[0] if names else device
        key = store.dedupe_key(slug, device_ref=device, family=r.family)
        first = min(str(g.get("observed_at") or "") for g in group) or format_utc_ms(now)
        # NO analyst verdict ever blocks B7 (`store._honours_verdicts`): every
        # CSAM lookup opens — or reopens, or appends to — a Black (B1), even
        # after a false-positive close of the device's last one.
        try:
            action = store.predict(slug, key, r.tier, now)
        except sqlite3.Error:
            action = "open"
        why = (f"{len(ids)} restricted lookup{'' if len(ids) == 1 else 's'} blocked by DNS "
               "protection (B7 — restricted)")
        taudit.system(f"incident.{action}", slug, "incident", None,
                      after={"tier": r.tier, "rule": r.id, "key": key,
                             "restricted_rows": len(ids), "first_at": first},
                      reason=why)
        try:
            opened = store.open_incident(
                slug, tier=r.tier, rule_id=r.id, rule_version=r.version, key=key,
                summary=restricted.CSAM_SUMMARY, scope="device", opened_by=store.SYSTEM_ACTOR,
                reason=why, device_ref=device, device_label=label,
                evidence={"restricted": True, "category": restricted.CSAM,
                          "first_lookup_at": first, "lookups": len(ids),
                          "profile_id": group[0].get("profile_id"),
                          "restricted_evidence_ids": ids, "why": why},
                restricted_ids=ids, now=now)
        except (store.StoreError, sqlite3.Error, ValueError) as exc:
            # Not linked: the rows stay pending and the next pass retries.
            taudit.system(f"incident.{action}_failed", slug, "incident", None,
                          after={"rule": r.id, "error": type(exc).__name__},
                          reason="the restricted incident could not be written — retried on "
                                 "the next pass")
            return
        if opened.incident is None:
            try:
                restricted.mark_processed(slug, ids)
            except (sqlite3.Error, OSError):
                pass
            return
        counts["opened"] += 1
        actual = store.OUTCOME_ACTION.get(opened.outcome, opened.outcome)
        if actual != action:
            taudit.system(f"incident.{actual}", slug, "incident", str(opened.incident.id),
                          after={"tier": opened.incident.tier, "rule": r.id, "key": key},
                          reason=f"the same key: {opened.outcome} (not {action})")

    # ----- FR2 coverage notices -----

    def _coverage_notices(self, now: datetime) -> None:
        try:
            blind = intake.blind_sources(self.manager, now, check_worker=False)
        except Exception as exc:  # noqa: BLE001
            logger.warning("[tier-worker] intake health not read (%s)", type(exc).__name__)
            return
        for b in blind:
            notify.send("*", kind="threat_coverage",
                        title=f"Athena is blind to {b.label} since {b.since[:16].replace('T', ' ')}"
                              " UTC",
                        body=f"{b.why}. Detection that depends on {b.label} is not covered "
                             f"({'fleet-wide' if b.fleet_wide else 'one client'}) until it "
                             "recovers.",
                        request_id=f"coverage:{b.source}:{b.since}", audience="admins")

    # ----- async lifecycle -----

    def poke(self, slug: str) -> None:
        with self._poke_lock:
            self._poked.add(slug)
        loop = self._loop
        if loop is not None and not loop.is_closed():
            loop.call_soon_threadsafe(self._wake.set)

    async def start(self) -> None:
        if self._task is not None and not self._task.done():
            return
        self._stopping.clear()
        self._loop = asyncio.get_running_loop()
        self._task = asyncio.create_task(self._run(), name="tier-worker")

    async def stop(self) -> None:
        if self._task is None:
            return
        self._stopping.set()
        self._wake.set()
        try:
            await asyncio.wait_for(self._task, timeout=20.0)
        except asyncio.TimeoutError:
            self._task.cancel()
        self._task = None

    async def _run(self) -> None:
        last_full = 0.0
        loop = asyncio.get_running_loop()
        while not self._stopping.is_set():
            with self._poke_lock:
                poked, self._poked = self._poked, set()
            full = loop.time() - last_full >= self._interval
            try:
                if full:
                    last_full = loop.time()
                    await asyncio.to_thread(self.run_once)
                elif poked:
                    await asyncio.to_thread(self.run_once, poked)
            except Exception as exc:  # noqa: BLE001
                logger.warning("[tier-worker] pass failed (%s)", type(exc).__name__)
            self._wake.clear()
            try:
                await asyncio.wait_for(self._wake.wait(), timeout=self._interval)
            except asyncio.TimeoutError:
                pass


_WORKER: Optional[TierWorker] = None


def current() -> Optional[TierWorker]:
    return _WORKER


def set_current(worker: Optional[TierWorker]) -> None:
    global _WORKER
    _WORKER = worker


def poke(slug: str) -> None:
    w = _WORKER
    if w is not None:
        w.poke(slug)
