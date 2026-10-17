"""LLM-on-uncertain escalation for the autonomous triage worker (#119c).

Heuristic-first, LLM-on-uncertain: the deterministic engine (119a) handles
the ~95% clear cases for free; only when it returns `uncertain` does the
worker consult the octo-llm sibling (`POST /v1/triage-event`) for a
model-reasoned disposition. Everything here is FAIL-CLOSED — any gate
miss, rate cap, timeout, transport error, or malformed response leaves the
heuristic's `uncertain` verdict untouched. One-shot per event: the model's
output is recorded, never fed back into another model call (no agentic
loop — a model feeding a model can thrash).

Gates (checked cheapest-first, before any network call):
  1. bundle `l2_llm_enabled`  — super_admin opt-in (shared with the
     operator Ask-Octo path; same registry key).
  2. per-tenant AI consent — the tenant's EFFECTIVE AI policy
     (`instances.ai_policy.ai_allowed(slug, octo_llm_locality())`, v0.10):
     the default octo-llm is the bundle's own LOCAL sibling, so a tenant
     whose effective policy is 'local' or 'cloud' escalates and 'none' (the
     default for every tenant) does not. A tenant that asked for 'cloud'
     without a live compliance sign-off runs as 'local' — it escalates to
     the local model, and is refused by any cloud endpoint: an OCTO_LLM_URL
     pointing off the deployment makes the locality 'cloud'
     (`ai_policy.locality_of_url`), and only tenants cleared for cloud
     escalate then.
  3. autonomous rate budget — a SEPARATE bucket from operator calls so a
     burst of uncertain events can't starve the interactive path.
The octo-llm health is not pre-probed; the call itself fails closed.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from typing import Callable, Optional

import httpx

from apps.octo import paths
from apps.octo.agent.heuristic_l1 import (
    Disposition, TriageDecision, TriageFeatures, triage,
)
from apps.octo.db import connect
from apps.octo.instances.ai_policy import ai_allowed, locality_of_url

logger = logging.getLogger(__name__)

# Reuse the exact env/key the operator path uses so dev + prod config is
# shared (one toggle drives both Ask-Octo and autonomous escalation).
OCTO_LLM_URL_ENV = "OCTO_LLM_URL"
DEFAULT_OCTO_LLM_URL = "http://octo-llm:8101"
BUNDLE_CONFIG_LLM_ENABLED_KEY = "l2_llm_enabled"
OCTO_LLM_HTTP_TIMEOUT_SECONDS = 35.0
MAX_SUMMARY = 2048
_VALID_DISPOSITIONS = ("noise", "pattern", "escalate", "uncertain")


# --- gates -----------------------------------------------------------------

def _octo_llm_url() -> str:
    return os.environ.get(OCTO_LLM_URL_ENV, DEFAULT_OCTO_LLM_URL).rstrip("/")


def bundle_llm_enabled() -> bool:
    """bundle_config.l2_llm_enabled — False if table/row missing."""
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        try:
            row = reg.execute(
                "SELECT value_json FROM bundle_config WHERE key = ?",
                (BUNDLE_CONFIG_LLM_ENABLED_KEY,),
            ).fetchone()
        except sqlite3.OperationalError:
            return False
        if row is None:
            return False
        raw = row["value_json"] if hasattr(row, "keys") else row[0]
        try:
            return json.loads(raw) is True
        except (json.JSONDecodeError, TypeError):
            return False
    finally:
        reg.close()


def octo_llm_locality() -> str:
    """Where every model call made from this module runs, from the
    configured URL (`ai_policy.locality_of_url`): 'local' for the default
    octo-llm on the bundle's internal network; 'cloud' when OCTO_LLM_URL
    points off the deployment — then only tenants cleared for cloud
    escalate."""
    return locality_of_url(_octo_llm_url())


def tenant_ai_consumption_allowed(slug: str, *, locality: str = "local") -> bool:
    """Per-tenant AI consent for a model at `locality` ('local' | 'cloud'):
    `instances.ai_policy.ai_allowed` — the ONE effective-policy gate.
    'local' is allowed when the effective policy is local or cloud; 'cloud'
    only when it is cloud (a live sign-off, or a tenant tagged 'none').
    Fail closed: an unknown tenant, or a registry that predates migration
    033, does not escalate anywhere."""
    return ai_allowed(slug, locality)


class AutonomousRateLimiter:
    """Sliding-window cap on autonomous LLM calls. Separate from the
    operator rate limiter so autonomous triage can't exhaust the budget
    operators rely on. Per-tenant and bundle-wide ceilings."""

    def __init__(
        self,
        *,
        per_tenant_per_min: int = 30,
        bundle_per_min: int = 120,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._per_tenant = per_tenant_per_min
        self._bundle = bundle_per_min
        self._clock = clock
        self._tenant_hits: dict[str, list[float]] = {}
        self._bundle_hits: list[float] = []

    def allow(self, slug: str) -> bool:
        now = self._clock()
        cutoff = now - 60.0
        self._bundle_hits = [t for t in self._bundle_hits if t > cutoff]
        if len(self._bundle_hits) >= self._bundle:
            return False
        hits = [t for t in self._tenant_hits.get(slug, []) if t > cutoff]
        if len(hits) >= self._per_tenant:
            self._tenant_hits[slug] = hits
            return False
        hits.append(now)
        self._tenant_hits[slug] = hits
        self._bundle_hits.append(now)
        return True


# --- the LLM call ----------------------------------------------------------

def _event_summary(event_row: sqlite3.Row) -> str:
    """A concise summary for the model. The ingest sink doesn't persist the
    `summary` column, so synthesize one from the row when it's empty."""
    keys = event_row.keys()
    base = (event_row["summary"] or "").strip() if "summary" in keys else ""
    if base:
        return base[:MAX_SUMMARY]
    host = event_row["source_host"] or "unknown-host"
    return (
        f"{event_row['severity']} {event_row['event_type']} on {host} "
        f"(source: {event_row['source']})"
    )[:MAX_SUMMARY]


def _call_octo_llm_triage(payload: dict) -> dict:
    """POST /v1/triage-event. Raises on transport/HTTP error (caller
    treats any raise as fail-closed). Isolated so tests can monkeypatch."""
    r = httpx.post(
        f"{_octo_llm_url()}/v1/triage-event",
        json=payload,
        timeout=OCTO_LLM_HTTP_TIMEOUT_SECONDS,
    )
    r.raise_for_status()
    return r.json()


def escalate_uncertain(
    event_row: sqlite3.Row, features: TriageFeatures, slug: str,
) -> Optional[TriageDecision]:
    """Consult the model for an uncertain event. Returns a refined
    TriageDecision, or None on ANY failure (caller keeps the heuristic).

    RESTRICTED (v0.17.1): an event that names a domain the tenant holds as
    restricted evidence (rule B7, CSAM) — at DNS-label boundaries — is NEVER
    sent to a model, nor is any event while that list cannot be read (fail
    closed), nor a buoy DNS sensor's block younger than
    `restricted.SENSOR_HOLD`: the NextDNS poll that would mark it may not
    have run yet (the heuristic decision stands)."""
    from apps.octo.threat import restricted

    if restricted.sensor_hold(event_row):
        logger.info("a DNS sensor's block too young for a model (%s); heuristic kept", slug)
        return None
    try:
        values = restricted.restricted_domains(slug)
    except (sqlite3.Error, OSError):
        logger.warning("restricted-evidence list unreadable for %s; no model call", slug)
        return None
    keys = event_row.keys()
    text = " ".join(str(event_row[k] or "") for k in ("summary", "payload", "source_host")
                    if k in keys)
    if restricted.text_mentions(text, values):
        logger.warning("event refers to a restricted domain (%s); never sent to a model", slug)
        return None
    payload = {
        "event_summary": _event_summary(event_row),
        "peer_events": [],  # v1: no peer window yet (future enrichment)
        "heuristic_severity": features.severity,
        "tenant_scope_slug": slug,
        "agent_id": "octo",
    }
    try:
        data = _call_octo_llm_triage(payload)
    except Exception as exc:  # noqa: BLE001 — fail-closed on any error
        logger.warning("octo-llm triage call failed for %s: %s", slug, exc)
        return None
    try:
        disposition: Disposition = data["disposition"]
        reason = str(data["disposition_reason"])
        confidence = float(data["confidence"])
        suggested = data.get("suggested_severity", features.severity)
    except (KeyError, TypeError, ValueError):
        logger.warning("octo-llm triage returned a malformed response for %s", slug)
        return None
    if disposition not in _VALID_DISPOSITIONS:
        return None
    return TriageDecision(
        disposition=disposition,
        suggested_severity=suggested,
        confidence=confidence,
        # "(LLM)" marks the note as model-reasoned vs the heuristic's text.
        rationale=f"(LLM) {reason}".strip(),
    )


def make_llm_decider(
    rate_limiter: Optional[AutonomousRateLimiter] = None,
) -> Callable[[TriageFeatures, sqlite3.Row, str], TriageDecision]:
    """Build the worker's decide function: heuristic first, LLM only on
    `uncertain` when all gates pass, fail-closed throughout."""
    limiter = rate_limiter or AutonomousRateLimiter()

    def decide(
        features: TriageFeatures, event_row: sqlite3.Row, slug: str,
    ) -> TriageDecision:
        decision = triage(features)
        if decision.disposition != "uncertain":
            return decision  # clear case — the model never sees it
        # Ambiguous → escalate to the model if (and only if) gates allow.
        if not bundle_llm_enabled():
            return decision
        if not tenant_ai_consumption_allowed(slug, locality=octo_llm_locality()):
            return decision
        if not limiter.allow(slug):
            logger.info("autonomous LLM rate cap hit for %s; keeping heuristic", slug)
            return decision
        refined = escalate_uncertain(event_row, features, slug)
        return refined if refined is not None else decision

    return decide
