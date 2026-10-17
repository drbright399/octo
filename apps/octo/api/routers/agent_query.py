"""Bridge endpoint: operator-triggered "ask octo" agent queries.

Routes an operator's canned-query request from the UI to octo-llm,
audits the call, and writes the resulting enrichment back into the
tenant's `agent_notes` table so it persists.

Flow (one request):

  UI clicks "Any recognized patterns?" on an alert
    → POST /api/v1/agent-query
        { client_slug, ref_kind, ref_id, query_kind, heuristic_note }
    → octo-core checks bundle_config.l2_llm_enabled
    → octo-core checks the tenant's EFFECTIVE AI policy (v0.10)
    → octo-core probes octo-llm GET /v1/healthz
    → octo-core forwards to octo-llm POST /v1/enrich-note (httpx)
    → octo-core writes audit row "octo_llm_query_<kind>"
    → octo-core INSERTs into per-tenant events.db agent_notes
    → returns the new AgentNote row to the UI

Failure modes (all fail-closed; UI shows "octo unavailable; using
heuristic only" — never blocks the operator):

  bundle_config flag false       → 503 "llm_disabled"
  tenant's effective AI policy   → 412 — no LLM-backed answer for a tenant
    is 'none'                      whose effective policy is 'none'
                                   (`instances.ai_policy.effective_ai_policy`).
                                   The default octo-llm is the bundle's LOCAL
                                   sibling, so 'local' and 'cloud' tenants are
                                   answered — a 'cloud' tenant without a live
                                   compliance sign-off runs as 'local', which
                                   is exactly this path.
  octo-llm URL off the deployment → 412 unless the tenant is cleared for
    and the tenant not cleared     cloud: the locality comes from the URL
    for cloud                      (`ai_policy.locality_of_url`), never from
                                   configuration saying "local".
  octo-llm healthz != 200        → 503 "llm_unavailable"
  octo-llm non-2xx on enrich     → 503 "llm_error"
  octo-llm timeout               → 504 "llm_timeout"
  network error                  → 503 "llm_unreachable"

Per the M5/§11.5 contract, NONE of these turn into a 5xx that breaks
the UI — the octo-llm is value-add, never load-bearing.

Per the LLM-triage taxonomy (the internal decision that splits
operator-triggered enrichment from autonomous triage): this endpoint handles
OPERATOR-triggered enrichment only. Autonomous-triage calls (the
disposition path) flow through a separate background job, NOT
through HTTP from the UI.

Banked 2026-05-21 as Slice 4 of the LLM-container arc.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import time
import uuid
from typing import Literal, Optional

import httpx
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from apps.octo import paths
from apps.octo.agent import notes as agent_notes
from apps.octo.api.errors import APIError
from apps.octo.api.routers._rate_limiter import LIMITER as _RATE_LIMITER
from apps.octo.api.routers.auth import session_identity, _audit_append
from apps.octo.auth import sessions
from apps.octo.db import connect
from apps.octo.instances import ai_policy


router = APIRouter(prefix="/agent-query", tags=["agent", "llm"])

# Sibling read-only router for fetching notes attached to a ref.
# Mounted alongside /agent-query so the bridge endpoint and the
# ref-scoped read share the same module boundary.
notes_router = APIRouter(prefix="/agent-notes", tags=["agent"])


# octo-llm sibling URL. Defaults to the docker-network DNS name on
# the standard port. Dev override via env. Slice 1 commits the value;
# Slice 4 reads it.
OCTO_LLM_URL_ENV = "OCTO_LLM_URL"
DEFAULT_OCTO_LLM_URL = "http://octo-llm:8101"

# bundle_config flag governing whether octo-core reaches out to
# octo-llm. Default false (opt-in). Per Rick's instruction the LLM
# is per-tenant opt-in; bundle-wide flag is the outer gate, tenant
# scope check is enforced by session_identity + scope grants.
BUNDLE_CONFIG_LLM_ENABLED_KEY = "l2_llm_enabled"

# Where octo-llm runs is decided from its URL (`_octo_llm_locality`): the
# default — the bundle's internal network — is 'local'; an OCTO_LLM_URL
# pointing off the deployment makes every call a 'cloud' call. The tenant
# gate asks `ai_policy.locality_allows(effective_ai_policy(slug), locality)`.

# Hard wall-clock cap on a single octo-llm call. Octo-llm itself
# has its own request_timeout_seconds; this is the upper bound at
# the bridge so a stuck octo-llm never hangs the operator UI.
OCTO_LLM_HTTP_TIMEOUT_SECONDS = 35.0


# ---------------------------------------------------------------------------
# Request / response shapes
# ---------------------------------------------------------------------------

# Mirror octo-llm's QueryKind enum. Closed set — no freeform prompts.
QueryKind = Literal[
    "tell_me_more",
    "recognized_patterns",
    "compare_recent",
    "suggest_disposition",
    "suggest_next_steps",
]


class AgentQueryRequest(BaseModel):
    """Operator-triggered "ask octo" call from a drawer surface.

    Note: `query_kind` does NOT include "auto_enrich" — that value is
    reserved for the autonomous background path, which is invoked
    directly by octo-core's agent runtime, NOT through this HTTP
    surface. An operator who tries to pass auto_enrich gets a 400.
    """
    client_slug: str = Field(min_length=1, max_length=128)
    ref_kind: Literal["event", "ticket", "indicator"]
    ref_id: int = Field(ge=1)
    query_kind: QueryKind
    # The heuristic note text already shown to the operator. Octo-llm
    # paraphrases / augments it. Bound to match octo-llm's
    # MAX_NOTE_TEXT so a caller can't exceed the downstream cap.
    heuristic_note: str = Field(min_length=1, max_length=2048)
    # Optional pre-extracted structured signals the heuristic engine
    # already computed. Octo-llm caps at 32.
    signals: list[str] = Field(default_factory=list, max_length=32)


class AgentNoteRow(BaseModel):
    """Mirrors the AgentNote shape used elsewhere (search, tickets).

    The UI re-uses its existing renderer; this endpoint just adds a
    new row to the table that the operator's next page-load will
    surface, AND returns the row inline so the drawer can render it
    immediately without a reload."""
    id: int
    agent_id: str
    note_text: str
    confidence: float
    created_at: str
    updated_at: Optional[str] = None
    # Slice 2 addition — UI shows the kind chip next to the note.
    query_kind: Optional[str] = None
    # Echoed for UI chip color + click-through routing.
    ref_kind: str
    ref_id: int


class AgentQueryResponse(BaseModel):
    """Successful enrichment landed; here's the row that was added."""
    note: AgentNoteRow
    # Latency back to operator. UI shows this in the success toast.
    llm_took_ms: int
    bridge_took_ms: int
    # The tenant's effective AI policy when the call was made, and where the
    # model ran — the UI never has to guess whether data left the bundle.
    effective_ai_policy: Literal["local", "cloud"] = "local"
    llm_locality: Literal["local", "cloud"] = "local"
    # Slice 9e (consensus reviewer P3). Forwarded from octo-llm.
    # "uncalibrated" until the calibration loop ships; UI must warn
    # operators not to gate decisions on the confidence number.
    calibration_state: Literal["uncalibrated", "calibrated"] = "uncalibrated"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _octo_llm_url() -> str:
    return os.environ.get(OCTO_LLM_URL_ENV, DEFAULT_OCTO_LLM_URL).rstrip("/")


def _octo_llm_locality() -> str:
    """'local' | 'cloud' — where the configured octo-llm endpoint runs
    (`ai_policy.locality_of_url`). No environment variable can make an
    off-deployment endpoint count as local."""
    return ai_policy.locality_of_url(_octo_llm_url())


def _llm_enabled() -> bool:
    """Read bundle_config.l2_llm_enabled. False if the table or row
    is missing (safe default — same shape as is_enabled() in
    sanitized_pool.extractor)."""
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
        raw = row[0] if not hasattr(row, "keys") else row["value_json"]
        try:
            return json.loads(raw) is True
        except (json.JSONDecodeError, TypeError):
            return False
    finally:
        reg.close()


def _llm_healthy() -> bool:
    """Quick liveness probe so we fail fast if octo-llm is down."""
    try:
        r = httpx.get(f"{_octo_llm_url()}/v1/healthz", timeout=2.0)
        return r.status_code == 200 and bool(r.json().get("model_loaded"))
    except Exception:  # noqa: BLE001
        return False


def _scope_or_403(
    operator_id: int,
    client_slug: str,
    *,
    ref_kind: Optional[str] = None,
    ref_id: Optional[int] = None,
    surface: str = "agent-query",
) -> None:
    """Verify the caller has scope for this client. Reuses the same
    scope check the tickets/search routers use to keep policy
    single-source. We import lazily to avoid a circular at module
    load.

    Slice 9a (consensus reviewer C3): scope violations now write an
    audit row BEFORE raising. Closes the forensic blind spot where
    an attacker could probe for tenant existence without audit
    footprint. Action code: `octo_llm_query_scope_violation`.
    Optional ref_kind/ref_id/surface fields make the row precise
    enough to reconstruct attack patterns across the bridge +
    per-ref read endpoints.
    """
    from apps.octo.api.routers.tickets import _caller_scope  # noqa: PLC2701
    scope = _caller_scope(operator_id)
    if scope != ["*"] and client_slug not in scope:
        target_id = client_slug
        if ref_kind is not None and ref_id is not None:
            target_id = f"{client_slug}:{ref_kind}:{ref_id}"
        _audit_append(
            "octo_llm_query_scope_violation",
            actor=str(operator_id),
            target_id=target_id,
            before=None,
            after={
                "attempted_slug": client_slug,
                "caller_scope": scope,
                "surface": surface,
            },
            reason=f"tenant {client_slug!r} not in caller scope (surface={surface})",
            request_id=str(uuid.uuid4()),
        )
        raise APIError(
            "ISOLATION_VIOLATION",
            f"tenant {client_slug!r} not in caller scope",
        )


# ---------------------------------------------------------------------------
# Slice 9b — Prompt-injection sanitization (reviewer consensus C2)
# ---------------------------------------------------------------------------
#
# Pre-9b the bridge accepted heuristic_note + signals verbatim and
# relied on the system message + tag wrapping inside the LLM prompt
# to keep injected instructions contained. That's defense-in-depth
# at one layer; reviewers wanted active rejection at the BRIDGE
# layer so the LLM never sees obvious takeover patterns at all.
#
# The patterns below are intentionally conservative — false negatives
# are tolerable (we still have data-tag wrapping as the next layer)
# but false positives would block legitimate alert text. Patterns
# anchor on shapes that legitimate heuristic-note authors do NOT
# produce: line-starting role tokens, model-specific control tokens,
# and explicit close-tag attempts on the bridge's data tags.

_INJECTION_PATTERNS: list[tuple[str, "re.Pattern[str]"]] = [
    # Role-takeover lines. Common across major chat models: "system:",
    # "assistant:", "user:" appearing at line-start. Multiline +
    # case-insensitive. We require the role token to be word-start
    # to avoid matching "system call" or "user agent".
    (
        "role_takeover",
        re.compile(
            r"(?im)^[\s>]*(?:system|assistant|user)\s*[:>]\s*\S",
        ),
    ),
    # Imperative "ignore previous/all/above" patterns. Very common
    # jailbreak preamble.
    (
        "ignore_previous_instructions",
        re.compile(
            r"(?i)\bignore\s+(?:all\s+)?(?:previous|prior|above|earlier)"
            r"\s+(?:instructions?|prompts?|context|messages?|rules?)",
        ),
    ),
    # Closing tags on the bridge's own data wrappers. A legitimate
    # alert summary should never contain "</event_summary>" or
    # "</signals>". We don't block "<" or ">" alone — those appear in
    # real CLI args, URLs, comparison operators, etc.
    (
        "tag_escape",
        re.compile(
            r"(?i)</\s*(?:event_summary|signals)\s*>",
        ),
    ),
    # Model-specific control tokens. ChatML, Llama, Granite, Qwen,
    # and Mistral all use bracketed control tokens we never want in
    # user-supplied content. Anchored on "<|" to avoid matching
    # natural prose.
    (
        "model_control_token",
        re.compile(
            r"<\|(?:im_start|im_end|system|user|assistant|endoftext|"
            r"start_header_id|end_header_id|eot_id|begin_of_text|"
            r"end_of_text|tool_call|tool_response)\|>",
            re.IGNORECASE,
        ),
    ),
]


def _check_text_for_injection(text: str) -> Optional[str]:
    """Return the FIRST matched pattern name, or None if clean. The
    patterns are tested in priority order: role-takeover first since
    it's the most direct attack on the chat structure, then
    instruction-overrides, then bridge-tag escapes, then model
    control tokens.

    Length matters here — checking very long strings is fine because
    Pydantic already capped heuristic_note at 2048 chars + signals at
    32 entries upstream. We're operating on bounded input."""
    for name, pattern in _INJECTION_PATTERNS:
        if pattern.search(text):
            return name
    return None


def _ref_texts(client_slug: str, ref_kind: str, ref_id: int) -> tuple[list[str], object]:
    """The stored text of the record a query is about (an event's summary,
    payload and host; an indicator's value and context) and the row itself
    (None when there is none)."""
    if ref_kind not in ("event", "indicator"):
        return [], None
    db_path = paths.client_db_path(client_slug, "events" if ref_kind == "event"
                                   else "indicators")
    if not db_path.exists():
        return [], None
    conn = connect(db_path, read_only=True)
    conn.row_factory = sqlite3.Row
    try:
        if ref_kind == "event":
            row = conn.execute(
                "SELECT received_at, source, event_type, summary, payload, source_host "
                "FROM events WHERE id = ?", (ref_id,)).fetchone()
            texts = [row["summary"], row["payload"], row["source_host"]] if row else []
        else:
            row = conn.execute("SELECT value, context FROM indicators WHERE id = ?",
                               (ref_id,)).fetchone()
            texts = [row["value"], row["context"]] if row else []
    finally:
        conn.close()
    return [t for t in texts if isinstance(t, str)], row


def _restricted_or_audit(*, operator_id: int, body: "AgentQueryRequest",
                         request_id: str) -> None:
    """RESTRICTED (rule B7, CSAM — v0.17.1): a domain the tenant holds as
    restricted evidence is NEVER sent to a model — not in the record the
    query is about, not in the note or the signals the console sends. A
    buoy DNS sensor's block younger than `restricted.SENSOR_HOLD` is not
    either (the NextDNS poll that would mark it may not have run yet). The
    list unreadable: refused (fail closed). Audited; the answer names
    nothing."""
    from apps.octo.threat import restricted

    # The list unreadable: `gate.hits` is True for anything (fail closed).
    gate = restricted.Gate.for_tenant(body.client_slug)
    why = None
    try:
        texts, row = _ref_texts(body.client_slug, body.ref_kind, body.ref_id)
    except sqlite3.Error:
        # The record itself unreadable: the model is sent only the note and
        # the signals — those are checked below either way.
        texts, row = [], None
    if gate.hits(body.heuristic_note, *body.signals, *texts):
        why = "restricted_content"
    if why is None and body.ref_kind == "event" and row is not None \
            and restricted.sensor_hold(row):
        why = "sensor_hold"
    if why is None:
        return
    _audit_append(
        "octo_llm_query_restricted",
        actor=str(operator_id),
        target_id=f"{body.client_slug}:{body.ref_kind}:{body.ref_id}",
        before=None,
        after={"query_kind": body.query_kind, "why": why},
        reason="restricted content is never sent to a model",
        request_id=request_id,
    )
    raise APIError("PRECONDITION_FAILED",
                   "this record cannot be sent to a model"
                   + (" yet — try again in half an hour" if why == "sensor_hold" else ""))


def _sanitize_or_audit(
    *,
    operator_id: int,
    client_slug: str,
    ref_kind: str,
    ref_id: int,
    query_kind: str,
    heuristic_note: str,
    signals: list[str],
    request_id: str,
) -> None:
    """Inspect heuristic_note + each signal for prompt-injection
    patterns. On detection: write
    `octo_llm_query_sanitization_reject` to the audit log with the
    pattern name + a TRUNCATED sample (64 chars) of the offending
    content, then raise APIError("VALIDATION_FAILED").

    Why we audit with a sample: forensic analysis needs enough
    context to distinguish a real attack from a noisy alert, but we
    don't want the full 2KB note text in the audit log (storage
    cost + the audit log gets backed up to off-host targets).
    64 chars centered on the match captures the shape without the
    payload.

    Reviewer consensus C2 of the 2026-05-22 LLM-pipeline review
    (archived outside the repo).
    """
    target_id = f"{client_slug}:{ref_kind}:{ref_id}"

    note_hit = _check_text_for_injection(heuristic_note)
    if note_hit is not None:
        sample = heuristic_note[:64]
        _audit_append(
            "octo_llm_query_sanitization_reject",
            actor=str(operator_id),
            target_id=target_id,
            before=None,
            after={
                "query_kind": query_kind,
                "field": "heuristic_note",
                "pattern_matched": note_hit,
                "sample_64": sample,
            },
            reason=f"heuristic_note matched injection pattern {note_hit!r}",
            request_id=request_id,
        )
        raise APIError(
            "VALIDATION_FAILED",
            "heuristic_note rejected by sanitization layer",
        )

    for idx, sig in enumerate(signals):
        sig_hit = _check_text_for_injection(sig)
        if sig_hit is not None:
            _audit_append(
                "octo_llm_query_sanitization_reject",
                actor=str(operator_id),
                target_id=target_id,
                before=None,
                after={
                    "query_kind": query_kind,
                    "field": f"signals[{idx}]",
                    "pattern_matched": sig_hit,
                    "sample_64": sig[:64],
                },
                reason=(
                    f"signals[{idx}] matched injection pattern {sig_hit!r}"
                ),
                request_id=request_id,
            )
            raise APIError(
                "VALIDATION_FAILED",
                f"signals[{idx}] rejected by sanitization layer",
            )


def _insert_agent_note(
    client_slug: str,
    *,
    ref_kind: str,
    ref_id: int,
    agent_id: str,
    note_text: str,
    confidence: float,
    request_id: str,
    query_kind: Optional[str] = None,
) -> AgentNoteRow:
    """Append an operator-enrichment note via the shared writer, and wrap
    the returned row as an AgentNoteRow for inline UI echo.

    The autonomous worker uses the same `agent_notes.insert_agent_note`
    (with a `disposition`); the operator path leaves disposition None.
    """
    row = agent_notes.insert_agent_note(
        client_slug,
        ref_kind=ref_kind,
        ref_id=ref_id,
        agent_id=agent_id,
        note_text=note_text,
        confidence=confidence,
        request_id=request_id,
        query_kind=query_kind,
    )
    return AgentNoteRow(
        id=row["id"], agent_id=row["agent_id"], note_text=row["note_text"],
        confidence=row["confidence"], created_at=row["created_at"],
        updated_at=row["updated_at"],
        ref_kind=ref_kind, ref_id=ref_id,
        query_kind=row["query_kind"],
    )


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

@router.post("", response_model=AgentQueryResponse)
def agent_query(
    body: AgentQueryRequest,
    info: sessions.SessionInfo = Depends(session_identity),
) -> AgentQueryResponse:
    bridge_started = time.monotonic()
    request_id = str(uuid.uuid4())

    _scope_or_403(
        info.operator_id,
        body.client_slug,
        ref_kind=body.ref_kind,
        ref_id=body.ref_id,
        surface="bridge",
    )

    # Per-operator GRANT (slice 5d-2). The admin must have granted
    # LLM access; without that, the operator cannot use enrichment
    # even if they've opted in via preferences. This is the
    # capability gate — preferences below is the consent gate.
    from apps.octo.api.routers.admin_llm_grants import (
        operator_l2_llm_granted,
    )
    if not operator_l2_llm_granted(info.operator_id):
        _audit_append(
            "octo_llm_query_no_grant",
            actor=str(info.operator_id),
            target_id=f"{body.client_slug}:{body.ref_kind}:{body.ref_id}",
            before=None,
            after={"query_kind": body.query_kind},
            reason="operator not granted LLM access by admin",
            request_id=request_id,
        )
        raise APIError(
            "PRECONDITION_FAILED",
            "your account has not been granted L2 LLM access; "
            "ask an admin to grant it",
        )

    # Per-operator opt-out (slice 5b). Operator can disable octo for
    # themselves regardless of the bundle-wide flag. Audit-record the
    # rejection so the visibility surface counts it.
    from apps.octo.api.routers.account_preferences import (
        operator_l2_llm_enabled,
    )
    if not operator_l2_llm_enabled(info.operator_id):
        _audit_append(
            "octo_llm_query_user_disabled",
            actor=str(info.operator_id),
            target_id=f"{body.client_slug}:{body.ref_kind}:{body.ref_id}",
            before=None,
            after={"query_kind": body.query_kind},
            reason="operator opted out via account preferences",
            request_id=request_id,
        )
        raise APIError(
            "PRECONDITION_FAILED",
            "octo-llm disabled in your account preferences",
        )

    if not _llm_enabled():
        # Audit-record the attempt — operator visibility into how
        # often the disabled flag is being hit.
        _audit_append(
            "octo_llm_query_disabled",
            actor=str(info.operator_id),
            target_id=f"{body.client_slug}:{body.ref_kind}:{body.ref_id}",
            before=None,
            after={"query_kind": body.query_kind},
            reason="bundle_config.l2_llm_enabled is false",
            request_id=request_id,
        )
        raise APIError(
            "PRECONDITION_FAILED",
            "octo-llm is disabled in bundle_config (super_admin opt-in)",
        )

    # v0.10: the tenant's EFFECTIVE AI policy — the one function every
    # enforcement point uses — against where octo-llm actually runs (its
    # URL). 'none' → no LLM-backed answer for this tenant, audited like the
    # other refusals. The default octo-llm is local: 'local' and 'cloud'
    # tenants reach it (a 'cloud' request without a live sign-off has
    # already been degraded to 'local' by `effective_ai_policy`). An
    # OCTO_LLM_URL off the deployment is a cloud endpoint: only a tenant
    # cleared for cloud reaches it.
    effective = ai_policy.effective_ai_policy(body.client_slug)
    locality = _octo_llm_locality()
    if not ai_policy.locality_allows(effective, locality):
        target_id = f"{body.client_slug}:{body.ref_kind}:{body.ref_id}"
        if effective == "none":
            _audit_append(
                "octo_llm_query_tenant_ai_none",
                actor=str(info.operator_id), target_id=target_id, before=None,
                after={"query_kind": body.query_kind, "effective_ai_policy": effective},
                reason="tenant's effective AI policy is 'none'",
                request_id=request_id,
            )
            raise APIError(
                "PRECONDITION_FAILED",
                "AI is off for this tenant (effective AI policy 'none'); an admin "
                "can opt it in under Settings → Tenants",
            )
        _audit_append(
            "octo_llm_query_tenant_ai_locality",
            actor=str(info.operator_id), target_id=target_id, before=None,
            after={"query_kind": body.query_kind, "effective_ai_policy": effective,
                   "llm_locality": locality},
            reason="octo-llm runs outside this deployment; the tenant is not cleared for cloud AI",
            request_id=request_id,
        )
        raise APIError(
            "PRECONDITION_FAILED",
            f"octo-llm is configured at an endpoint outside this deployment, and this tenant "
            f"runs AI as '{effective}' — only a tenant cleared for cloud AI may use it",
        )

    # Slice 9b (consensus reviewer C2). Active prompt-injection
    # sanitization at the bridge layer. Runs BEFORE _llm_healthy so
    # an attacker can't use a sibling-down state as a probe oracle —
    # if the sibling is down AND the payload is malicious, the
    # attacker should learn about the malicious payload reject, not
    # the sibling state. This ordering also keeps the audit trail
    # consistent regardless of sibling health.
    _sanitize_or_audit(
        operator_id=info.operator_id,
        client_slug=body.client_slug,
        ref_kind=body.ref_kind,
        ref_id=body.ref_id,
        query_kind=body.query_kind,
        heuristic_note=body.heuristic_note,
        signals=body.signals,
        request_id=request_id,
    )
    # RESTRICTED (B7, CSAM): never to a model — the record, the note, the
    # signals (and a DNS sensor's block too young to be checked).
    _restricted_or_audit(operator_id=info.operator_id, body=body, request_id=request_id)

    # Slice 9f (consensus reviewer P2). Three-bucket sliding-window
    # rate limiter: 60/min/operator, 30/min/tenant, 200/min/bundle.
    # Runs AFTER sanitization so a sustained malicious caller burns
    # their reject quota on each attempt — the limiter shouldn't
    # shield bad actors from the sanitization audit trail.
    verdict = _RATE_LIMITER.check_or_reject(
        info.operator_id, body.client_slug,
    )
    if not verdict.allowed:
        _audit_append(
            "octo_llm_query_rate_limited",
            actor=str(info.operator_id),
            target_id=f"{body.client_slug}:{body.ref_kind}:{body.ref_id}",
            before=None,
            after={
                "query_kind": body.query_kind,
                "bucket": verdict.bucket,
                "retry_after_s": verdict.retry_after_s,
            },
            reason=f"rate limit exceeded on {verdict.bucket} bucket",
            request_id=request_id,
        )
        raise APIError(
            "RATE_LIMITED",
            f"rate limit exceeded ({verdict.bucket}); retry in "
            f"{verdict.retry_after_s}s",
        )

    if not _llm_healthy():
        _audit_append(
            "octo_llm_query_unavailable",
            actor=str(info.operator_id),
            target_id=f"{body.client_slug}:{body.ref_kind}:{body.ref_id}",
            before=None,
            after={"query_kind": body.query_kind},
            reason="octo-llm /v1/healthz != 200 or model not loaded",
            request_id=request_id,
        )
        raise APIError(
            "SERVICE_UNAVAILABLE",
            "octo-llm is enabled but not healthy; falling back to heuristic",
        )

    # Call octo-llm. Treat ANY failure as 503 so the UI falls back
    # cleanly without surfacing a 5xx-style error.
    payload = {
        "ref_kind":          body.ref_kind,
        "ref_id":            body.ref_id,
        "heuristic_note":    body.heuristic_note,
        "signals":           body.signals,
        "tenant_scope_slug": body.client_slug,
        "agent_id":          "octo",
        "query_kind":        body.query_kind,
    }
    try:
        resp = httpx.post(
            f"{_octo_llm_url()}/v1/enrich-note",
            json=payload,
            timeout=OCTO_LLM_HTTP_TIMEOUT_SECONDS,
        )
    except httpx.TimeoutException:
        _audit_append(
            "octo_llm_query_timeout",
            actor=str(info.operator_id),
            target_id=f"{body.client_slug}:{body.ref_kind}:{body.ref_id}",
            before=None,
            after={"query_kind": body.query_kind},
            reason="octo-llm request exceeded bridge timeout",
            request_id=request_id,
        )
        raise APIError("SERVICE_UNAVAILABLE", "octo-llm timeout")
    except httpx.HTTPError as exc:
        _audit_append(
            "octo_llm_query_unreachable",
            actor=str(info.operator_id),
            target_id=f"{body.client_slug}:{body.ref_kind}:{body.ref_id}",
            before=None,
            after={"query_kind": body.query_kind, "error_type": type(exc).__name__},
            reason="octo-llm network error",
            request_id=request_id,
        )
        raise APIError("SERVICE_UNAVAILABLE", "octo-llm unreachable")

    if resp.status_code != 200:
        _audit_append(
            "octo_llm_query_error",
            actor=str(info.operator_id),
            target_id=f"{body.client_slug}:{body.ref_kind}:{body.ref_id}",
            before=None,
            after={
                "query_kind": body.query_kind,
                "downstream_status": resp.status_code,
            },
            reason=f"octo-llm returned {resp.status_code}",
            request_id=request_id,
        )
        raise APIError(
            "SERVICE_UNAVAILABLE",
            f"octo-llm error (status {resp.status_code})",
        )

    body_json = resp.json()
    enriched_text = body_json["enriched_text"]
    confidence = body_json["confidence"]
    llm_took_ms = body_json["took_ms"]
    model_version = body_json["model_version"]
    # Slice 9e (P3): default to uncalibrated if the field is absent
    # so an older octo-llm sibling (pre-9e) doesn't break the bridge.
    calibration_state = body_json.get("calibration_state", "uncalibrated")

    # Audit success BEFORE the write so a failed write still leaves
    # an audit trail of the call.
    _audit_append(
        f"octo_llm_query_{body.query_kind}",
        actor=str(info.operator_id),
        target_id=f"{body.client_slug}:{body.ref_kind}:{body.ref_id}",
        before=None,
        after={
            "query_kind": body.query_kind,
            "model_version": model_version,
            "confidence": confidence,
            "llm_took_ms": llm_took_ms,
            # Slice 9b — explicit marker that the bridge sanitization
            # gate ran AND passed. Forensic analysis can now split
            # rejected-by-sanitization vs called-and-cleared queries
            # at the action level (reject) AND at the success row
            # level (this field).
            "sanitization_passed": True,
            "effective_ai_policy": effective,
            "llm_locality": locality,
        },
        reason=None,
        request_id=request_id,
    )

    note = _insert_agent_note(
        body.client_slug,
        ref_kind=body.ref_kind, ref_id=body.ref_id,
        agent_id="octo",
        note_text=enriched_text,
        confidence=confidence,
        request_id=request_id,
        query_kind=body.query_kind,
    )

    return AgentQueryResponse(
        note=note,
        llm_took_ms=llm_took_ms,
        bridge_took_ms=int((time.monotonic() - bridge_started) * 1000),
        calibration_state=calibration_state,
        effective_ai_policy=effective,
        llm_locality=locality,
    )


# ---------------------------------------------------------------------------
# GET /api/v1/agent-notes/{slug}/{ref_kind}/{ref_id}  (Slice 7h)
# ---------------------------------------------------------------------------

class AgentNoteListResponse(BaseModel):
    """Notes persisted in this tenant's events.db that belong to the
    given ref. Filters out synthetic dev-seeded rows so the panel
    only shows real bridge-written + heuristic-written enrichments.
    """
    client_slug: str
    ref_kind: str
    ref_id: int
    notes: list[AgentNoteRow]


@notes_router.get(
    "/{client_slug}/{ref_kind}/{ref_id}",
    response_model=AgentNoteListResponse,
)
def list_notes_for_ref(
    client_slug: str,
    ref_kind: Literal["event", "ticket", "indicator"],
    ref_id: int,
    info: sessions.SessionInfo = Depends(session_identity),
) -> AgentNoteListResponse:
    """Read all agent_notes attached to a single (slug, ref_kind, ref_id).

    Solves the drawer state-bleed bug — surfaces (alert, event, ticket)
    now show only their OWN history instead of inheriting whatever the
    previous selection had in the panel's local React state.

    Scope-enforced: caller must have visibility into client_slug.
    Synthetic dev-seeded rows are filtered out so the operator sees
    only real bridge + heuristic notes (matches the triage feed's
    server-side filter — same audit_request_id LIKE 'synthetic-%'
    discriminator).
    """
    _scope_or_403(
        info.operator_id,
        client_slug,
        ref_kind=ref_kind,
        ref_id=ref_id,
        surface="agent-notes-read",
    )

    edb = paths.client_dir(client_slug) / "events.db"
    if not edb.exists():
        return AgentNoteListResponse(
            client_slug=client_slug, ref_kind=ref_kind, ref_id=ref_id, notes=[],
        )

    conn = connect(edb, read_only=True)
    try:
        # query_kind column added by migration 028 + lazy-applied by
        # the bridge on first insert; tolerate pre-028 events.db.
        try:
            rows = conn.execute(
                "SELECT id, agent_id, note_text, confidence, "
                "       created_at, updated_at, query_kind "
                "FROM agent_notes "
                "WHERE ref_kind = ? AND ref_id = ? "
                "  AND (audit_request_id IS NULL "
                "       OR audit_request_id NOT LIKE 'synthetic-%') "
                "ORDER BY created_at ASC",
                (ref_kind, ref_id),
            ).fetchall()
            has_qk = True
        except sqlite3.OperationalError:
            rows = conn.execute(
                "SELECT id, agent_id, note_text, confidence, "
                "       created_at, updated_at "
                "FROM agent_notes "
                "WHERE ref_kind = ? AND ref_id = ? "
                "  AND (audit_request_id IS NULL "
                "       OR audit_request_id NOT LIKE 'synthetic-%') "
                "ORDER BY created_at ASC",
                (ref_kind, ref_id),
            ).fetchall()
            has_qk = False
    finally:
        conn.close()

    notes = [
        AgentNoteRow(
            id=r["id"], agent_id=r["agent_id"], note_text=r["note_text"],
            confidence=r["confidence"], created_at=r["created_at"],
            updated_at=r["updated_at"],
            query_kind=r["query_kind"] if has_qk else None,
            ref_kind=ref_kind, ref_id=ref_id,
        )
        for r in rows
    ]
    return AgentNoteListResponse(
        client_slug=client_slug, ref_kind=ref_kind, ref_id=ref_id, notes=notes,
    )
